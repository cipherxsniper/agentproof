import base64
import json
import os
import tempfile

from agentproof.core import sign_event, generate_key, export_public_key
from agentproof.policy import PolicyEngine
from agentproof.replay import replay_log


def _make_log(tmp_path):
    log_path = os.path.join(tmp_path, "test.jsonl")
    raw_key, b64_key = generate_key()
    os.environ["AGENTPROOF_SIGNING_KEY"] = b64_key
    pubkey_b64 = export_public_key()

    policy = PolicyEngine(default_allow=False, default_reason="default-deny")
    policy.add_rule(
        name="under_cap",
        predicate=lambda action_type, ctx: ctx["amount_cents"] <= 500_000,
        allow=True,
        reason="under cap",
    )
    decision = policy.check_action(
        log_path, action_type="pay_invoice", context={"amount_cents": 12500},
    )
    return log_path, policy, base64.b64decode(pubkey_b64), decision


def test_replay_matches_correct_policy(tmp_path):
    log_path, policy, pubkey_bytes, decision = _make_log(str(tmp_path))
    ok, msg = replay_log(log_path, policy_engine=policy, pubkey_bytes=pubkey_bytes)
    assert ok, msg
    assert "1 claim" in msg


def test_replay_catches_wrong_policy(tmp_path):
    log_path, _, pubkey_bytes, decision = _make_log(str(tmp_path))

    wrong_policy = PolicyEngine(default_allow=False, default_reason="default-deny")
    wrong_policy.add_rule(
        name="tiny_cap",
        predicate=lambda action_type, ctx: ctx["amount_cents"] <= 100,
        allow=True,
        reason="tiny cap",
    )
    ok, msg = replay_log(log_path, policy_engine=wrong_policy, pubkey_bytes=pubkey_bytes)
    assert not ok
    assert "policy_decision" in msg


def test_replay_skips_policy_check_without_engine(tmp_path):
    log_path, _, pubkey_bytes, _ = _make_log(str(tmp_path))
    ok, msg = replay_log(log_path, pubkey_bytes=pubkey_bytes)
    assert ok
    assert "0 claim" in msg


def test_replay_fails_on_broken_chain(tmp_path):
    log_path, policy, pubkey_bytes, _ = _make_log(str(tmp_path))
    with open(log_path) as f:
        lines = f.readlines()
    entry = json.loads(lines[0])
    entry["data"]["context"]["amount_cents"] = 999999999
    lines[0] = json.dumps(entry) + "\n"
    with open(log_path, "w") as f:
        f.writelines(lines)

    ok, msg = replay_log(log_path, policy_engine=policy, pubkey_bytes=pubkey_bytes)
    assert not ok
    assert "chain verification failed" in msg


def test_replay_fixture_hash_match(tmp_path):
    from agentproof.adapters import record_http_call

    log_path = os.path.join(str(tmp_path), "http.jsonl")
    raw_key, b64_key = generate_key()
    os.environ["AGENTPROOF_SIGNING_KEY"] = b64_key
    pubkey_b64 = export_public_key()
    pubkey_bytes = base64.b64decode(pubkey_b64)

    req_body = {"amount": 12500, "currency": "usd"}
    resp_body = {"id": "pi_test123", "status": "succeeded"}
    record_http_call(
        log_path, method="POST", url="https://api.stripe.com/v1/payment_intents",
        status_code=200, request_body=req_body, response_body=resp_body,
    )

    fixtures = {0: {"request": req_body, "response": resp_body}}
    ok, msg = replay_log(log_path, fixtures=fixtures, pubkey_bytes=pubkey_bytes)
    assert ok, msg
    assert "2 claim" in msg


def test_replay_fixture_hash_mismatch(tmp_path):
    from agentproof.adapters import record_http_call

    log_path = os.path.join(str(tmp_path), "http2.jsonl")
    raw_key, b64_key = generate_key()
    os.environ["AGENTPROOF_SIGNING_KEY"] = b64_key
    pubkey_b64 = export_public_key()
    pubkey_bytes = base64.b64decode(pubkey_b64)

    record_http_call(
        log_path, method="POST", url="https://api.stripe.com/v1/payment_intents",
        status_code=200,
        request_body={"amount": 12500}, response_body={"status": "succeeded"},
    )

    wrong_fixtures = {0: {"request": {"amount": 99999}}}
    ok, msg = replay_log(log_path, fixtures=wrong_fixtures, pubkey_bytes=pubkey_bytes)
    assert not ok
    assert "request fixture" in msg
