import json
import pytest

from agentproof import generate_key, verify_log
from agentproof.policy import (
    PolicyEngine, amount_under_threshold, amount_at_or_above_threshold, field_matches,
)


@pytest.fixture
def key():
    raw, b64 = generate_key()
    return raw, b64


def test_default_deny_with_no_rules(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = PolicyEngine()  # no rules, default_allow=False

    decision = engine.check_action(log, "payment", {"amount": 50}, signing_key=raw)
    assert decision.allowed is False
    assert decision.reason == "no matching rule; default-deny"

    entry = json.loads(log.read_text().strip())
    assert entry["type"] == "policy_decision"
    assert entry["data"]["allowed"] is False


def test_amount_under_threshold_allows(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = PolicyEngine().add_rule(
        "auto_approve_small", amount_under_threshold(100), allow=True, reason="under $100 auto-approved"
    )

    decision = engine.check_action(log, "payment", {"amount": 50}, signing_key=raw)
    assert decision.allowed is True
    assert decision.rule_name == "auto_approve_small"


def test_amount_at_or_above_threshold_denies(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = (
        PolicyEngine()
        .add_rule("auto_approve_small", amount_under_threshold(100), allow=True, reason="under $100")
        .add_rule("require_approval_large", amount_at_or_above_threshold(100), allow=False, reason="needs human approval")
    )

    decision = engine.check_action(log, "payment", {"amount": 5000}, signing_key=raw)
    assert decision.allowed is False
    assert decision.rule_name == "require_approval_large"


def test_first_matching_rule_wins(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = (
        PolicyEngine()
        .add_rule("rule_a", lambda a, c: True, allow=True, reason="always matches first")
        .add_rule("rule_b", lambda a, c: True, allow=False, reason="would also match")
    )

    decision = engine.check_action(log, "anything", {}, signing_key=raw)
    assert decision.rule_name == "rule_a"
    assert decision.allowed is True


def test_field_matches_predicate(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = PolicyEngine().add_rule(
        "trusted_vendor", field_matches("vendor_id", r"^VEND-TRUSTED-"),
        allow=True, reason="trusted vendor prefix",
    )

    d1 = engine.check_action(log, "payment", {"vendor_id": "VEND-TRUSTED-001"}, signing_key=raw)
    assert d1.allowed is True

    d2 = engine.check_action(log, "payment", {"vendor_id": "VEND-UNKNOWN-002"}, signing_key=raw)
    assert d2.allowed is False  # falls through to default-deny


def test_denied_decisions_are_signed_and_verifiable(tmp_path, key):
    raw, _ = key
    log = tmp_path / "run.log"
    engine = PolicyEngine()  # everything denied by default

    for i in range(3):
        engine.check_action(log, "payment", {"amount": i * 1000}, signing_key=raw)

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True
    assert "3 entries verified" in msg

    for line in log.read_text().strip().splitlines():
        entry = json.loads(line)
        assert entry["data"]["allowed"] is False  # every denial genuinely on record


def test_policy_and_tool_call_share_one_chain(tmp_path, key):
    """The whole point: policy decisions and the actions they gate live
    in the SAME hash-chained log, so a verifier sees one continuous,
    tamper-evident sequence -- not a policy log and an action log that
    could be edited independently of each other."""
    from agentproof.adapters import wrap_tool_call

    raw, _ = key
    log = tmp_path / "run.log"
    engine = PolicyEngine().add_rule(
        "small_ok", amount_under_threshold(100), allow=True, reason="auto-approved"
    )

    decision = engine.check_action(log, "payment", {"amount": 50}, signing_key=raw)
    assert decision.allowed is True

    @wrap_tool_call(log, signing_key=raw)
    def make_payment(amount):
        return {"status": "paid", "amount": amount}

    make_payment(50)

    ok, msg = verify_log(log, signing_key=raw)
    assert ok is True
    assert "2 entries verified" in msg

    lines = log.read_text().strip().splitlines()
    types = [json.loads(l)["type"] for l in lines]
    assert types == ["policy_decision", "tool_call"]
