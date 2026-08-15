import base64
import json
import tempfile
from pathlib import Path

import pytest

from agentproof import ProofChain, ProofChainError, generate_key, sign_event, verify_log


@pytest.fixture
def tmp_log():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d) / "test.log"


@pytest.fixture
def key():
    raw, b64 = generate_key()
    return raw, b64


def test_sign_and_verify_single_event(tmp_log, key):
    raw, _ = key
    entry = sign_event(tmp_log, "tool_call", {"tool": "read_file"}, signing_key=raw)
    assert entry["type"] == "tool_call"
    assert entry["prev_hash"] == "genesis"

    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is True
    assert "1 entries verified" in msg


def test_chain_grows_correctly(tmp_log, key):
    raw, _ = key
    for i in range(5):
        sign_event(tmp_log, "step", {"i": i}, signing_key=raw)

    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is True
    assert "5 entries verified" in msg

    lines = tmp_log.read_text().strip().splitlines()
    entries = [json.loads(l) for l in lines]
    for i in range(1, 5):
        assert entries[i]["prev_hash"] == entries[i - 1]["entry_hash"]


def test_tampered_data_fails_verification(tmp_log, key):
    raw, _ = key
    sign_event(tmp_log, "tool_call", {"amount": 100}, signing_key=raw)

    lines = tmp_log.read_text().strip().splitlines()
    entry = json.loads(lines[0])
    entry["data"]["amount"] = 999999
    tmp_log.write_text(json.dumps(entry) + "\n")

    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is False
    assert "tampered" in msg or "invalid signature" in msg


def test_deleted_entry_breaks_chain(tmp_log, key):
    raw, _ = key
    for i in range(3):
        sign_event(tmp_log, "step", {"i": i}, signing_key=raw)

    lines = tmp_log.read_text().strip().splitlines()
    tmp_log.write_text(lines[0] + "\n" + lines[2] + "\n")

    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is False
    assert "chain broken" in msg


def test_wrong_public_key_fails(tmp_log, key):
    raw, _ = key
    sign_event(tmp_log, "tool_call", {}, signing_key=raw)

    other_raw, _ = generate_key()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    other_pub = Ed25519PrivateKey.from_private_bytes(other_raw).public_key()
    other_pub_bytes = other_pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    ok, msg = verify_log(tmp_log, pubkey_bytes=other_pub_bytes)
    assert ok is False
    assert "invalid signature" in msg


def test_missing_log_reports_cleanly(tmp_log, key):
    raw, _ = key
    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is False
    assert "does not exist" in msg


def test_no_key_raises_clear_error(tmp_log, monkeypatch):
    monkeypatch.delenv("AGENTPROOF_SIGNING_KEY", raising=False)
    monkeypatch.delenv("AGENTPROOF_KEYFILE", raising=False)
    with pytest.raises(ProofChainError):
        sign_event(tmp_log, "tool_call", {})


def test_env_var_key_resolution(tmp_log, key, monkeypatch):
    raw, b64 = key
    monkeypatch.setenv("AGENTPROOF_SIGNING_KEY", b64)
    entry = sign_event(tmp_log, "tool_call", {})
    assert entry["type"] == "tool_call"
    ok, _ = verify_log(tmp_log)
    assert ok is True


def test_legacy_keyfile_json_dict_format(tmp_log, key, tmp_path):
    raw, _ = key
    keyfile = tmp_path / "key.json"
    keyfile.write_text(json.dumps({"secret": list(raw)}))

    entry = sign_event(tmp_log, "tool_call", {}, keyfile=str(keyfile))
    assert entry["type"] == "tool_call"
    ok, _ = verify_log(tmp_log, keyfile=str(keyfile))
    assert ok is True


def test_proofchain_class_wrapper(tmp_log, key):
    raw, _ = key
    chain = ProofChain(tmp_log, signing_key=raw)
    chain.sign_event("tool_call", {"x": 1})
    chain.sign_event("tool_call", {"x": 2})
    ok, msg = chain.verify()
    assert ok is True
    assert "2 entries verified" in msg


def test_malformed_key_length_raises(tmp_log):
    from agentproof.core import ProofChainError

    too_short = b"\x00" * 16
    with pytest.raises(ProofChainError, match="expected exactly 32"):
        sign_event(tmp_log, "tool_call", {}, signing_key=too_short)

    too_long_b64 = base64.b64encode(b"\x00" * 48).decode()
    with pytest.raises(ProofChainError, match="expected exactly 32"):
        sign_event(tmp_log, "tool_call", {}, signing_key=too_long_b64)


def test_corrupt_tail_raises_on_sign(tmp_log, key):
    from agentproof.core import ProofChainError

    raw, _ = key
    sign_event(tmp_log, "tool_call", {"i": 0}, signing_key=raw)

    # simulate a crash mid-append: a truncated, non-JSON final line
    with open(tmp_log, "a") as f:
        f.write('{"type": "tool_call", "data": {"i": 1}, "prev_ha')

    with pytest.raises(ProofChainError, match="corrupt or incomplete"):
        sign_event(tmp_log, "tool_call", {"i": 2}, signing_key=raw)


def test_corrupt_tail_reported_cleanly_on_verify(tmp_log, key):
    raw, _ = key
    sign_event(tmp_log, "tool_call", {"i": 0}, signing_key=raw)

    with open(tmp_log, "a") as f:
        f.write('{"type": "tool_call", "data": {"i": 1}, "prev_ha')

    ok, msg = verify_log(tmp_log, signing_key=raw)
    assert ok is False
    assert "not valid JSON" in msg
