"""
End-to-end tests for the CLI as an actual subprocess, exercising it the
way a real user would -- not calling main() in-process, but invoking
`python -m agentproof.cli` and checking stdout/exit codes. This is what
proves the CLI itself works, not just the library functions it calls.
"""

import base64
import json
import os
import subprocess
import sys

import pytest

from agentproof import sign_event, generate_key


def run_cli(*args, env=None):
    cmd = [sys.executable, "-m", "agentproof.cli"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _env_with_key(b64_key):
    env = os.environ.copy()
    env["AGENTPROOF_SIGNING_KEY"] = b64_key
    return env


def _pub_b64_for(raw_priv_bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    pub = Ed25519PrivateKey.from_private_bytes(raw_priv_bytes).public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_bytes).decode()


def test_cli_keygen_produces_usable_key():
    result = run_cli("keygen")
    assert result.returncode == 0
    assert "AGENTPROOF_SIGNING_KEY=" in result.stdout

    key_line = [l for l in result.stdout.splitlines() if l.startswith("AGENTPROOF_SIGNING_KEY=")][0]
    b64 = key_line.split("=", 1)[1]
    raw = base64.b64decode(b64)
    assert len(raw) == 32


def test_cli_verify_valid_log(tmp_path):
    raw, b64 = generate_key()
    log_path = tmp_path / "test.log"
    sign_event(log_path, "tool_call", {"x": 1}, signing_key=raw)

    result = run_cli("verify", str(log_path), "--pubkey", _pub_b64_for(raw))
    assert result.returncode == 0
    assert result.stdout.startswith("OK:")


def test_cli_verify_tampered_log_fails_with_nonzero_exit(tmp_path):
    raw, b64 = generate_key()
    log_path = tmp_path / "test.log"
    sign_event(log_path, "tool_call", {"amount": 100}, signing_key=raw)

    entry = json.loads(log_path.read_text().strip())
    entry["data"]["amount"] = 999999
    log_path.write_text(json.dumps(entry) + "\n")

    result = run_cli("verify", str(log_path), "--pubkey", _pub_b64_for(raw))
    assert result.returncode == 1
    assert result.stdout.startswith("FAIL:")


def test_cli_rotate_creates_linked_segment(tmp_path):
    raw, b64 = generate_key()
    old_log = tmp_path / "old.log"
    new_log = tmp_path / "new.log"
    sign_event(old_log, "step", {"i": 0}, signing_key=raw)

    result = run_cli("rotate", str(old_log), str(new_log), env=_env_with_key(b64))
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "Rotated." in result.stdout
    assert "AGENTPROOF_SIGNING_KEY=" in result.stdout
    assert new_log.exists()

    first_entry = json.loads(new_log.read_text().strip().splitlines()[0])
    assert first_entry["type"] == "key_rotation"


def test_cli_rotate_refuses_missing_old_log(tmp_path):
    missing = tmp_path / "does_not_exist.log"
    new_log = tmp_path / "new.log"

    result = run_cli("rotate", str(missing), str(new_log))
    assert result.returncode == 2
    assert "ERROR:" in result.stderr
    assert not new_log.exists()


def test_cli_verify_history_walks_rotated_segments(tmp_path):
    raw, b64 = generate_key()
    old_log = tmp_path / "old.log"
    new_log = tmp_path / "new.log"
    sign_event(old_log, "step", {"i": 0}, signing_key=raw)

    rotate_result = run_cli("rotate", str(old_log), str(new_log), env=_env_with_key(b64))
    assert rotate_result.returncode == 0, f"stderr: {rotate_result.stderr}"

    new_key_line = [l for l in rotate_result.stdout.splitlines() if l.startswith("AGENTPROOF_SIGNING_KEY=")][0]
    new_b64 = new_key_line.split("=", 1)[1]
    new_raw = base64.b64decode(new_b64)

    sign_event(new_log, "step", {"i": 1}, signing_key=new_raw)

    result = run_cli("verify", str(new_log), "--pubkey", _pub_b64_for(new_raw), "--history")
    assert result.returncode == 0
    assert "OK:" in result.stdout
    assert "2 segments" in result.stdout
