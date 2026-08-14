"""
agentproof.core — cryptographically signed, hash-chained audit logs for
autonomous agents.

Design goals:
  - Every event an agent takes (tool call, decision, self-modification)
    can be signed with an Ed25519 key and appended to a JSONL log.
  - Each entry references the SHA-256 hash of the previous entry, so any
    tampering — insertion, deletion, or edit — breaks the chain and is
    detectable by verify().
  - No dependency on any particular agent framework. This module has no
    opinion about what an "event" is; it just signs whatever dict you
    give it.
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KeyLike = Union[bytes, str, None]


class ProofChainError(Exception):
    """Raised for configuration errors (e.g. no key available)."""


def _load_signer(
    signing_key: KeyLike = None,
    keyfile: Optional[Union[str, Path]] = None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Resolve a private signing key from, in order of precedence:
      1. `signing_key` passed directly (raw 32 bytes, or a base64 string)
      2. `env_var` (base64-encoded 32-byte key) — e.g. for platforms like
         Render/Fly/Heroku where there's no persistent filesystem
      3. `keyfile` passed directly (path to a JSON file with a "secret"
         field, or a raw JSON array of ints — matches the original
         omega_proof.py format for backward compatibility)
      4. `keyfile_env_var` (path to the same kind of JSON file)

    Raises ProofChainError if none of these resolve to a usable key.
    No placeholder or randomly-generated key is ever silently substituted.
    """
    raw: Optional[bytes] = None

    if signing_key is not None:
        raw = _coerce_key_bytes(signing_key)

    if raw is None:
        b64 = os.environ.get(env_var)
        if b64:
            raw = base64.b64decode(b64)[:32]

    if raw is None:
        path = keyfile or os.environ.get(keyfile_env_var)
        if path:
            data = json.loads(Path(path).expanduser().read_text())
            raw = bytes(data["secret"][:32]) if isinstance(data, dict) else bytes(data[:32])

    if raw is None:
        raise ProofChainError(
            f"No signing key found. Pass signing_key=, set {env_var} "
            f"(base64), or set {keyfile_env_var} (path to a JSON keyfile). "
            f"No placeholder key will be used."
        )

    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return priv, priv.public_key()


def _coerce_key_bytes(signing_key: Union[bytes, str]) -> bytes:
    if isinstance(signing_key, bytes):
        return signing_key[:32]
    if isinstance(signing_key, str):
        return base64.b64decode(signing_key)[:32]
    raise ProofChainError("signing_key must be bytes or a base64-encoded str")


def generate_key() -> Tuple[bytes, str]:
    """
    Generate a fresh Ed25519 private key.
    Returns (raw_32_bytes, base64_str) — store the base64 string in
    AGENTPROOF_SIGNING_KEY or a keyfile; never commit it to source control.
    """
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes_raw() if hasattr(priv, "private_bytes_raw") else _private_bytes_fallback(priv)
    return raw, base64.b64encode(raw).decode()


def _private_bytes_fallback(priv: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _prev_hash(log_path: Path) -> str:
    if log_path.exists() and log_path.stat().st_size > 0:
        last_line = log_path.read_text().strip().splitlines()[-1]
        return json.loads(last_line)["entry_hash"]
    return "genesis"


class ProofChain:
    """
    Convenience wrapper around sign_event/verify_log bound to a single
    log file and key configuration. Optional — the module-level functions
    work standalone if you prefer not to instantiate a class.
    """

    def __init__(
        self,
        log_path: Union[str, Path],
        signing_key: KeyLike = None,
        keyfile: Optional[Union[str, Path]] = None,
        env_var: str = "AGENTPROOF_SIGNING_KEY",
        keyfile_env_var: str = "AGENTPROOF_KEYFILE",
    ):
        self.log_path = Path(log_path).expanduser()
        self._signing_key = signing_key
        self._keyfile = keyfile
        self._env_var = env_var
        self._keyfile_env_var = keyfile_env_var

    def _signer(self):
        return _load_signer(
            self._signing_key, self._keyfile, self._env_var, self._keyfile_env_var
        )

    def sign_event(self, event_type: str, data: dict) -> dict:
        return sign_event(
            self.log_path,
            event_type,
            data,
            signing_key=self._signing_key,
            keyfile=self._keyfile,
            env_var=self._env_var,
            keyfile_env_var=self._keyfile_env_var,
        )

    def verify(self, pubkey_bytes: Optional[bytes] = None) -> Tuple[bool, str]:
        return verify_log(
            self.log_path,
            pubkey_bytes=pubkey_bytes,
            signing_key=self._signing_key,
            keyfile=self._keyfile,
            env_var=self._env_var,
            keyfile_env_var=self._keyfile_env_var,
        )


def sign_event(
    log_path: Union[str, Path],
    event_type: str,
    data: dict,
    signing_key: KeyLike = None,
    keyfile: Optional[Union[str, Path]] = None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> dict:
    """
    Sign one event and append it to the hash-chained JSONL log at
    log_path. Returns the full entry that was written.
    """
    priv, _ = _load_signer(signing_key, keyfile, env_var, keyfile_env_var)
    log_path = Path(log_path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "type": event_type,
        "data": data,
        "prev_hash": _prev_hash(log_path),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    msg = json.dumps(entry, sort_keys=True, default=str).encode()
    sig = base64.b64encode(priv.sign(msg)).decode()
    entry_hash = hashlib.sha256(msg + sig.encode()).hexdigest()
    entry["signature"] = sig
    entry["entry_hash"] = entry_hash

    with open(log_path, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")

    return entry


def verify_log(
    log_path: Union[str, Path],
    pubkey_bytes: Optional[bytes] = None,
    signing_key: KeyLike = None,
    keyfile: Optional[Union[str, Path]] = None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> Tuple[bool, str]:
    """
    Walk the full chain in log_path, re-verifying every hash link and
    every signature. Returns (True, "<n> entries verified, chain intact")
    on success, or (False, "<reason>") on the first failure found.

    If pubkey_bytes is not given, the public key is derived from whatever
    private key resolves via signing_key/keyfile/env vars — i.e. the same
    identity that would sign new events. For third-party verification
    (someone checking your log without your private key), pass the
    public key bytes explicitly instead.
    """
    log_path = Path(log_path).expanduser()
    if not log_path.exists():
        return False, "log does not exist"

    if pubkey_bytes is None:
        _, pub = _load_signer(signing_key, keyfile, env_var, keyfile_env_var)
    else:
        pub = Ed25519PublicKey.from_public_bytes(pubkey_bytes)

    lines = log_path.read_text().strip().splitlines()
    if not lines:
        return False, "log is empty"

    expected_prev = "genesis"
    for i, line in enumerate(lines):
        entry = json.loads(line)

        if entry.get("prev_hash") != expected_prev:
            return False, f"chain broken at entry {i}: prev_hash mismatch"

        sig_b64 = entry["signature"]
        entry_hash = entry["entry_hash"]
        check_entry = {k: v for k, v in entry.items() if k not in ("signature", "entry_hash")}
        msg = json.dumps(check_entry, sort_keys=True, default=str).encode()

        recomputed_hash = hashlib.sha256(msg + sig_b64.encode()).hexdigest()
        if recomputed_hash != entry_hash:
            return False, f"entry_hash mismatch at entry {i} — log tampered"

        try:
            pub.verify(base64.b64decode(sig_b64), msg)
        except InvalidSignature:
            return False, f"invalid signature at entry {i} — forged or corrupted"

        expected_prev = entry_hash

    return True, f"{len(lines)} entries verified, chain intact"


def export_public_key(
    signing_key: KeyLike = None,
    keyfile: Optional[Union[str, Path]] = None,
    env_var: str = "AGENTPROOF_SIGNING_KEY",
    keyfile_env_var: str = "AGENTPROOF_KEYFILE",
) -> str:
    """
    Return the base64-encoded public key for the resolved signing key,
    so it can be published/shared for third-party verification without
    exposing the private key.
    """
    _, pub = _load_signer(signing_key, keyfile, env_var, keyfile_env_var)
    from cryptography.hazmat.primitives import serialization

    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()
