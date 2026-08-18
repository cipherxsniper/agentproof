"""
agentproof.replay -- fixture-based replay verification.

verify_log() (core.py) proves the chain wasn't tampered with: every
hash links to its predecessor, every signature is valid. It does NOT
prove the *decisions* recorded in the chain were correct - a log can
be perfectly hash-chained and signed while still recording a policy
decision that doesn't match what the declared policy rules would
actually produce for that context.

replay_log() closes that gap for the two entry types where it's
checkable without needing the original raw payloads (which are
deliberately never stored, only hashed):

  - policy_decision: re-run the SAME rule set against the recorded
    context and confirm the recomputed decision matches what the log
    claims. Catches a log edited to claim an approval that the
    declared policy would never have granted.

  - http_call (and any wrap_tool_call event with args/return hashes):
    if the caller supplies the real request/response bodies used
    during the original run (a "fixture"), replay recomputes their
    hashes and confirms they match request_hash/response_hash. This
    proves the recorded evidence corresponds to specific known
    payloads, not just "some hash".

This does NOT replay an http_call against the live network - agentproof
never re-executes side-effecting actions. It only confirms the log is
internally consistent with a supplied policy engine and/or fixture data.
"""

import json
import hashlib
from pathlib import Path
from typing import Optional, Union, Callable

from .core import verify_log


def _hash_json(obj) -> str:
    blob = json.dumps(obj, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def replay_log(
    log_path: Union[str, Path],
    policy_engine=None,
    fixtures: Optional[dict] = None,
    pubkey_bytes: Optional[bytes] = None,
):
    """
    Replay a signed log against known-good inputs and confirm every
    checkable decision/evidence entry matches what's recorded.

    policy_engine: an agentproof.policy.PolicyEngine instance configured
        with the SAME rules used during the original run. Every
        policy_decision entry in the log is re-evaluated against its
        own recorded context; if the recomputed decision (allowed +
        rule_name) doesn't match what's stored, replay fails at that
        entry. If not provided, policy_decision entries are skipped
        (not verified, not counted as failures).

    fixtures: optional dict mapping entry index (0-based, position in
        the log) -> {"request": <raw request body>, "response": <raw
        response body>} for http_call/tool_call entries. If a fixture
        is supplied for an entry, its hash is recomputed and compared
        against the entry's stored request_hash/response_hash.

    Returns (True, "<n> entries replayed, all checkable claims match")
    on success, or (False, "<reason>") on the first mismatch.

    Always runs core.verify_log() first - replay is meaningless on a
    log whose chain/signatures are already broken.
    """
    chain_ok, chain_msg = verify_log(log_path, pubkey_bytes=pubkey_bytes)
    if not chain_ok:
        return False, f"chain verification failed before replay: {chain_msg}"

    fixtures = fixtures or {}
    checked = 0

    with open(log_path) as f:
        lines = [json.loads(line) for line in f if line.strip()]

    for i, entry in enumerate(lines):
        etype = entry.get("type")
        data = entry.get("data", {})

        if etype == "policy_decision" and policy_engine is not None:
            action_type = data.get("action_type")
            context = data.get("context", {})
            claimed_allowed = data.get("allowed")
            claimed_rule = data.get("rule_name")

            decision = policy_engine.evaluate(action_type, context)

            if decision.allowed != claimed_allowed or decision.rule_name != claimed_rule:
                return False, (
                    f"entry {i} (policy_decision): log claims allowed="
                    f"{claimed_allowed}, rule={claimed_rule!r}, but replaying "
                    f"the supplied policy against the recorded context "
                    f"produces allowed={decision.allowed}, rule={decision.rule_name!r}"
                )
            checked += 1

        elif etype in ("http_call", "tool_call") and i in fixtures:
            fixture = fixtures[i]
            if "request" in fixture and "request_hash" in data:
                recomputed = _hash_json(fixture["request"])
                if recomputed != data["request_hash"]:
                    return False, (
                        f"entry {i} ({etype}): supplied request fixture hashes to "
                        f"{recomputed}, but log records request_hash={data['request_hash']}"
                    )
                checked += 1
            if "response" in fixture and "response_hash" in data:
                recomputed = _hash_json(fixture["response"])
                if recomputed != data["response_hash"]:
                    return False, (
                        f"entry {i} ({etype}): supplied response fixture hashes to "
                        f"{recomputed}, but log records response_hash={data['response_hash']}"
                    )
                checked += 1

    return True, f"{checked} claim(s) replayed and matched across {len(lines)} entries"
