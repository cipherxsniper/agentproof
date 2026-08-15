"""
agentproof.policy -- signed policy decisions gating an agent's actions.

A PolicyEngine holds a set of rules. Every check_action() call is
itself signed and appended to the log as a "policy_decision" event
BEFORE the caller is told whether the action is allowed -- so a denied
action is on record just as durably as an approved one, and a caller
can't skip logging a denial by not calling the policy at all (the
demo/adapter code enforces "no policy_decision entry => no payment
call", not this module alone).

This does not execute the action. It only decides. Enforcement is the
caller's responsibility -- see demo/invoice_workflow.py for the
pattern of "check policy, and only proceed if allowed".
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Union

from .core import sign_event


@dataclass
class PolicyRule:
    name: str
    # predicate(action_type, context) -> True if this rule's condition
    # is met. Rules are evaluated in order; the first rule whose
    # predicate returns True determines the outcome via `allow`.
    predicate: Callable[[str, dict], bool]
    allow: bool
    reason: str


@dataclass
class PolicyEngine:
    rules: List[PolicyRule] = field(default_factory=list)
    default_allow: bool = False
    default_reason: str = "no matching rule; default-deny"

    def add_rule(self, name: str, predicate: Callable[[str, dict], bool], allow: bool, reason: str):
        self.rules.append(PolicyRule(name, predicate, allow, reason))
        return self

    def evaluate(self, action_type: str, context: dict) -> "PolicyDecision":
        for rule in self.rules:
            if rule.predicate(action_type, context):
                return PolicyDecision(allowed=rule.allow, rule_name=rule.name, reason=rule.reason)
        return PolicyDecision(allowed=self.default_allow, rule_name=None, reason=self.default_reason)

    def check_action(
        self,
        log_path: Union[str, Path],
        action_type: str,
        context: dict,
        signing_key=None,
        keyfile=None,
        env_var: str = "AGENTPROOF_SIGNING_KEY",
        keyfile_env_var: str = "AGENTPROOF_KEYFILE",
    ) -> "PolicyDecision":
        """
        Evaluate the policy for action_type/context, sign and append a
        policy_decision event recording the outcome, and return the
        decision. Context is hashed via the same JSON-serialization the
        adapters use, so amounts/details that matter for audit review
        (e.g. an approval threshold) should be passed as plain, reviewable
        fields in context -- only put things that must stay private
        behind a hash by pre-hashing them yourself before calling this.
        """
        decision = self.evaluate(action_type, context)
        sign_event(
            log_path, "policy_decision",
            {
                "action_type": action_type,
                "context": context,
                "allowed": decision.allowed,
                "rule_name": decision.rule_name,
                "reason": decision.reason,
            },
            signing_key=signing_key, keyfile=keyfile,
            env_var=env_var, keyfile_env_var=keyfile_env_var,
        )
        return decision


@dataclass
class PolicyDecision:
    allowed: bool
    rule_name: Optional[str]
    reason: str


def amount_under_threshold(threshold: float, field_name: str = "amount") -> Callable[[str, dict], bool]:
    """Predicate factory: matches if context[field_name] < threshold."""
    def predicate(action_type: str, context: dict) -> bool:
        val = context.get(field_name)
        return val is not None and val < threshold
    return predicate


def amount_at_or_above_threshold(threshold: float, field_name: str = "amount") -> Callable[[str, dict], bool]:
    def predicate(action_type: str, context: dict) -> bool:
        val = context.get(field_name)
        return val is not None and val >= threshold
    return predicate


def field_matches(field_name: str, pattern: str) -> Callable[[str, dict], bool]:
    """Predicate factory: matches if context[field_name] matches a regex."""
    compiled = re.compile(pattern)
    def predicate(action_type: str, context: dict) -> bool:
        val = context.get(field_name)
        return val is not None and bool(compiled.match(str(val)))
    return predicate
