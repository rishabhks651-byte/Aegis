"""Deterministic policy evaluation engine.

Flow:
    Action + Policies → PolicyEngine.evaluate() → Decision

The engine is pure logic — no I/O, no AI, no external state.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.models import (
    Action,
    Decision,
    DecisionResult,
    Policy,
    Rule,
    RuleEffect,
)


# ---------------------------------------------------------------------------
# Match helpers
# ---------------------------------------------------------------------------

def _value_matches(pattern: Any, value: Any) -> bool:
    """Check if a single value matches a pattern from a rule's match dict."""
    if isinstance(pattern, str) and pattern == "*":
        return value is not None
    if isinstance(pattern, str) and pattern.endswith("*"):
        if not isinstance(value, str):
            return False
        return value.startswith(pattern[:-1])
    return value == pattern


def _resolve_key(action: Action, key: str) -> Any:
    """Resolve a dot-notation key (e.g. ``params.path``) against an Action."""
    parts = key.split(".")
    if parts[0] == "action_type":
        return action.action_type
    if parts[0] == "params":
        return _deep_get(action.params, parts[1:])
    if parts[0] == "context":
        if action.context is None:
            return None
        return _deep_get(action.context, parts[1:])
    return None


def _deep_get(d: dict[str, Any], keys: list[str]) -> Any:
    current: Any = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return None
    return current


def _rule_matches(rule: Rule, action: Action) -> bool:
    """Return True if *all* conditions in the rule's match dict are satisfied."""
    for key, pattern in rule.match.items():
        value = _resolve_key(action, key)
        if not _value_matches(pattern, value):
            return False
    return True


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Deterministic policy evaluator.

    The engine takes an Action and a list of Policies, evaluates them
    according to the Aegis evaluation semantics, and returns a Decision.

    The engine is stateless and pure — instantiate once or per evaluation.
    """

    def evaluate(
        self,
        action: Action,
        policies: list[Policy],
    ) -> Decision:
        """Evaluate *action* against *policies* and return a Decision.

        Evaluation semantics:

        1. Policies are sorted by ``priority`` descending (higher = first).
        2. Within each policy, rules are evaluated in list order.
        3. The **first matching rule** wins — its effect becomes the result.
        4. If no rule matches across all policies → DENY (default-deny).
        5. All errors are caught and result in DENY (fail-closed).

        The caller is responsible for verifying that the action's agent
        exists and is not revoked *before* calling this method.
        """
        try:
            return self._evaluate(action, policies)
        except Exception:
            return self._deny(
                action,
                "Internal evaluation error",
                matched=False,
            )

    # -- internal ------------------------------------------------------------

    def _evaluate(self, action: Action, policies: list[Policy]) -> Decision:
        sorted_policies = sorted(policies, key=lambda p: p.priority, reverse=True)

        for policy in sorted_policies:
            if not policy.enabled:
                continue
            for rule in policy.rules:
                if _rule_matches(rule, action):
                    result_enum = (
                        DecisionResult.ALLOW
                        if rule.effect is RuleEffect.ALLOW
                        else DecisionResult.DENY
                    )
                    reason = (
                        f"Policy '{policy.name}' rule '{rule.id}': "
                        f"{rule.comment or result_enum.value}"
                    )
                    return Decision(
                        decision_id=str(uuid.uuid4()),
                        action_id=action.action_id,
                        agent_id=action.agent_id,
                        result=result_enum,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        rule_id=rule.id,
                        rule_effect=rule.effect,
                        matched=True,
                        evaluated_at=datetime.now(timezone.utc),
                        reason=reason,
                    )

        return self._deny(
            action,
            "No matching rule in any enabled policy",
            matched=False,
        )

    def _deny(
        self,
        action: Action,
        reason: str,
        matched: bool = False,
    ) -> Decision:
        return Decision(
            decision_id=str(uuid.uuid4()),
            action_id=action.action_id,
            agent_id=action.agent_id,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=matched,
            evaluated_at=datetime.now(timezone.utc),
            reason=reason,
        )
