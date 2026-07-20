"""Tests for the policy evaluation engine."""

import uuid
from datetime import datetime, timezone

import pytest

from aegis.models import (
    Action,
    DecisionResult,
    Policy,
    Rule,
    RuleEffect,
)
from aegis.engine import PolicyEngine


def _action(
    action_type: str = "read",
    params: dict | None = None,
    context: dict | None = None,
) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        agent_id=str(uuid.uuid4()),
        action_type=action_type,
        params=params or {},
        context=context,
        requested_at=datetime.now(timezone.utc),
    )


_USER_ID = str(uuid.uuid4())


def _policy(
    name: str = "p",
    priority: int = 100,
    enabled: bool = True,
    rules: list[Rule] | None = None,
) -> Policy:
    return Policy(
        id=str(uuid.uuid4()),
        name=name,
        user_id=_USER_ID,
        description="",
        priority=priority,
        enabled=enabled,
        rules=tuple(rules or []),
        created_at=datetime.now(timezone.utc),
    )


def _rule(
    effect: RuleEffect = RuleEffect.ALLOW,
    match: dict | None = None,
    rid: str = "r1",
    comment: str = "",
) -> Rule:
    return Rule(
        id=rid, effect=effect, match=match or {"action_type": "*"}, comment=comment
    )


class TestEngineBasics:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_allow_single_rule(self):
        a = _action(action_type="read")
        p = _policy(rules=[_rule(effect=RuleEffect.ALLOW, match={"action_type": "read"})])
        decision = self.engine.evaluate(a, [p])
        assert decision.result is DecisionResult.ALLOW
        assert decision.matched is True
        assert decision.policy_id == p.id

    def test_deny_single_rule(self):
        a = _action(action_type="write")
        p = _policy(rules=[_rule(effect=RuleEffect.DENY, match={"action_type": "write"})])
        decision = self.engine.evaluate(a, [p])
        assert decision.result is DecisionResult.DENY
        assert decision.matched is True

    def test_default_deny_no_match(self):
        a = _action(action_type="delete")
        p = _policy(rules=[_rule(match={"action_type": "read"})])
        decision = self.engine.evaluate(a, [p])
        assert decision.result is DecisionResult.DENY
        assert decision.matched is False

    def test_default_deny_no_policies(self):
        a = _action(action_type="read")
        decision = self.engine.evaluate(a, [])
        assert decision.result is DecisionResult.DENY
        assert decision.matched is False

    def test_first_matching_rule_wins(self):
        a = _action(action_type="read")
        p = _policy(rules=[
            _rule(effect=RuleEffect.DENY, match={"action_type": "*"}, rid="r1"),
            _rule(effect=RuleEffect.ALLOW, match={"action_type": "read"}, rid="r2"),
        ])
        decision = self.engine.evaluate(a, [p])
        assert decision.result is DecisionResult.DENY
        assert decision.rule_id == "r1"

    def test_policy_priority_ordering(self):
        a = _action(action_type="read")
        low = _policy(
            name="low", priority=10,
            rules=[_rule(effect=RuleEffect.DENY, match={"action_type": "*"}, rid="r1")],
        )
        high = _policy(
            name="high", priority=100,
            rules=[_rule(effect=RuleEffect.ALLOW, match={"action_type": "*"}, rid="r2")],
        )
        decision = self.engine.evaluate(a, [low, high])
        assert decision.result is DecisionResult.ALLOW
        assert decision.policy_id == high.id

    def test_disabled_policy_skipped(self):
        a = _action(action_type="read")
        enabled = _policy(
            name="enabled", priority=10,
            rules=[_rule(effect=RuleEffect.ALLOW, match={"action_type": "*"})],
        )
        disabled = _policy(
            name="disabled", priority=100, enabled=False,
            rules=[_rule(effect=RuleEffect.DENY, match={"action_type": "*"})],
        )
        decision = self.engine.evaluate(a, [disabled, enabled])
        assert decision.result is DecisionResult.ALLOW
        assert decision.policy_id == enabled.id


class TestWildcardMatching:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_star_wildcard_matches_any(self):
        a = _action(action_type="anything")
        p = _policy(rules=[_rule(match={"action_type": "*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_prefix_wildcard(self):
        a = _action(action_type="ns_read")
        p = _policy(rules=[_rule(match={"action_type": "ns_*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_prefix_wildcard_no_match(self):
        a = _action(action_type="other_read")
        p = _policy(rules=[_rule(match={"action_type": "ns_*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY

    def test_star_requires_non_none_value(self):
        a = _action(params={"path": None})
        p = _policy(rules=[_rule(match={"params.path": "*"})])
        # None should NOT match *
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY


class TestParamMatching:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_exact_param_match(self):
        a = _action(params={"path": "/safe/foo"})
        p = _policy(rules=[_rule(match={"params.path": "/safe/foo"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_prefix_param_match(self):
        a = _action(params={"path": "/safe/foo/bar"})
        p = _policy(rules=[_rule(match={"params.path": "/safe/*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_param_mismatch(self):
        a = _action(params={"path": "/dangerous/foo"})
        p = _policy(rules=[_rule(match={"params.path": "/safe/*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY

    def test_missing_param(self):
        a = _action(params={"other": "value"})
        p = _policy(rules=[_rule(match={"params.path": "*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY

    def test_nested_param(self):
        a = _action(params={"db": {"collection": "users", "op": "find"}})
        p = _policy(rules=[_rule(match={"params.db.collection": "users"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_nested_param_mismatch(self):
        a = _action(params={"db": {"collection": "admins"}})
        p = _policy(rules=[_rule(match={"params.db.collection": "users"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY


class TestContextMatching:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_context_match(self):
        a = _action(context={"env": "production"})
        p = _policy(rules=[_rule(match={"context.env": "production"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW

    def test_context_mismatch(self):
        a = _action(context={"env": "staging"})
        p = _policy(rules=[_rule(match={"context.env": "production"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY

    def test_none_context(self):
        a = _action(context=None)
        p = _policy(rules=[_rule(match={"context.env": "production"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.DENY

    def test_context_wildcard(self):
        a = _action(context={"env": "staging"})
        p = _policy(rules=[_rule(match={"context.env": "*"})])
        assert self.engine.evaluate(a, [p]).result is DecisionResult.ALLOW


class TestErrorHandling:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_fail_closed_on_exception(self):
        class CrashingPolicy:
            id = "crash"
            name = "crash"
            user_id = "u1"
            description = ""
            priority = 100
            enabled = True
            rules = None  # will cause iteration error
            created_at = datetime.now(timezone.utc)

            def __init__(self):
                pass

        a = _action()
        decision = self.engine.evaluate(a, [CrashingPolicy()])  # type: ignore
        assert decision.result is DecisionResult.DENY
        assert decision.matched is False

    def test_decision_fields_populated(self):
        a = _action(action_type="read")
        p = _policy(rules=[_rule(match={"action_type": "read"})])
        decision = self.engine.evaluate(a, [p])
        assert decision.action_id == a.action_id
        assert decision.agent_id == a.agent_id
        assert isinstance(decision.decision_id, str)
        assert len(decision.decision_id) > 0

    def test_reason_for_allow(self):
        a = _action(action_type="read")
        p = _policy(
            name="my-policy",
            rules=[_rule(effect=RuleEffect.ALLOW, match={"action_type": "read"}, rid="r1", comment="allowed")],
        )
        decision = self.engine.evaluate(a, [p])
        assert "my-policy" in decision.reason
        assert "r1" in decision.reason
        assert decision.reason is not None

    def test_reason_for_default_deny(self):
        a = _action(action_type="unknown")
        decision = self.engine.evaluate(a, [])
        assert "No matching" in (decision.reason or "")

    def test_engine_is_stateless(self):
        e1 = PolicyEngine()
        e2 = PolicyEngine()
        a = _action(action_type="read")
        p = _policy(rules=[_rule(match={"action_type": "read"})])
        d1 = e1.evaluate(a, [p])
        d2 = e2.evaluate(a, [p])
        assert d1.result is d2.result  # same enum member
