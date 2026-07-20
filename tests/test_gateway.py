"""Tests for the action evaluation gateway."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest

from aegis.auth import Authenticator
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult
from aegis.policy import parse_policy_yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_ID = str(uuid.uuid4())
_DENY_ID = str(uuid.uuid4())

_ALLOW_POLICY = f"""\
version: "1.0"
id: "{_POLICY_ID}"
name: allow-all
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "*"
"""

_DENY_POLICY = f"""\
version: "1.0"
id: "{_DENY_ID}"
name: deny-all
priority: 100
enabled: true
rules:
  - effect: DENY
    match:
      action_type: "*"
"""


def _make_action(agent_id: str, action_type: str = "read") -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_type=action_type,
        params={},
        context=None,
        requested_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def env():
    """Set up a fully provisioned test environment.

    Returns a dict with: tmpdir, gateway, user_id, agent, policy_id
    """
    tmpdir = tempfile.mkdtemp()
    auth = Authenticator(tmpdir)
    user = auth.register("testuser", "ValidPass1!")
    gateway = Gateway(tmpdir)

    # register agent
    from aegis.registry import AgentRegistry
    registry = AgentRegistry(tmpdir)
    agent = registry.create(user.id, "test-agent")

    # apply policy
    policy = parse_policy_yaml(_ALLOW_POLICY, user.id)
    from aegis.policy import PolicyStore
    store = PolicyStore(tmpdir)
    store.save(policy)

    return {
        "tmpdir": tmpdir,
        "gateway": gateway,
        "user_id": user.id,
        "agent": agent,
        "policy_id": policy.id,
        "other_user_id": uuid.uuid4().hex,
    }


# ---------------------------------------------------------------------------
# Successful flow
# ---------------------------------------------------------------------------


class TestSuccessfulFlow:
    def test_full_evaluate_allows(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.ALLOW
        assert decision.action_id == action.action_id
        assert decision.agent_id == env["agent"].id

    def test_audit_event_persisted(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert len(events) == 1
        assert events[0].decision_id == decision.decision_id
        assert events[0].result == decision.result.value

    def test_audit_event_verifiable(self, env):
        action = _make_action(env["agent"].id)
        env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        results = store.verify(env["user_id"])
        assert all(r["valid"] for r in results)

    def test_ids_consistent(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.action_id == action.action_id
        assert decision.agent_id == env["agent"].id
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert events[0].decision_id == decision.decision_id
        assert events[0].action_id == action.action_id
        assert events[0].agent_id == env["agent"].id


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_unauthenticated_rejected(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            "", action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "not found" in (decision.reason or "").lower()

    def test_unknown_agent_rejected(self, env):
        action = _make_action(str(uuid.uuid4()))
        decision = env["gateway"].evaluate(
            env["user_id"], action, str(uuid.uuid4()), env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "not found" in (decision.reason or "").lower()

    def test_cross_user_agent_rejected(self, env):
        action = _make_action(env["agent"].id)
        # use a different user (not the agent owner)
        decision = env["gateway"].evaluate(
            env["other_user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "not found" in (decision.reason or "").lower()

    def test_revoked_agent_rejected(self, env):
        from aegis.registry import AgentRegistry
        registry = AgentRegistry(env["tmpdir"])
        registry.revoke(env["agent"].id, env["user_id"])
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "revoked" in (decision.reason or "").lower()

    def test_cross_user_policy_falls_back_to_default_deny(self, env):
        """When the policy belongs to another user, the gateway falls back
        to no-policy evaluation (default DENY)."""
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["other_user_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert not decision.matched


# ---------------------------------------------------------------------------
# Policy behavior
# ---------------------------------------------------------------------------


class TestPolicyBehavior:
    def test_matching_allow(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.ALLOW
        assert decision.matched

    def test_matching_deny(self, env):
        from aegis.policy import PolicyStore, parse_policy_yaml
        store = PolicyStore(env["tmpdir"])
        deny = parse_policy_yaml(_DENY_POLICY, env["user_id"])
        store.save(deny)
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, deny.id,
        )
        assert decision.result is DecisionResult.DENY
        assert decision.matched

    def test_default_deny_no_matching_policy(self, env):
        action = _make_action(env["agent"].id)
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, "nonexistent-id",
        )
        assert decision.result is DecisionResult.DENY
        assert not decision.matched


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    def test_engine_exception_produces_deny(self, env):
        """If the policy engine raises an exception, the gateway returns DENY."""
        from aegis.gateway import Gateway
        from aegis.engine import PolicyEngine

        class BrokenEngine:
            def evaluate(self, action, policies):
                raise RuntimeError("engine crash")

        gateway = Gateway(env["tmpdir"], engine=BrokenEngine())  # type: ignore
        action = _make_action(env["agent"].id)
        decision = gateway.evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "evaluation error" in (decision.reason or "").lower()

    def test_audit_persistence_failure_produces_deny(self, env):
        """If the audit store cannot persist, the gateway returns DENY."""
        from aegis.gateway import Gateway
        from aegis.audit import AuditStore

        class BrokenAuditStore:
            def append(self, event):
                raise RuntimeError("disk full")

            def list(self, user_id):
                return AuditStore(env["tmpdir"]).list(user_id)

            def get(self, event_id, user_id):
                return AuditStore(env["tmpdir"]).get(event_id, user_id)

            def verify(self, user_id):
                return AuditStore(env["tmpdir"]).verify(user_id)

        gateway = Gateway(env["tmpdir"])
        # replace the audit store with a broken one
        gateway._audit_store = BrokenAuditStore()  # type: ignore
        action = _make_action(env["agent"].id)
        decision = gateway.evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY
        assert "audit" in (decision.reason or "").lower()

    def test_deny_audit_failure_still_produces_deny(self, env):
        """Even if the engine says DENY, audit failure still produces DENY
        (consistent fail-closed behavior)."""
        from aegis.gateway import Gateway

        class BrokenAuditStore:
            def append(self, event):
                raise RuntimeError("audit fail")

            def list(self, user_id):
                return []

            def get(self, event_id, user_id):
                raise ValueError("not found")

            def verify(self, user_id):
                return [{"valid": True, "error": None}]

        # Use a DENY policy so engine returns DENY
        from aegis.policy import PolicyStore, parse_policy_yaml
        store = PolicyStore(env["tmpdir"])
        deny = parse_policy_yaml(_DENY_POLICY, env["user_id"])
        store.save(deny)

        gateway = Gateway(env["tmpdir"])
        gateway._audit_store = BrokenAuditStore()  # type: ignore
        action = _make_action(env["agent"].id)
        decision = gateway.evaluate(
            env["user_id"], action, env["agent"].id, deny.id,
        )
        assert decision.result is DecisionResult.DENY  # was DENY, stays DENY


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_audit_logged_when_agent_rejected(self, env):
        """If the agent is rejected, no audit event is created."""
        from aegis.audit import AuditStore
        action = _make_action(str(uuid.uuid4()))
        env["gateway"].evaluate(
            env["user_id"], action, str(uuid.uuid4()), env["policy_id"],
        )
        store = AuditStore(env["tmpdir"])
        assert store.list(env["user_id"]) == []

    def test_no_audit_logged_when_engine_fails(self, env):
        """If the engine crashes, no audit event is created."""
        from aegis.gateway import Gateway
        from aegis.audit import AuditStore

        class BrokenEngine:
            def evaluate(self, action, policies):
                raise RuntimeError("crash")

        gateway = Gateway(env["tmpdir"], engine=BrokenEngine())  # type: ignore
        action = _make_action(env["agent"].id)
        gateway.evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        store = AuditStore(env["tmpdir"])
        assert store.list(env["user_id"]) == []

    def test_gateway_uses_default_engine(self, env):
        """Gateway creates its own PolicyEngine if none is provided."""
        gateway = Gateway(env["tmpdir"])
        assert hasattr(gateway, "_engine")
