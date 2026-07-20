"""Tests for subscription and entitlement system."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

import pytest

from aegis.entitlement import (
    EntitlementError,
    EntitlementService,
    Plan,
    Subscription,
    SubscriptionStatus,
    _BUILT_IN_PLANS,
)
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def svc():
    """EntitlementService with seeded plans."""
    td = tempfile.mkdtemp()
    return EntitlementService(td), td


@pytest.fixture
def user_id():
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Plan model tests
# ---------------------------------------------------------------------------


class TestPlanModel:
    def test_valid_plan(self):
        p = Plan(id="test", name="Test", version="1.0", active=True,
                 entitlements={"agents.max": 5})
        assert p.id == "test"
        assert p.entitlements["agents.max"] == 5

    def test_empty_id_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            Plan(id="", name="X", version="1.0", active=True, entitlements={})

    def test_serialization_roundtrip(self):
        p = Plan(id="x", name="X", version="1.0", active=True,
                 entitlements={"a": 1, "b": False})
        d = p.to_dict()
        p2 = Plan.from_dict(d)
        assert p2.id == p.id
        assert p2.name == p.name
        assert p2.entitlements == p.entitlements


# ---------------------------------------------------------------------------
# Subscription model tests
# ---------------------------------------------------------------------------


class TestSubscriptionModel:
    def test_valid_subscription(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        assert s.is_active()

    def test_expired_not_active(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="free",
            status=SubscriptionStatus.EXPIRED,
            start_time=datetime.now(timezone.utc),
        )
        assert not s.is_active()

    def test_cancelled_not_active(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="free",
            status=SubscriptionStatus.CANCELLED,
            start_time=datetime.now(timezone.utc),
        )
        assert not s.is_active()

    def test_suspended_not_active(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="free",
            status=SubscriptionStatus.SUSPENDED,
            start_time=datetime.now(timezone.utc),
        )
        assert not s.is_active()

    def test_unknown_status_not_treated_as_active(self):
        """Fail-closed: unknown statuses must not be treated as active."""
        with pytest.raises(ValueError):
            SubscriptionStatus("UNKNOWN")

    def test_serialization_roundtrip(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            renewal=True,
        )
        d = s.to_dict()
        s2 = Subscription.from_dict(d)
        assert s2.id == s.id
        assert s2.plan_id == s.plan_id
        assert s2.status is SubscriptionStatus.ACTIVE
        assert s2.renewal == s.renewal


# ---------------------------------------------------------------------------
# Built-in plans
# ---------------------------------------------------------------------------


class TestBuiltInPlans:
    def test_free_plan_exists(self):
        assert "free" in _BUILT_IN_PLANS
        assert _BUILT_IN_PLANS["free"]["entitlements"]["agents.max"] == 1

    def test_pro_plan_exists(self):
        assert "pro" in _BUILT_IN_PLANS
        assert _BUILT_IN_PLANS["pro"]["entitlements"]["ai.copilot"] is True

    def test_enterprise_plan_exists(self):
        assert "enterprise" in _BUILT_IN_PLANS
        assert _BUILT_IN_PLANS["enterprise"]["entitlements"]["agents.max"] == 100


# ---------------------------------------------------------------------------
# EntitlementService tests
# ---------------------------------------------------------------------------


class TestEntitlementService:
    def test_seeded_plans(self, svc):
        service, _ = svc
        plans = service.list_plans()
        plan_ids = {p.id for p in plans}
        assert "free" in plan_ids
        assert "pro" in plan_ids
        assert "enterprise" in plan_ids

    def test_no_subscription_denies_all(self, svc, user_id):
        service, _ = svc
        assert not service.has(user_id, "ai.copilot")
        assert service.limit(user_id, "agents.max") == 0

    def test_activate_and_check_has(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "pro")
        assert service.has(user_id, "ai.copilot") is True
        assert service.has(user_id, "process.execute") is True
        assert service.has(user_id, "network.http") is True

    def test_activate_and_check_limit(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "pro")
        assert service.limit(user_id, "agents.max") == 10
        assert service.limit(user_id, "policies.max") == 20

    def test_free_plan_limits(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "free")
        assert service.limit(user_id, "agents.max") == 1
        assert service.limit(user_id, "policies.max") == 3
        assert not service.has(user_id, "ai.copilot")
        assert not service.has(user_id, "process.execute")
        assert not service.has(user_id, "network.http")

    def test_require_success(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "pro")
        service.require(user_id, "ai.copilot")  # should not raise

    def test_require_failure(self, svc, user_id):
        service, _ = svc
        with pytest.raises(EntitlementError, match="not entitled"):
            service.require(user_id, "ai.copilot")

    def test_unknown_entitlement_denied(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "pro")
        assert not service.has(user_id, "nonexistent.feature")

    def test_expired_subscription_denied(self, svc, user_id):
        service, td = svc
        # Create an expired subscription directly (not preceded by an active one)
        expired = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.EXPIRED,
            start_time=datetime.now(timezone.utc),
        )
        from aegis.entitlement import _append_ndjson
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            expired.to_dict(),
        )
        # Re-create service to pick up data
        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot")

    def test_inactive_plan_rejected(self, svc, user_id):
        service, td = svc
        with pytest.raises(EntitlementError, match="not found"):
            service.activate_subscription(user_id, "nonexistent")

    def test_cross_user_isolation(self, svc):
        service, _ = svc
        uid1 = str(uuid.uuid4())
        uid2 = str(uuid.uuid4())
        service.activate_subscription(uid1, "pro")
        assert service.has(uid1, "ai.copilot")
        assert not service.has(uid2, "ai.copilot")

    def test_list_entitlements(self, svc, user_id):
        service, _ = svc
        service.activate_subscription(user_id, "free")
        info = service.list_entitlements(user_id)
        assert info["agents.max"] == 1
        assert info["ai.copilot"] is False


# ---------------------------------------------------------------------------
# Gateway integration tests
# ---------------------------------------------------------------------------


class TestGatewayEntitlement:
    def test_process_execution_requires_entitlement(self):
        td = tempfile.mkdtemp()
        gw = Gateway(td)
        action = Action(
            action_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            action_type="execute_process",
            params={"executable": "test"},
            requested_at=datetime.now(timezone.utc),
        )
        decision, result = gw.execute_process(
            str(uuid.uuid4()), action, str(uuid.uuid4()), str(uuid.uuid4()),
            executable_name="test",
        )
        assert decision.result is DecisionResult.DENY
        # Should be denied because of entitlement, not agent lookup
        # (agent lookup would also fail, but entitlement check is first)
        assert "not entitled" in decision.reason

    def test_http_request_requires_entitlement(self):
        td = tempfile.mkdtemp()
        gw = Gateway(td)
        action = Action(
            action_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            action_type="http_request",
            params={"url": "https://example.com/"},
            requested_at=datetime.now(timezone.utc),
        )
        decision, result = gw.http_request(
            str(uuid.uuid4()), action, str(uuid.uuid4()), str(uuid.uuid4()),
            url="https://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert "not entitled" in decision.reason

    def test_entitled_user_passes_gateway(self):
        """A user with a Pro subscription can proceed past entitlement."""
        td = tempfile.mkdtemp()
        from aegis.auth import Authenticator
        from aegis.registry import AgentRegistry
        from aegis.policy import parse_policy_yaml, PolicyStore
        from aegis.entitlement import EntitlementService

        auth = Authenticator(td)
        user = auth.register("gwtest", "ValidPass1!")
        svc = EntitlementService(td)
        svc.activate_subscription(user.id, "pro")

        registry = AgentRegistry(td)
        agent = registry.create(user.id, "gw-agent")

        policy = parse_policy_yaml(f"""\
version: "1.0"
id: "{str(uuid.uuid4())}"
name: gw-test
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "fs_read"
""", user.id)
        store = PolicyStore(td)
        store.save(policy)

        gw = Gateway(td)
        action = Action(
            action_id=str(uuid.uuid4()),
            agent_id=agent.id,
            action_type="fs_read",
            params={"path": "/test"},
            requested_at=datetime.now(timezone.utc),
        )
        # This should not be blocked by entitlement (fs_read has no entitlement
        # gate), but will proceed to agent/policy checks
        decision = gw.evaluate(user.id, action, agent.id, policy.id)
        assert decision.result is DecisionResult.ALLOW

    def test_entitlement_does_not_bypass_policy(self):
        """Even with an entitlement, the policy engine is still authoritative."""
        td = tempfile.mkdtemp()
        from aegis.auth import Authenticator
        from aegis.registry import AgentRegistry
        from aegis.policy import parse_policy_yaml, PolicyStore
        from aegis.entitlement import EntitlementService

        auth = Authenticator(td)
        user = auth.register("gwtest2", "ValidPass1!")
        svc = EntitlementService(td)
        svc.activate_subscription(user.id, "pro")

        registry = AgentRegistry(td)
        agent = registry.create(user.id, "gw-agent")

        # Policy that DENYs everything
        policy = parse_policy_yaml(f"""\
version: "1.0"
id: "{str(uuid.uuid4())}"
name: deny-all
priority: 100
enabled: true
rules:
  - effect: DENY
    match:
      action_type: "*"
""", user.id)
        store = PolicyStore(td)
        store.save(policy)

        gw = Gateway(td)
        action = Action(
            action_id=str(uuid.uuid4()),
            agent_id=agent.id,
            action_type="fs_read",
            params={"path": "/test"},
            requested_at=datetime.now(timezone.utc),
        )
        decision = gw.evaluate(user.id, action, agent.id, policy.id)
        assert decision.result is DecisionResult.DENY


# ---------------------------------------------------------------------------
# Regression: Subscription state machine
# ---------------------------------------------------------------------------
# Core rule: the MOST RECENT subscription (by created_at) determines
# the effective state, regardless of prior ACTIVE rows.
# ---------------------------------------------------------------------------


class TestSubscriptionStateMachine:
    """Verify the most-recent-wins state machine contract.

    Only the last-created subscription matters.  Cancelling, expiring,
    or suspending creates a *new* subscription row — earlier rows are
    never mutated.
    """

    def test_active_then_cancelled_loses_entitlement(self, svc, user_id):
        """ACTIVE + newer CANCELLED → not entitled (most recent wins)."""
        service, td = svc
        from aegis.entitlement import _append_ndjson, Subscription

        # 1. Activate a Pro subscription (older)
        older = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            older.to_dict(),
        )

        # 2. Create a CANCELLED subscription *after* it (newer)
        newer = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.CANCELLED,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            newer.to_dict(),
        )

        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot"), \
            "Most-recent CANCELLED should override older ACTIVE"

    def test_active_then_expired_loses_entitlement(self, svc, user_id):
        """ACTIVE + newer EXPIRED → not entitled."""
        service, td = svc
        from aegis.entitlement import _append_ndjson, Subscription

        older = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            older.to_dict(),
        )

        newer = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.EXPIRED,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            newer.to_dict(),
        )

        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot"), \
            "Most-recent EXPIRED should override older ACTIVE"

    def test_active_then_suspended_loses_entitlement(self, svc, user_id):
        """ACTIVE + newer SUSPENDED → not entitled."""
        service, td = svc
        from aegis.entitlement import _append_ndjson, Subscription

        older = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            older.to_dict(),
        )

        newer = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.SUSPENDED,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            newer.to_dict(),
        )

        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot"), \
            "Most-recent SUSPENDED should override older ACTIVE"

    def test_cancelled_then_reactivated_restores_entitlement(self, svc, user_id):
        """CANCELLED + newer ACTIVE → entitled (new active wins)."""
        service, td = svc
        from aegis.entitlement import _append_ndjson, Subscription

        older = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.CANCELLED,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            older.to_dict(),
        )

        newer = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            newer.to_dict(),
        )

        service2 = EntitlementService(td)
        assert service2.has(user_id, "ai.copilot"), \
            "Most-recent ACTIVE should override older CANCELLED"

    def test_two_active_most_recent_wins(self, svc, user_id):
        """Two ACTIVE subscriptions: most-recent's plan is used."""
        service, td = svc
        from aegis.entitlement import _append_ndjson, Subscription

        older = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="free",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            older.to_dict(),
        )

        newer = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            newer.to_dict(),
        )

        service2 = EntitlementService(td)
        assert service2.has(user_id, "ai.copilot"), "Pro plan should win"
        assert service2.limit(user_id, "agents.max") == 10


# ---------------------------------------------------------------------------
# Regression: end_time enforcement
# ---------------------------------------------------------------------------


class TestEndTimeEnforcement:
    """``is_active()`` must check *both* status *and* end_time."""

    def test_active_with_future_end_time_is_active(self):
        """ACTIVE + end_time in the future → active."""
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2099, 12, 31, tzinfo=timezone.utc),
        )
        assert s.is_active()

    def test_active_with_past_end_time_is_expired(self):
        """ACTIVE + end_time in the past → not active."""
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2020, 6, 1, tzinfo=timezone.utc),
        )
        assert not s.is_active()

    def test_active_with_no_end_time_is_active_indefinitely(self):
        """No end_time means active until explicitly terminated."""
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            end_time=None,
        )
        assert s.is_active()

    def test_expired_status_even_with_future_end_time(self):
        """EXPIRED status beats a future end_time."""
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.EXPIRED,
            start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2099, 12, 31, tzinfo=timezone.utc),
        )
        assert not s.is_active()

    def test_service_denies_after_end_time(self, svc, user_id):
        """End-time-expired subscriptions are denied by the service."""
        service, td = svc
        from aegis.entitlement import _append_ndjson

        past = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2020, 6, 1, tzinfo=timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            past.to_dict(),
        )
        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot")


# ---------------------------------------------------------------------------
# Regression: get_latest_subscription vs get_effective_subscription
# ---------------------------------------------------------------------------


class TestSubscriptionAccessors:
    def test_get_latest_returns_most_recent_regardless_of_status(self, svc, user_id):
        """get_latest_subscription returns the newest row, even if CANCELLED."""
        service, td = svc
        from aegis.entitlement import _append_ndjson

        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            Subscription(
                id=str(uuid.uuid4()), user_id=user_id, plan_id="pro",
                status=SubscriptionStatus.ACTIVE,
                start_time=datetime(2020, 1, 1, tzinfo=timezone.utc),
            ).to_dict(),
        )
        cancelled = Subscription(
            id=str(uuid.uuid4()), user_id=user_id, plan_id="pro",
            status=SubscriptionStatus.CANCELLED,
            start_time=datetime(2020, 2, 1, tzinfo=timezone.utc),
        )
        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            cancelled.to_dict(),
        )

        service2 = EntitlementService(td)
        latest = service2.get_latest_subscription(user_id)
        assert latest is not None
        assert latest.status is SubscriptionStatus.CANCELLED

        effective = service2.get_effective_subscription(user_id)
        assert effective is None, "Most recent is CANCELLED → no effective sub"

    def test_get_effective_returns_active_when_latest_is_active(self, svc, user_id):
        """get_effective_subscription returns the sub when latest is ACTIVE."""
        service, td = svc
        service.activate_subscription(user_id, "pro")
        effective = service.get_effective_subscription(user_id)
        assert effective is not None
        assert effective.plan_id == "pro"

    def test_get_effective_returns_free(self, svc, user_id):
        """Free plan subscribers get their subscription back."""
        service, td = svc
        service.activate_subscription(user_id, "free")
        effective = service.get_effective_subscription(user_id)
        assert effective is not None
        assert effective.plan_id == "free"


# ---------------------------------------------------------------------------
# Backward compatibility: existing tests must still pass
# ---------------------------------------------------------------------------
# The tests in TestEntitlementService are unchanged; these additional
# tests ensure edge-cases that were not previously covered.


class TestBackwardCompatibility:
    """Verify that behavioural changes do not break existing contracts."""

    def test_expired_subscription_only_still_denied(self, svc, user_id):
        """A lone EXPIRED subscription → denied (same as before)."""
        service, td = svc
        from aegis.entitlement import _append_ndjson

        _append_ndjson(
            os.path.join(td, "subscriptions.ndjson"),
            Subscription(
                id=str(uuid.uuid4()), user_id=user_id, plan_id="pro",
                status=SubscriptionStatus.EXPIRED,
                start_time=datetime.now(timezone.utc),
            ).to_dict(),
        )
        service2 = EntitlementService(td)
        assert not service2.has(user_id, "ai.copilot")

    def test_activate_then_check_entitlement_works(self, svc, user_id):
        """The basic activate → check flow (existing test behaviour)."""
        service, td = svc
        service.activate_subscription(user_id, "pro")
        assert service.has(user_id, "ai.copilot") is True
        assert service.has(user_id, "process.execute") is True
        assert service.limit(user_id, "agents.max") == 10

    def test_old_get_subscription_still_accessible(self, svc, user_id):
        """get_subscription is gone; get_latest_subscription replaces it."""
        service, td = svc
        assert not hasattr(service, "get_subscription"), \
            "get_subscription was renamed — use get_latest_subscription"
        assert hasattr(service, "get_latest_subscription")


# ---------------------------------------------------------------------------
# Deterministic serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_plan_deterministic(self):
        p = Plan(id="x", name="X", version="1.0", active=True,
                 entitlements={"b": 2, "a": 1})
        d = p.to_dict()
        assert list(d["entitlements"].keys()) == ["a", "b"]

    def test_subscription_deterministic(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        d = s.to_dict()
        # Verify it can be JSON-serialized
        json.dumps(d)
