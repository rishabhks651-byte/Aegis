"""Tests for the core data models."""

import json
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError

import pytest

from aegis.models import (
    Agent,
    Action,
    Decision,
    AuditEvent,
    DecisionResult,
    RuleEffect,
    _validate_uuid,
    _validate_tz_aware,
    _normalize_dt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_A_UUID = "550e8400-e29b-41d4-a716-446655440000"
_B_UUID = "660e8400-e29b-41d4-a716-446655440001"
_C_UUID = "770e8400-e29b-41d4-a716-446655440002"


def _utc(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)


def _make_agent(**kw) -> Agent:
    return Agent(
        id=kw.get("id", _A_UUID),
        name=kw.get("name", "ci-bot-prod"),
        user_id=kw.get("user_id", _B_UUID),
        created_at=kw.get("created_at", _utc("2026-01-01T00:00:00+00:00")),
        metadata=kw.get("metadata", {}),
        revoked=kw.get("revoked", False),
        revoked_at=kw.get("revoked_at"),
    )


def _make_action(**kw) -> Action:
    return Action(
        action_id=kw.get("action_id", _A_UUID),
        agent_id=kw.get("agent_id", _A_UUID),
        action_type=kw.get("action_type", "read_file"),
        params=kw.get("params", {"path": "/tmp/log"}),
        requested_at=kw.get("requested_at", _utc("2026-07-19T10:30:00+00:00")),
        context=kw.get("context"),
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestDecisionResult:
    def test_values(self) -> None:
        assert DecisionResult.ALLOW.value == "ALLOW"
        assert DecisionResult.DENY.value == "DENY"

    def test_from_string(self) -> None:
        assert DecisionResult("ALLOW") is DecisionResult.ALLOW
        assert DecisionResult("DENY") is DecisionResult.DENY

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            DecisionResult("MAYBE")  # type: ignore[arg-type]


class TestRuleEffect:
    def test_values(self) -> None:
        assert RuleEffect.ALLOW.value == "ALLOW"
        assert RuleEffect.DENY.value == "DENY"

    def test_from_string(self) -> None:
        assert RuleEffect("ALLOW") is RuleEffect.ALLOW

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            RuleEffect("BYPASS")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class TestValidateUuid:
    def test_valid_uuid_passes(self) -> None:
        _validate_uuid(_A_UUID, "test")

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises(ValueError):
            _validate_uuid("not-a-uuid", "test")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            _validate_uuid("", "test")


class TestValidateTzAware:
    def test_tz_aware_passes(self) -> None:
        _validate_tz_aware(datetime(2026, 1, 1, tzinfo=timezone.utc), "test")

    def test_naive_datetime_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            _validate_tz_aware(datetime(2026, 1, 1), "test")

    def test_non_datetime_raises(self) -> None:
        with pytest.raises(TypeError):
            _validate_tz_aware("2026-01-01", "test")  # type: ignore[arg-type]


class TestNormalizeDt:
    def test_already_utc(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert _normalize_dt(dt) is dt

    def test_non_utc_converted(self) -> None:
        dt = datetime(2026, 1, 1, 5, 0, 0, tzinfo=timezone(timedelta(hours=5)))
        normalized = _normalize_dt(dt)
        assert normalized == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_deterministic(self) -> None:
        dt1 = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        dt2 = datetime(2026, 6, 15, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        assert _normalize_dt(dt1) == _normalize_dt(dt2)


# ---------------------------------------------------------------------------
# Agent model
# ---------------------------------------------------------------------------


class TestAgentCreation:
    def test_minimal_agent(self) -> None:
        agent = _make_agent()
        assert agent.id == _A_UUID
        assert agent.name == "ci-bot-prod"
        assert agent.created_at.tzinfo is not None
        assert agent.metadata == {}
        assert agent.revoked is False
        assert agent.revoked_at is None

    def test_agent_with_metadata(self) -> None:
        agent = _make_agent(metadata={"env": "prod", "team": "infra"})
        assert agent.metadata["env"] == "prod"

    def test_agent_with_revoked_at(self) -> None:
        revoked_at = _utc("2026-06-01T00:00:00+00:00")
        agent = _make_agent(revoked=True, revoked_at=revoked_at)
        assert agent.revoked is True
        assert agent.revoked_at == revoked_at

    def test_invalid_id_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_agent(id="bad-id")

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_agent(id="")

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_agent(name="")

    def test_name_with_spaces_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_agent(name="my agent")

    def test_name_too_long_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_agent(name="a" * 65)

    def test_naive_created_at_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            _make_agent(created_at=datetime(2026, 1, 1))

    def test_naive_revoked_at_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            _make_agent(revoked=True, revoked_at=datetime(2026, 6, 1))

    def test_created_at_normalized_to_utc(self) -> None:
        tz = timezone(timedelta(hours=-5))
        agent = _make_agent(created_at=datetime(2026, 1, 1, 5, 0, 0, tzinfo=tz))
        assert agent.created_at.tzinfo is timezone.utc
        assert agent.created_at.hour == 10


class TestAgentFrozen:
    def test_cannot_modify(self) -> None:
        agent = _make_agent()
        with pytest.raises(FrozenInstanceError):
            agent.name = "new-name"  # type: ignore[misc]


class TestAgentSerialization:
    def test_to_dict_keys(self) -> None:
        agent = _make_agent()
        d = agent.to_dict()
        assert d["id"] == _A_UUID
        assert d["name"] == "ci-bot-prod"
        assert isinstance(d["created_at"], str)
        assert d["created_at"].endswith("+00:00")
        assert d["revoked"] is False
        assert "revoked_at" not in d

    def test_to_dict_with_revoked_at(self) -> None:
        agent = _make_agent(
            revoked=True, revoked_at=_utc("2026-06-01T00:00:00+00:00")
        )
        d = agent.to_dict()
        assert d["revoked"] is True
        assert d["revoked_at"] == "2026-06-01T00:00:00+00:00"

    def test_to_dict_deterministic_metadata(self) -> None:
        agent = _make_agent(metadata={"z": "1", "a": "2"})
        d = agent.to_dict()
        keys = list(d["metadata"].keys())
        assert keys == ["a", "z"]

    def test_from_dict_round_trip(self) -> None:
        original = _make_agent(
            revoked=True, revoked_at=_utc("2026-06-01T00:00:00+00:00")
        )
        d = original.to_dict()
        restored = Agent.from_dict(d)
        assert restored == original

    def test_from_dict_no_revoked_at(self) -> None:
        original = _make_agent()
        restored = Agent.from_dict(original.to_dict())
        assert restored == original

    def test_json_round_trip(self) -> None:
        original = _make_agent(metadata={"key": "val"})
        json_str = json.dumps(original.to_dict(), sort_keys=True)
        restored = Agent.from_dict(json.loads(json_str))
        assert restored == original


# ---------------------------------------------------------------------------
# Action model
# ---------------------------------------------------------------------------


class TestActionCreation:
    def test_minimal_action(self) -> None:
        action = _make_action()
        assert action.action_id == _A_UUID
        assert action.agent_id == _A_UUID
        assert action.action_type == "read_file"
        assert action.params == {"path": "/tmp/log"}
        assert action.context is None

    def test_action_with_context(self) -> None:
        action = _make_action(context={"cwd": "/home/user"})
        assert action.context == {"cwd": "/home/user"}

    def test_action_empty_params(self) -> None:
        action = _make_action(params={})
        assert action.params == {}

    def test_invalid_action_id_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_action(action_id="bad")

    def test_invalid_agent_id_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_action(agent_id="bad")

    def test_empty_action_type_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_action(action_type="")

    def test_action_type_with_space_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_action(action_type="read file")

    def test_action_type_special_chars_raises(self) -> None:
        with pytest.raises(ValueError):
            _make_action(action_type="read.file")  # dot is not allowed

    def test_action_type_with_underscore_allowed(self) -> None:
        action = _make_action(action_type="read_file")
        assert action.action_type == "read_file"

    def test_action_type_with_hyphen_allowed(self) -> None:
        action = _make_action(action_type="read-file")
        assert action.action_type == "read-file"

    def test_naive_requested_at_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            _make_action(requested_at=datetime(2026, 7, 19))

    def test_non_utc_normalized(self) -> None:
        tz = timezone(timedelta(hours=9))
        action = _make_action(
            requested_at=datetime(2026, 7, 19, 19, 30, 0, tzinfo=tz)
        )
        assert action.requested_at.tzinfo is timezone.utc
        assert action.requested_at.hour == 10


class TestActionFrozen:
    def test_cannot_modify(self) -> None:
        action = _make_action()
        with pytest.raises(FrozenInstanceError):
            action.action_type = "new"  # type: ignore[misc]


class TestActionSerialization:
    def test_to_dict_keys(self) -> None:
        action = _make_action()
        d = action.to_dict()
        assert d["action_id"] == _A_UUID
        assert d["action_type"] == "read_file"
        assert isinstance(d["requested_at"], str)
        assert "context" not in d

    def test_to_dict_with_context(self) -> None:
        action = _make_action(context={"cwd": "/home"})
        d = action.to_dict()
        assert d["context"] == {"cwd": "/home"}

    def test_to_dict_deterministic_params(self) -> None:
        action = _make_action(params={"z": 1, "a": 2})
        d = action.to_dict()
        keys = list(d["params"].keys())
        assert keys == ["a", "z"]

    def test_from_dict_round_trip(self) -> None:
        original = _make_action(context={"cwd": "/tmp"})
        restored = Action.from_dict(original.to_dict())
        assert restored == original

    def test_json_round_trip(self) -> None:
        original = _make_action()
        json_str = json.dumps(original.to_dict(), sort_keys=True)
        restored = Action.from_dict(json.loads(json_str))
        assert restored == original


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


class TestDecisionCreation:
    def test_allow_decision(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="allow-tmp-read",
            rule_id="rule-01",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="Policy 'allow-tmp-read' rule 'rule-01': allowed",
        )
        assert d.result is DecisionResult.ALLOW
        assert d.matched is True

    def test_deny_decision(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="deny-etc",
            rule_id="rule-01",
            rule_effect=RuleEffect.DENY,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="Policy 'deny-etc' rule 'rule-01': denied",
        )
        assert d.result is DecisionResult.DENY

    def test_fallback_deny(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="No matching rule in any enabled policy",
        )
        assert d.result is DecisionResult.DENY
        assert d.matched is False
        assert d.policy_id is None

    def test_empty_reason_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            Decision(
                decision_id=_A_UUID,
                action_id=_B_UUID,
                agent_id=_C_UUID,
                result=DecisionResult.DENY,
                policy_id=None,
                policy_name=None,
                rule_id=None,
                rule_effect=None,
                matched=False,
                evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
                reason="",
            )

    def test_invalid_result_type_raises(self) -> None:
        with pytest.raises(TypeError):
            Decision(
                decision_id=_A_UUID,
                action_id=_B_UUID,
                agent_id=_C_UUID,
                result="ALLOW",  # type: ignore[arg-type]
                policy_id=None,
                policy_name=None,
                rule_id=None,
                rule_effect=None,
                matched=False,
                evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
                reason="denied",
            )

    def test_invalid_rule_effect_type_raises(self) -> None:
        with pytest.raises(TypeError):
            Decision(
                decision_id=_A_UUID,
                action_id=_B_UUID,
                agent_id=_C_UUID,
                result=DecisionResult.ALLOW,
                policy_id=None,
                policy_name=None,
                rule_id=None,
                rule_effect="ALLOW",  # type: ignore[arg-type]
                matched=True,
                evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
                reason="allowed",
            )


class TestDecisionFrozen:
    def test_cannot_modify(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="denied",
        )
        with pytest.raises(FrozenInstanceError):
            d.reason = "new"  # type: ignore[misc]


class TestDecisionSerialization:
    def test_to_dict_allow(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="p",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        dd = d.to_dict()
        assert dd["result"] == "ALLOW"
        assert dd["rule_effect"] == "ALLOW"
        assert dd["matched"] is True

    def test_to_dict_fallback_deny(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        dd = d.to_dict()
        assert dd["result"] == "DENY"
        assert dd["rule_effect"] is None
        assert dd["matched"] is False

    def test_from_dict_round_trip(self) -> None:
        original = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="p",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        restored = Decision.from_dict(original.to_dict())
        assert restored == original

    def test_json_round_trip(self) -> None:
        original = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        json_str = json.dumps(original.to_dict(), sort_keys=True)
        restored = Decision.from_dict(json.loads(json_str))
        assert restored == original


# ---------------------------------------------------------------------------
# AuditEvent model
# ---------------------------------------------------------------------------


class TestAuditEventCreation:
    def test_from_decision_allow(self) -> None:
        action = _make_action(action_id=_A_UUID, agent_id=_A_UUID)
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="allow-tmp",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        event = AuditEvent.from_decision(decision, action, "ci-bot-prod")
        assert event.audit_version == "1.0"
        assert event.decision_id == _B_UUID
        assert event.agent_name == "ci-bot-prod"
        assert event.action_type == "read_file"
        assert event.params == {"path": "/tmp/log"}
        assert event.result == "ALLOW"
        assert event.matched is True
        assert event.rule_effect == "ALLOW"
        assert event.reason == "allowed"

    def test_from_decision_fallback_deny(self) -> None:
        action = _make_action(action_id=_A_UUID)
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        event = AuditEvent.from_decision(decision, action, "bot")
        assert event.result == "DENY"
        assert event.matched is False
        assert event.rule_effect is None

    def test_default_audit_version(self) -> None:
        event = AuditEvent()
        assert event.audit_version == "1.0"

    def test_invalid_audit_version_raises(self) -> None:
        with pytest.raises(ValueError):
            AuditEvent(audit_version="2.0")

    def test_invalid_decision_id_raises(self) -> None:
        with pytest.raises(ValueError):
            AuditEvent(decision_id="bad")

    def test_invalid_result_raises(self) -> None:
        with pytest.raises(ValueError):
            AuditEvent(result="MAYBE")

    def test_allow_without_match_raises(self) -> None:
        with pytest.raises(ValueError, match="ALLOW result requires matched=True"):
            AuditEvent(result="ALLOW", matched=False)

    def test_allow_with_match_ok(self) -> None:
        event = AuditEvent(result="ALLOW", matched=True)
        assert event.result == "ALLOW"

    def test_deny_without_match_ok(self) -> None:
        event = AuditEvent(result="DENY", matched=False)
        assert event.result == "DENY"

    def test_deny_with_match_ok(self) -> None:
        event = AuditEvent(result="DENY", matched=True)
        assert event.result == "DENY"


class TestAuditEventSerialization:
    def test_to_dict_keys(self) -> None:
        action = _make_action()
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        event = AuditEvent.from_decision(decision, action, "bot")
        d = event.to_dict()
        assert d["audit_version"] == "1.0"
        assert d["decision_id"] == _B_UUID
        assert d["result"] == "DENY"
        assert d["evaluated_at"] is not None

    def test_from_dict_round_trip(self) -> None:
        action = _make_action()
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="p",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        original = AuditEvent.from_decision(decision, action, "bot")
        restored = AuditEvent.from_dict(original.to_dict())
        assert restored == original

    def test_json_round_trip(self) -> None:
        action = _make_action()
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        original = AuditEvent.from_decision(decision, action, "bot")
        json_str = json.dumps(original.to_dict(), sort_keys=True)
        restored = AuditEvent.from_dict(json.loads(json_str))
        assert restored == original

    def test_default_event_round_trip(self) -> None:
        original = AuditEvent()
        restored = AuditEvent.from_dict(original.to_dict())
        assert restored == original


# ---------------------------------------------------------------------------
# Cross-model invariants
# ---------------------------------------------------------------------------


class TestCrossModelInvariants:
    def test_audit_event_matches_decision(self) -> None:
        action = _make_action()
        decision = Decision(
            decision_id=_B_UUID,
            action_id=_A_UUID,
            agent_id=_A_UUID,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="p",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        event = AuditEvent.from_decision(decision, action, "bot")
        assert event.result == decision.result.value
        assert event.matched == decision.matched
        assert event.policy_id == decision.policy_id
        assert event.rule_id == decision.rule_id
        assert event.action_id == decision.action_id

    def test_decision_contains_action_ids(self) -> None:
        action = _make_action(action_id=_A_UUID, agent_id=_A_UUID)
        decision = Decision(
            decision_id=_B_UUID,
            action_id=action.action_id,
            agent_id=action.agent_id,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        assert decision.action_id == action.action_id
        assert decision.agent_id == action.agent_id

    def test_all_models_serialize_to_json(self) -> None:
        agent = _make_agent()
        action = _make_action()
        decision = Decision(
            decision_id=_B_UUID,
            action_id=action.action_id,
            agent_id=agent.id,
            result=DecisionResult.ALLOW,
            policy_id="660e8400-e29b-41d4-a716-446655440010",
            policy_name="p",
            rule_id="r1",
            rule_effect=RuleEffect.ALLOW,
            matched=True,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="allowed",
        )
        event = AuditEvent.from_decision(decision, action, agent.name)
        for model, name in [
            (agent, "agent"),
            (action, "action"),
            (decision, "decision"),
            (event, "audit_event"),
        ]:
            d = model.to_dict()
            json_str = json.dumps(d, sort_keys=True)
            assert isinstance(json_str, str), f"{name} serialization failed"
            assert len(json_str) > 0, f"{name} serialized to empty string"


# ---------------------------------------------------------------------------
# Fail-closed / edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_decision_fallback_deny_always_possible(self) -> None:
        """Decision model allows the critical security pattern: deny with no match."""
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no matching rule",
        )
        assert d.result is DecisionResult.DENY
        assert d.matched is False

    def test_all_fields_none_on_fallback(self) -> None:
        """Fallback DENY must not have stale policy references."""
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        assert d.policy_id is None
        assert d.policy_name is None
        assert d.rule_id is None
        assert d.rule_effect is None

    def test_policy_id_is_none_not_empty_string(self) -> None:
        """Design invariant: policy_id is None when not applicable, not ''."""
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        assert d.policy_id is None

    def test_normalize_preserves_determinism(self) -> None:
        """Same absolute time, different timezones -> same decision record."""
        tz1 = timezone(timedelta(hours=2))
        tz2 = timezone(timedelta(hours=-3))
        dt1 = datetime(2026, 7, 19, 12, 0, 0, tzinfo=tz1)
        dt2 = datetime(2026, 7, 19, 7, 0, 0, tzinfo=tz2)
        assert _normalize_dt(dt1) == _normalize_dt(dt2)

    def test_uuid_accepts_upper_and_lower(self) -> None:
        """UUID validation is case-insensitive."""
        _validate_uuid("550E8400-E29B-41D4-A716-446655440000", "test")
        _validate_uuid("550e8400-e29b-41d4-a716-446655440000", "test")


# ---------------------------------------------------------------------------
# Deterministic serialization
# ---------------------------------------------------------------------------


class TestDeterministicSerialization:
    def test_agent_to_dict_same_twice(self) -> None:
        agent = _make_agent(metadata={"b": "2", "a": "1"})
        assert agent.to_dict() == agent.to_dict()

    def test_action_to_dict_same_twice(self) -> None:
        action = _make_action(params={"b": 2, "a": 1})
        assert action.to_dict() == action.to_dict()

    def test_decision_to_dict_same_twice(self) -> None:
        d = Decision(
            decision_id=_A_UUID,
            action_id=_B_UUID,
            agent_id=_C_UUID,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=_utc("2026-07-19T10:30:05+00:00"),
            reason="no match",
        )
        assert d.to_dict() == d.to_dict()
