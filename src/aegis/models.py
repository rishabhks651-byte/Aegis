"""Core data models for Aegis v0.1.

These frozen dataclasses are the stable contracts between all components.
Every model validates its own fields on construction and provides
deterministic serialization via to_dict() / from_dict().
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DecisionResult(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class RuleEffect(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_AGENT_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_ACTION_TYPE_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_POLICY_NAME_RE = re.compile(r"^.{1,128}$")


def _validate_uuid(value: str, field_name: str) -> None:
    if not _UUID_RE.match(value):
        raise ValueError(f"{field_name} must be a valid UUID string: {value!r}")


def _validate_tz_aware(dt: datetime, field_name: str) -> None:
    if not isinstance(dt, datetime):
        raise TypeError(f"{field_name} must be a datetime instance")
    if dt.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _normalize_dt(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc)


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(frozen=True)
class Agent:
    """A registered Aegis agent identity, owned by a user."""

    id: str
    name: str
    user_id: str
    created_at: datetime
    metadata: dict[str, str] = field(default_factory=dict)
    revoked: bool = False
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.id, "id")
        _validate_uuid(self.user_id, "user_id")
        if not _AGENT_NAME_RE.match(self.name):
            raise ValueError(
                f"name must be 1-64 chars matching [a-zA-Z0-9._-]: {self.name!r}"
            )
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))
        if self.revoked_at is not None:
            _validate_tz_aware(self.revoked_at, "revoked_at")
            object.__setattr__(self, "revoked_at", _normalize_dt(self.revoked_at))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "metadata": dict(sorted(self.metadata.items())),
            "revoked": self.revoked,
        }
        if self.revoked_at is not None:
            d["revoked_at"] = self.revoked_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Agent:
        revoked_at = _parse_iso(data["revoked_at"]) if data.get("revoked_at") else None
        return cls(
            id=data["id"],
            name=data["name"],
            user_id=data["user_id"],
            created_at=_parse_iso(data["created_at"]),
            metadata=data.get("metadata", {}),
            revoked=data.get("revoked", False),
            revoked_at=revoked_at,
        )


@dataclass(frozen=True)
class Action:
    """A request by an agent to perform an action."""

    action_id: str
    agent_id: str
    action_type: str
    params: dict[str, Any]
    requested_at: datetime
    context: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.action_id, "action_id")
        _validate_uuid(self.agent_id, "agent_id")
        if not _ACTION_TYPE_RE.match(self.action_type):
            raise ValueError(
                f"action_type must match [a-zA-Z0-9_-]: {self.action_type!r}"
            )
        _validate_tz_aware(self.requested_at, "requested_at")
        object.__setattr__(self, "requested_at", _normalize_dt(self.requested_at))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "params": dict(sorted(self.params.items())),
            "requested_at": self.requested_at.isoformat(),
        }
        if self.context is not None:
            d["context"] = dict(sorted(self.context.items()))
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Action:
        return cls(
            action_id=data["action_id"],
            agent_id=data["agent_id"],
            action_type=data["action_type"],
            params=data.get("params", {}),
            requested_at=_parse_iso(data["requested_at"]),
            context=data.get("context"),
        )


@dataclass(frozen=True)
class Decision:
    """The result of evaluating an action against policy."""

    decision_id: str
    action_id: str
    agent_id: str
    result: DecisionResult
    policy_id: str | None
    policy_name: str | None
    rule_id: str | None
    rule_effect: RuleEffect | None
    matched: bool
    evaluated_at: datetime
    reason: str

    def __post_init__(self) -> None:
        _validate_uuid(self.decision_id, "decision_id")
        _validate_uuid(self.action_id, "action_id")
        _validate_uuid(self.agent_id, "agent_id")
        if not isinstance(self.result, DecisionResult):
            raise TypeError(f"result must be a DecisionResult: {self.result!r}")
        if self.policy_id is not None:
            _validate_uuid(self.policy_id, "policy_id")
        if self.rule_effect is not None and not isinstance(self.rule_effect, RuleEffect):
            raise TypeError(f"rule_effect must be a RuleEffect: {self.rule_effect!r}")
        if not isinstance(self.matched, bool):
            raise TypeError("matched must be a bool")
        _validate_tz_aware(self.evaluated_at, "evaluated_at")
        object.__setattr__(self, "evaluated_at", _normalize_dt(self.evaluated_at))
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("reason must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "result": self.result.value,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "rule_id": self.rule_id,
            "rule_effect": self.rule_effect.value if self.rule_effect else None,
            "matched": self.matched,
            "evaluated_at": self.evaluated_at.isoformat(),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Decision:
        rule_effect = (
            RuleEffect(data["rule_effect"]) if data.get("rule_effect") else None
        )
        return cls(
            decision_id=data["decision_id"],
            action_id=data["action_id"],
            agent_id=data["agent_id"],
            result=DecisionResult(data["result"]),
            policy_id=data.get("policy_id"),
            policy_name=data.get("policy_name"),
            rule_id=data.get("rule_id"),
            rule_effect=rule_effect,
            matched=data["matched"],
            evaluated_at=_parse_iso(data["evaluated_at"]),
            reason=data["reason"],
        )


@dataclass(frozen=True)
class AuditEvent:
    """An immutable record written to the audit log for every evaluation."""

    audit_version: str = "1.0"
    decision_id: str = ""
    action_id: str = ""
    agent_id: str = ""
    agent_name: str = ""
    action_type: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    result: str = ""
    matched: bool = False
    policy_id: str | None = None
    policy_name: str | None = None
    rule_id: str | None = None
    rule_effect: str | None = None
    evaluated_at: str = ""
    reason: str = ""
    user_id: str = ""
    previous_hash: str | None = None
    hash: str = ""

    def __post_init__(self) -> None:
        if self.audit_version != "1.0":
            raise ValueError(f"audit_version must be '1.0': {self.audit_version!r}")
        if self.decision_id and not _UUID_RE.match(self.decision_id):
            raise ValueError(
                f"decision_id must be a valid UUID: {self.decision_id!r}"
            )
        if self.result and self.result not in ("ALLOW", "DENY"):
            raise ValueError(f"result must be ALLOW or DENY: {self.result!r}")
        if self.result == "ALLOW" and not self.matched:
            raise ValueError("ALLOW result requires matched=True")
        if self.evaluated_at:
            _parse_iso(self.evaluated_at)

    @classmethod
    def from_decision(
        cls,
        decision: Decision,
        action: Action,
        agent_name: str,
        user_id: str = "",
    ) -> AuditEvent:
        return cls(
            decision_id=decision.decision_id,
            action_id=decision.action_id,
            agent_id=decision.agent_id,
            agent_name=agent_name,
            action_type=action.action_type,
            params=action.params,
            result=decision.result.value,
            matched=decision.matched,
            policy_id=decision.policy_id,
            policy_name=decision.policy_name,
            rule_id=decision.rule_id,
            rule_effect=(
                decision.rule_effect.value if decision.rule_effect else None
            ),
            evaluated_at=decision.evaluated_at.isoformat(),
            reason=decision.reason,
            user_id=user_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action_type": self.action_type,
            "params": dict(sorted(self.params.items())),
            "result": self.result,
            "matched": self.matched,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "rule_id": self.rule_id,
            "rule_effect": self.rule_effect,
            "evaluated_at": self.evaluated_at,
            "reason": self.reason,
            "user_id": self.user_id,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        return cls(
            audit_version=data.get("audit_version", "1.0"),
            decision_id=data.get("decision_id", ""),
            action_id=data.get("action_id", ""),
            agent_id=data.get("agent_id", ""),
            agent_name=data.get("agent_name", ""),
            action_type=data.get("action_type", ""),
            params=data.get("params", {}),
            result=data.get("result", ""),
            matched=data.get("matched", False),
            policy_id=data.get("policy_id"),
            policy_name=data.get("policy_name"),
            rule_id=data.get("rule_id"),
            rule_effect=data.get("rule_effect"),
            evaluated_at=data.get("evaluated_at", ""),
            reason=data.get("reason", ""),
            user_id=data.get("user_id", ""),
            previous_hash=data.get("previous_hash"),
            hash=data.get("hash", ""),
        )


# ---------------------------------------------------------------------------
# Policy & Rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A single policy rule — an effect (ALLOW/DENY) with match conditions."""

    id: str
    effect: RuleEffect
    match: dict[str, Any]
    comment: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("Rule id must be a non-empty string")
        if not isinstance(self.effect, RuleEffect):
            raise TypeError(f"Rule effect must be a RuleEffect: {self.effect!r}")
        if not isinstance(self.match, dict) or not self.match:
            raise ValueError("Rule match must be a non-empty dict")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "effect": self.effect.value,
            "match": dict(sorted(self.match.items())),
            "comment": self.comment,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            id=data["id"],
            effect=RuleEffect(data["effect"]),
            match=data["match"],
            comment=data.get("comment", ""),
        )


# ---------------------------------------------------------------------------
# Network (HTTP)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpResponse:
    """The outcome of a controlled HTTP request."""

    status_code: int
    elapsed_ms: int
    timed_out: bool
    body_truncated: bool
    body: str
    headers: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "elapsed_ms": self.elapsed_ms,
            "timed_out": self.timed_out,
            "body_truncated": self.body_truncated,
            "body": self.body,
            "headers": dict(sorted(self.headers.items())),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HttpResponse:
        return cls(
            status_code=data["status_code"],
            elapsed_ms=data.get("elapsed_ms", 0),
            timed_out=data.get("timed_out", False),
            body_truncated=data.get("body_truncated", False),
            body=data.get("body", ""),
            headers=data.get("headers", {}),
        )


# ---------------------------------------------------------------------------
# Process Execution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessResult:
    """The outcome of executing a controlled process."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    execution_time_ms: int
    executable: str
    args: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "execution_time_ms": self.execution_time_ms,
            "executable": self.executable,
            "args": list(self.args),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProcessResult:
        return cls(
            exit_code=data["exit_code"],
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            timed_out=data.get("timed_out", False),
            output_truncated=data.get("output_truncated", False),
            execution_time_ms=data.get("execution_time_ms", 0),
            executable=data["executable"],
            args=tuple(data.get("args", [])),
        )


@dataclass(frozen=True)
class Policy:
    """A named collection of ordered rules owned by a user."""

    id: str
    name: str
    user_id: str
    description: str = ""
    rules: tuple[Rule, ...] = ()
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("Policy id must be a non-empty string")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Policy name must be a non-empty string")
        _validate_uuid(self.user_id, "user_id")
        if not isinstance(self.rules, tuple) or not all(
            isinstance(r, Rule) for r in self.rules
        ):
            raise TypeError("Policy rules must be a tuple of Rule instances")
        if not isinstance(self.priority, int):
            raise TypeError("Policy priority must be an integer")
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "description": self.description,
            "rules": [r.to_dict() for r in self.rules],
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = tuple(Rule.from_dict(r) for r in data.get("rules", []))
        return cls(
            id=data["id"],
            name=data["name"],
            user_id=data["user_id"],
            description=data.get("description", ""),
            rules=rules,
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
            created_at=_parse_iso(data["created_at"])
            if "created_at" in data
            else datetime.now(timezone.utc),
        )
