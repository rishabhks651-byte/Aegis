"""Subscription and entitlement system.

Core principle
--------------
Payment → Payment Record → Subscription → Entitlements → Feature Access

Each layer is independent.  The entitlement system answers one question:
"Is this user entitled to use feature X?"  It does NOT authorise
individual agent actions — that is the PolicyEngine's responsibility.
"""

from __future__ import annotations

import json
import os
import os.path
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aegis.rbac import AuthorizationService, PERM_SUBSCRIPTION_MANAGE

# ---------------------------------------------------------------------------
# Constants / built-in plans
# ---------------------------------------------------------------------------

_BUILT_IN_PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "name": "Free",
        "version": "1.0",
        "price_minor": 0,
        "currency": "INR",
        "entitlements": {
            "agents.max": 1,
            "policies.max": 3,
            "ai.copilot": False,
            "audit.advanced": False,
            "process.execute": False,
            "network.http": False,
        },
    },
    "pro": {
        "name": "Pro",
        "version": "1.0",
        "price_minor": 49900,
        "currency": "INR",
        "entitlements": {
            "agents.max": 10,
            "policies.max": 20,
            "ai.copilot": True,
            "audit.advanced": True,
            "process.execute": True,
            "network.http": True,
        },
    },
    "enterprise": {
        "name": "Enterprise",
        "version": "1.0",
        "price_minor": 99900,
        "currency": "INR",
        "entitlements": {
            "agents.max": 100,
            "policies.max": 500,
            "ai.copilot": True,
            "audit.advanced": True,
            "process.execute": True,
            "network.http": True,
        },
    },
}

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EntitlementError(Exception):
    """Raised when a user is not entitled to a feature."""


# ---------------------------------------------------------------------------
# Subscription status
# ---------------------------------------------------------------------------


class SubscriptionStatus(Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    PENDING = "PENDING"
    SUSPENDED = "SUSPENDED"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """A subscription plan with entitlement definitions and pricing."""

    id: str
    name: str
    version: str
    active: bool
    entitlements: dict[str, Any]
    price_minor: int = 0
    currency: str = "INR"
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("Plan id must be non-empty")
        if not self.name or not self.name.strip():
            raise ValueError("Plan name must be non-empty")
        if not isinstance(self.entitlements, dict):
            raise TypeError("entitlements must be a dict")
        if not isinstance(self.price_minor, int) or self.price_minor < 0:
            raise ValueError("price_minor must be a non-negative integer")
        if not self.currency or not isinstance(self.currency, str):
            raise ValueError("currency must be a non-empty string")
        from aegis.models import _validate_tz_aware, _normalize_dt
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "active": self.active,
            "price_minor": self.price_minor,
            "currency": self.currency,
            "entitlements": dict(sorted(self.entitlements.items())),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Plan:
        from aegis.models import _parse_iso
        return cls(
            id=data["id"],
            name=data["name"],
            version=data.get("version", "1.0"),
            active=data.get("active", True),
            price_minor=data.get("price_minor", 0),
            currency=data.get("currency", "INR"),
            entitlements=data.get("entitlements", {}),
            created_at=_parse_iso(data["created_at"])
            if "created_at" in data
            else datetime.now(timezone.utc),
        )


@dataclass(frozen=True)
class Subscription:
    """A user's subscription to a plan."""

    id: str
    user_id: str
    plan_id: str
    status: SubscriptionStatus
    start_time: datetime
    end_time: datetime | None = None
    renewal: bool = True
    payment_id: str | None = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def __post_init__(self) -> None:
        from aegis.models import _validate_uuid, _validate_tz_aware, _normalize_dt
        _validate_uuid(self.id, "id")
        _validate_uuid(self.user_id, "user_id")
        if not self.plan_id or not self.plan_id.strip():
            raise ValueError("plan_id must be non-empty")
        if not isinstance(self.status, SubscriptionStatus):
            raise TypeError(f"status must be a SubscriptionStatus: {self.status!r}")
        _validate_tz_aware(self.start_time, "start_time")
        object.__setattr__(self, "start_time", _normalize_dt(self.start_time))
        if self.end_time is not None:
            _validate_tz_aware(self.end_time, "end_time")
            object.__setattr__(self, "end_time", _normalize_dt(self.end_time))
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))

    def is_active(self) -> bool:
        """Return True only when the subscription is ACTIVE *and* within its time window.

        A subscription with no ``end_time`` is active indefinitely as long
        as its status is ACTIVE.
        """
        if self.status is not SubscriptionStatus.ACTIVE:
            return False
        if self.end_time is not None:
            now = datetime.now(timezone.utc)
            if now >= self.end_time:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "user_id": self.user_id,
            "plan_id": self.plan_id,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "renewal": self.renewal,
            "created_at": self.created_at.isoformat(),
        }
        if self.end_time is not None:
            d["end_time"] = self.end_time.isoformat()
        if self.payment_id is not None:
            d["payment_id"] = self.payment_id
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Subscription:
        from aegis.models import _parse_iso
        end_time = _parse_iso(data["end_time"]) if data.get("end_time") else None
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            plan_id=data["plan_id"],
            status=SubscriptionStatus(data["status"]),
            start_time=_parse_iso(data["start_time"]),
            end_time=end_time,
            renewal=data.get("renewal", True),
            payment_id=data.get("payment_id"),
            created_at=_parse_iso(data["created_at"])
            if "created_at" in data
            else datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# NDJSON helpers (local copies)
# ---------------------------------------------------------------------------


def _read_ndjson(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _append_ndjson(path: str, record: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _dedup_by_field(
    records: list[dict[str, Any]], field: str = "id",
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for r in records:
        result[r[field]] = r
    return result


# ---------------------------------------------------------------------------
# EntitlementService
# ---------------------------------------------------------------------------


class EntitlementService:
    """Central gateway for entitlement checks.

    Usage::

        svc = EntitlementService(data_dir)
        svc.require(user_id, "ai.copilot")       # raises on failure
        svc.has(user_id, "process.execute")       # → bool
        svc.limit(user_id, "agents.max")          # → int
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._plans_path = os.path.join(data_dir, "plans.ndjson")
        self._subs_path = os.path.join(data_dir, "subscriptions.ndjson")
        self._ensure_seed_plans()

    @property
    def _authz(self) -> AuthorizationService:
        if not hasattr(self, "_authz_svc"):
            object.__setattr__(self, "_authz_svc", AuthorizationService(self._data_dir))
        return self._authz_svc  # type: ignore[has-type]

    # -- public API ----------------------------------------------------------

    def require(self, user_id: str, entitlement: str) -> None:
        """Raise ``EntitlementError`` if *user_id* lacks *entitlement*.

        For boolean entitlements the user must have ``True``.
        For numeric entitlements the user must have a value > 0.
        """
        if not self.has(user_id, entitlement):
            raise EntitlementError(
                f"User is not entitled to '{entitlement}'"
            )

    def has(self, user_id: str, entitlement: str) -> bool:
        """Return ``True`` if the user's plan grants *entitlement*.

        Fail-closed: unknown user, missing subscription, inactive
        subscription, unknown plan, or corrupted data all return False.
        """
        sub = self._active_subscription(user_id)
        if sub is None:
            return False
        plan = self._plan(sub.plan_id)
        if plan is None:
            return False
        value = plan.entitlements.get(entitlement)
        if value is None:
            return False  # unknown entitlement → deny
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value > 0
        return bool(value)

    def limit(self, user_id: str, entitlement: str) -> int:
        """Return the numeric limit for *entitlement*, or 0 if not entitled.

        Unlike ``has()``, this returns the actual limit value (e.g. 10
        for ``agents.max``) even when the user is entitled.
        """
        sub = self._active_subscription(user_id)
        if sub is None:
            return 0
        plan = self._plan(sub.plan_id)
        if plan is None:
            return 0
        value = plan.entitlements.get(entitlement)
        if value is None:
            return 0
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, (int, float)):
            return int(value)
        return 0

    def get_latest_subscription(self, user_id: str) -> Subscription | None:
        """Return the most-recently-created subscription for *user_id*.

        Unlike :meth:`get_effective_subscription`, this does *not* check
        whether the subscription is currently active — it returns whatever
        row was created last, regardless of status.
        """
        subs = self._user_subscriptions(user_id)
        if not subs:
            return None
        return subs[-1]

    def get_effective_subscription(self, user_id: str) -> Subscription | None:
        """Return the subscription that currently governs entitlements.

        This delegates to the same logic as the internal
        ``_active_subscription`` method.  Returns ``None`` when there is
        no effective (active, non-free) subscription.
        """
        return self._active_subscription(user_id)

    def get_plan(self, plan_id: str) -> Plan | None:
        """Look up a plan by ID."""
        return self._plan(plan_id)

    def list_plans(self) -> list[Plan]:
        """Return all active plans."""
        return [p for p in self._all_plans() if p.active]

    def activate_subscription(
        self, user_id: str, plan_id: str, caller_id: str | None = None,
    ) -> Subscription:
        """Activate a subscription for *user_id*.

        Requires ``subscription.manage`` permission on *caller_id*.
        Creates a new ACTIVE subscription.  Existing subscriptions are
        preserved for history.
        """
        if caller_id is not None:
            self._authz.require(caller_id, PERM_SUBSCRIPTION_MANAGE)

        plan = self._plan(plan_id)
        if plan is None:
            raise EntitlementError(f"Plan {plan_id!r} not found")
        if not plan.active:
            raise EntitlementError(f"Plan {plan_id!r} is not active")

        sub = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id=plan_id,
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        _append_ndjson(self._subs_path, sub.to_dict())
        return sub

    def activate_from_payment(
        self, user_id: str, plan_id: str, payment_id: str,
    ) -> Subscription:
        """Activate a subscription from a verified payment.

        This is the **only** production path for creating paid subscriptions.
        The caller is responsible for ensuring *payment_id* has already been
        VERIFIED.  Idempotent: if a subscription linked to *payment_id*
        already exists, it is returned instead of creating a duplicate.
        """
        # Idempotency: check for existing subscription from this payment
        existing = self._subscription_by_payment(payment_id)
        if existing is not None:
            return existing

        plan = self._plan(plan_id)
        if plan is None:
            raise EntitlementError(f"Plan {plan_id!r} not found")
        if not plan.active:
            raise EntitlementError(f"Plan {plan_id!r} is not active")

        sub = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id=plan_id,
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            payment_id=payment_id,
        )
        _append_ndjson(self._subs_path, sub.to_dict())
        return sub

    def list_entitlements(self, user_id: str) -> dict[str, Any]:
        """Return all entitlements for the user's current plan."""
        sub = self._active_subscription(user_id)
        if sub is None:
            return {}
        plan = self._plan(sub.plan_id)
        if plan is None:
            return {}
        return dict(plan.entitlements)

    # -- internal ------------------------------------------------------------

    def _ensure_seed_plans(self) -> None:
        """Seed built-in plans on first access."""
        existing = self._all_plans()
        existing_ids = {p.id for p in existing}
        for pid, cfg in _BUILT_IN_PLANS.items():
            if pid not in existing_ids:
                plan = Plan(
                    id=pid,
                    name=cfg["name"],
                    version=cfg["version"],
                    active=True,
                    price_minor=cfg.get("price_minor", 0),
                    currency=cfg.get("currency", "INR"),
                    entitlements=cfg["entitlements"],
                )
                _append_ndjson(self._plans_path, plan.to_dict())

    def _active_subscription(self, user_id: str) -> Subscription | None:
        """Return the **effective** subscription, or None.

        Effective means: the **most-recent** subscription (by ``created_at``)
        determines the user's state.  If that subscription is active (see
        :meth:`Subscription.is_active`) it is returned.

        This implements a **most-recent-wins** state machine: only the
        last-created subscription matters.  Cancelling, expiring, or
        suspending simply creates a new subscription row with the
        appropriate status — there is no mutation of earlier rows.
        """
        subs = self._user_subscriptions(user_id)
        if not subs:
            return None
        most_recent = subs[-1]
        if most_recent.is_active():
            return most_recent
        return None

    def _user_subscriptions(self, user_id: str) -> list[Subscription]:
        """Return all subscriptions for a user, deduped, in order."""
        all_records = _read_ndjson(self._subs_path)
        user_records = [
            r for r in all_records if r.get("user_id") == user_id
        ]
        deduped = _dedup_by_field(user_records, "id")
        subs = [
            Subscription.from_dict(r)
            for r in deduped.values()
        ]
        subs.sort(key=lambda s: s.created_at)
        return subs

    def _subscription_by_payment(self, payment_id: str) -> Subscription | None:
        """Return the subscription linked to *payment_id*, or None."""
        all_records = _read_ndjson(self._subs_path)
        for r in all_records:
            if r.get("payment_id") == payment_id:
                return Subscription.from_dict(r)
        return None

    def _all_plans(self) -> list[Plan]:
        records = _read_ndjson(self._plans_path)
        deduped = _dedup_by_field(records, "id")
        return [Plan.from_dict(r) for r in deduped.values()]

    def _plan(self, plan_id: str) -> Plan | None:
        for p in self._all_plans():
            if p.id == plan_id:
                return p
        return None
