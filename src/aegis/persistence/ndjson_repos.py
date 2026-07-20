"""NDJSON-backed repository implementations (LegacyFilePersistence).

Wraps the existing NDJSON-based storage code into the repository interface.
Useful for development, offline CLI usage, migration source, and backward
compatibility.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.auth import (
    Session as DomainSession,
    User,
    UserStore,
    hash_password,
    _append_ndjson,
    _dedup_by_field,
    _read_ndjson,
)
from aegis.entitlement import (
    Plan,
    Subscription,
    _append_ndjson as _append_sub,
    _dedup_by_field as _dedup_sub,
    _read_ndjson as _read_sub,
)
from aegis.models import Agent, AuditEvent
from aegis.payment import (
    Payment,
    _append_ndjson as _append_pay,
    _dedup_by_field as _dedup_pay,
    _normalize_utr,
    _read_ndjson as _read_pay,
)
from aegis.persistence.interfaces import (
    AgentRepository,
    AuditRepository,
    PaymentRepository,
    PlanRepository,
    SessionRepository,
    SubscriptionRepository,
    UserRepository,
)


class NdjsonUserRepository(UserRepository):
    """Legacy NDJSON-backed user repository."""

    def __init__(self, data_dir: str) -> None:
        self._store = UserStore(data_dir)
        self._path = self._store._path

    def create(self, username: str, password_hash: str, role: str = "USER") -> User:
        pwh = password_hash if password_hash else hash_password("temp")
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=pwh,
            created_at=datetime.now(timezone.utc),
            active=True,
            role=role,
        )
        _append_ndjson(self._path, user.to_dict())
        return user

    def get_by_id(self, user_id: str) -> User | None:
        return self._store.get_by_id(user_id)

    def get_by_username(self, username: str) -> User | None:
        return self._store.get_by_username(username)

    def list(self) -> list[User]:
        records = _read_ndjson(self._path)
        deduped = _dedup_by_field(records, "id")
        return [User.from_dict(r) for r in deduped.values()]

    def set_role(self, user_id: str, role: str) -> User:
        return self._store.set_role(user_id, role)

    def deactivate(self, user_id: str) -> None:
        self._store.deactivate(user_id)


class NdjsonSessionRepository(SessionRepository):
    """Legacy NDJSON-backed session repository."""

    def __init__(self, data_dir: str) -> None:
        from aegis.auth import SessionStore
        self._store = SessionStore(data_dir)
        self._path = self._store._path

    def create(self, user_id: str, token_hash: str,
               expires_at: Any) -> DomainSession:
        from aegis.auth import create_session_token
        session_id = str(uuid.uuid4())
        session = DomainSession(
            session_id=session_id,
            token_hash=token_hash,
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        _append_ndjson(self._path, session.to_dict())
        return session

    def get_by_token_hash(self, token_hash: str) -> DomainSession | None:
        for r in self._store._list_raw():
            if r["token_hash"] == token_hash:
                return DomainSession.from_dict(r)
        return None

    def get_by_id(self, session_id: str) -> DomainSession | None:
        return self._store.get_by_id(session_id)

    def revoke(self, session_id: str) -> None:
        self._store.revoke(session_id)


class NdjsonAgentRepository(AgentRepository):
    """Legacy NDJSON-backed agent repository."""

    def __init__(self, data_dir: str) -> None:
        from aegis.registry import AgentRegistry
        self._registry = AgentRegistry(data_dir)
        self._path = self._registry._path

    def create(self, user_id: str, name: str) -> Agent:
        return self._registry.create(user_id, name)

    def get_by_id(self, agent_id: str) -> Agent | None:
        return self._registry.get_by_id(agent_id)

    def list_for_user(self, user_id: str) -> list[Agent]:
        return self._registry.list_for_user(user_id)

    def revoke(self, agent_id: str, user_id: str) -> Agent:
        return self._registry.revoke(agent_id, user_id)


class NdjsonPaymentRepository(PaymentRepository):
    """Legacy NDJSON-backed payment repository."""

    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "payments.ndjson")

    def save(self, payment: Payment) -> None:
        _append_pay(self._path, payment.to_dict())

    def get_by_id(self, payment_id: str) -> Payment | None:
        records = _read_pay(self._path)
        for r in records:
            if r.get("payment_id") == payment_id:
                return Payment.from_dict(r)
        return None

    def get_by_utr(self, normalized_utr: str) -> Payment | None:
        records = _read_pay(self._path)
        for r in records:
            payment = Payment.from_dict(r)
            if _normalize_utr(payment.submitted_utr) == normalized_utr:
                return payment
        return None

    def list_for_user(self, user_id: str) -> list[Payment]:
        records = _read_pay(self._path)
        user_records = [r for r in records if r.get("user_id") == user_id]
        deduped = _dedup_pay(user_records, "payment_id")
        payments = [Payment.from_dict(r) for r in deduped.values()]
        payments.sort(key=lambda p: p.submitted_at, reverse=True)
        return payments

    def list_all(self) -> list[Payment]:
        records = _read_pay(self._path)
        deduped = _dedup_pay(records, "payment_id")
        payments = [Payment.from_dict(r) for r in deduped.values()]
        payments.sort(key=lambda p: p.submitted_at, reverse=True)
        return payments

    def overwrite(self, payment: Payment) -> None:
        records = _read_pay(self._path)
        filtered = [r for r in records if r.get("payment_id") != payment.payment_id]
        filtered.append(payment.to_dict())
        if os.path.exists(self._path):
            os.remove(self._path)
        for r in filtered:
            _append_pay(self._path, r)


class NdjsonSubscriptionRepository(SubscriptionRepository):
    """Legacy NDJSON-backed subscription repository."""

    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "subscriptions.ndjson")

    def save(self, subscription: Subscription) -> None:
        _append_sub(self._path, subscription.to_dict())

    def list_for_user(self, user_id: str) -> list[Subscription]:
        records = _read_sub(self._path)
        user_records = [r for r in records if r.get("user_id") == user_id]
        deduped = _dedup_sub(user_records, "id")
        subs = [Subscription.from_dict(r) for r in deduped.values()]
        subs.sort(key=lambda s: s.created_at)
        return subs

    def get_by_payment(self, payment_id: str) -> Subscription | None:
        records = _read_sub(self._path)
        for r in records:
            if r.get("payment_id") == payment_id:
                return Subscription.from_dict(r)
        return None

    def list_all(self) -> list[Subscription]:
        records = _read_sub(self._path)
        deduped = _dedup_sub(records, "id")
        return [Subscription.from_dict(r) for r in deduped.values()]


class NdjsonPlanRepository(PlanRepository):
    """Legacy NDJSON-backed plan repository."""

    def __init__(self, data_dir: str) -> None:
        from aegis.entitlement import EntitlementService
        self._svc = EntitlementService(data_dir)
        self._path = os.path.join(data_dir, "plans.ndjson")

    def save(self, plan: Plan) -> None:
        from aegis.entitlement import _append_ndjson as _append_plan
        _append_plan(self._path, plan.to_dict())

    def get_by_id(self, plan_id: str) -> Plan | None:
        return self._svc.get_plan(plan_id)

    def list_active(self) -> list[Plan]:
        return self._svc.list_plans()

    def list_all(self) -> list[Plan]:
        from aegis.entitlement import _read_ndjson as _read_plan
        from aegis.entitlement import _dedup_by_field as _dedup_plan
        records = _read_plan(self._path)
        deduped = _dedup_plan(records, "id")
        return [Plan.from_dict(r) for r in deduped.values()]


class NdjsonAuditRepository(AuditRepository):
    """Legacy NDJSON-backed audit repository."""

    def __init__(self, data_dir: str) -> None:
        from aegis.audit import AuditStore
        self._store = AuditStore(data_dir)

    def append(self, event: AuditEvent) -> AuditEvent:
        return self._store.append(event)

    def list(self, user_id: str) -> list[AuditEvent]:
        return self._store.list(user_id)

    def get(self, event_id: str, user_id: str) -> AuditEvent | None:
        try:
            return self._store.get(event_id, user_id)
        except ValueError:
            return None

    def verify(self, user_id: str) -> list[dict[str, Any]]:
        return self._store.verify(user_id)

    def last_hash(self, user_id: str) -> str | None:
        return self._store._last_hash(user_id)
