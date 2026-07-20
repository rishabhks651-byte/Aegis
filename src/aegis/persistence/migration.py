"""NDJSON → Relational Database Migration.

Deterministic, idempotent, auditable migration from the file-based
NDJSON store to a SQLAlchemy-backed relational database.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aegis.auth import User, _dedup_by_field as _dedup_user, _read_ndjson
from aegis.entitlement import Plan, Subscription
from aegis.entitlement import _dedup_by_field as _dedup_sub
from aegis.entitlement import _read_ndjson as _read_sub
from aegis.models import Agent, AuditEvent
from aegis.payment import Payment
from aegis.payment import _dedup_by_field as _dedup_payment
from aegis.payment import _read_ndjson as _read_payment
from aegis.persistence.database import session_scope
from aegis.persistence.models import (
    AgentModel,
    AuditEventModel,
    Base,
    PaymentModel,
    PlanModel,
    SessionModel,
    SubscriptionModel,
    UserModel,
)
from aegis.persistence.repositories import (
    SqlAgentRepository,
    SqlAuditRepository,
    SqlPaymentRepository,
    SqlPlanRepository,
    SqlSessionRepository,
    SqlSubscriptionRepository,
    SqlUserRepository,
)


@dataclass
class MigrationResult:
    """Result of a single migration run."""

    users: int = 0
    sessions: int = 0
    agents: int = 0
    payments: int = 0
    subscriptions: int = 0
    plans: int = 0
    audit_events: int = 0
    elapsed_seconds: float = 0.0

    @property
    def total(self) -> int:
        return (self.users + self.sessions + self.agents + self.payments
                + self.subscriptions + self.plans + self.audit_events)

    def summary(self) -> str:
        return (
            f"Migrated {self.total} records "
            f"({self.users} users, {self.sessions} sessions, "
            f"{self.agents} agents, {self.payments} payments, "
            f"{self.subscriptions} subscriptions, {self.plans} plans, "
            f"{self.audit_events} audit events) "
            f"in {self.elapsed_seconds:.2f}s"
        )


def migrate(data_dir: str, rebuild: bool = False) -> MigrationResult:
    """Migrate all NDJSON data from *data_dir* into the configured database.

    Args:
        data_dir: Path to the NDJSON data directory.
        rebuild: If True, drop and recreate all tables before migration.

    Returns:
        A MigrationResult with per-entity counts.
    """
    import time

    start = time.perf_counter()

    if rebuild:
        from aegis.persistence.database import rebuild_db
        rebuild_db()

    with session_scope() as session:
        result = MigrationResult()

        # 1. Users
        user_path = os.path.join(data_dir, "users.ndjson")
        if os.path.exists(user_path):
            records = _read_ndjson(user_path)
            deduped = _dedup_user(records, "id")
            user_repo = SqlUserRepository(session)
            for uid, record in deduped.items():
                existing = user_repo.get_by_id(uid)
                if not existing:
                    user = User.from_dict(record)
                    model = UserModel(
                        id=user.id,
                        username=user.username,
                        password_hash=user.password_hash,
                        role=user.role,
                        active=user.active,
                        created_at=user.created_at,
                    )
                    session.add(model)
                    result.users += 1

        # 2. Sessions
        session_path = os.path.join(data_dir, "sessions.ndjson")
        if os.path.exists(session_path):
            records = _read_ndjson(session_path)
            for record in records:
                existing = session.query(SessionModel).filter(
                    SessionModel.id == record.get("session_id")
                ).first()
                if not existing:
                    model = SessionModel(
                        id=record.get("session_id", ""),
                        token_hash=record.get("token_hash", ""),
                        user_id=record.get("user_id", ""),
                        created_at=_parse_dt(record.get("created_at")),
                        expires_at=_parse_dt(record.get("expires_at")),
                        revoked=record.get("revoked", False),
                    )
                    session.add(model)
                    result.sessions += 1

        # 3. Agents
        agent_path = os.path.join(data_dir, "agents.ndjson")
        if os.path.exists(agent_path):
            records = _read_ndjson(agent_path)
            for record in records:
                existing = session.query(AgentModel).filter(
                    AgentModel.id == record.get("id")
                ).first()
                if not existing:
                    model = AgentModel(
                        id=record.get("id", ""),
                        name=record.get("name", ""),
                        user_id=record.get("user_id", ""),
                        created_at=_parse_dt(record.get("created_at")),
                        metadata_json=record.get("metadata", {}),
                        revoked=record.get("revoked", False),
                        revoked_at=_parse_dt(record.get("revoked_at")),
                    )
                    session.add(model)
                    result.agents += 1

        # 4. Payments
        payment_path = os.path.join(data_dir, "payments.ndjson")
        if os.path.exists(payment_path):
            records = _read_payment(payment_path)
            deduped = _dedup_payment(records, "payment_id")
            for pid, record in deduped.items():
                existing = session.query(PaymentModel).filter(
                    PaymentModel.id == pid
                ).first()
                if not existing:
                    payment = Payment.from_dict(record)
                    model = PaymentModel(
                        id=payment.payment_id,
                        user_id=payment.user_id,
                        plan_id=payment.plan_id,
                        amount_minor=payment.amount_minor,
                        currency=payment.currency,
                        destination_upi=payment.destination_upi,
                        submitted_utr=payment.submitted_utr,
                        submitted_at=payment.submitted_at,
                        status=payment.status.value,
                        verification_method=payment.verification_method,
                        verified_at=payment.verified_at,
                        rejection_reason=payment.rejection_reason,
                    )
                    session.add(model)
                    result.payments += 1

        # 5. Subscriptions
        sub_path = os.path.join(data_dir, "subscriptions.ndjson")
        if os.path.exists(sub_path):
            records = _read_sub(sub_path)
            deduped = _dedup_sub(records, "id")
            for sid, record in deduped.items():
                existing = session.query(SubscriptionModel).filter(
                    SubscriptionModel.id == sid
                ).first()
                if not existing:
                    subscription = Subscription.from_dict(record)
                    model = SubscriptionModel(
                        id=subscription.id,
                        user_id=subscription.user_id,
                        plan_id=subscription.plan_id,
                        status=subscription.status.value,
                        start_time=subscription.start_time,
                        end_time=subscription.end_time,
                        renewal=subscription.renewal,
                        payment_id=subscription.payment_id,
                        created_at=subscription.created_at,
                    )
                    session.add(model)
                    result.subscriptions += 1

        # 6. Plans
        plan_path = os.path.join(data_dir, "plans.ndjson")
        if os.path.exists(plan_path):
            records = _read_ndjson(plan_path)
            seen: set[str] = set()
            for record in records:
                pid = record.get("id", "")
                if pid in seen:
                    continue
                seen.add(pid)
                existing = session.query(PlanModel).filter(
                    PlanModel.id == pid
                ).first()
                if not existing:
                    plan = Plan.from_dict(record)
                    model = PlanModel(
                        id=plan.id,
                        name=plan.name,
                        version=plan.version,
                        active=plan.active,
                        price_minor=plan.price_minor,
                        currency=plan.currency,
                        entitlements_json=dict(plan.entitlements),
                        created_at=plan.created_at,
                    )
                    session.add(model)
                    result.plans += 1

        # 7. Audit events
        audit_path = os.path.join(data_dir, "audit.ndjson")
        if os.path.exists(audit_path):
            records = _read_ndjson(audit_path)
            for record in records:
                existing = session.query(AuditEventModel).filter(
                    AuditEventModel.id == record.get("decision_id")
                ).first()
                if not existing:
                    model = AuditEventModel(
                        id=record.get("decision_id", ""),
                        audit_version=record.get("audit_version", 1),
                        action_id=record.get("action_id", ""),
                        agent_id=record.get("agent_id", ""),
                        agent_name=record.get("agent_name", ""),
                        action_type=record.get("action_type", ""),
                        params=record.get("params", {}),
                        result=record.get("result", ""),
                        matched=record.get("matched", False),
                        policy_id=record.get("policy_id", ""),
                        policy_name=record.get("policy_name", ""),
                        rule_id=record.get("rule_id", ""),
                        rule_effect=record.get("rule_effect", ""),
                        evaluated_at=_parse_dt(record.get("evaluated_at")),
                        reason=record.get("reason", ""),
                        user_id=record.get("user_id", ""),
                        previous_hash=record.get("previous_hash"),
                        hash=record.get("hash", ""),
                    )
                    session.add(model)
                    result.audit_events += 1

    result.elapsed_seconds = time.perf_counter() - start
    return result


def verify_migration(data_dir: str) -> dict[str, int]:
    """Compare record counts between NDJSON source and database.

    Returns a dict of ``{entity: {"ndjson": N, "db": M}}``.
    """
    from aegis.persistence.database import get_session

    counts: dict[str, dict[str, int]] = {}

    # Count NDJSON
    ndjson_files = {
        "users": ("users.ndjson", _read_ndjson, _dedup_user, "id"),
        "sessions": ("sessions.ndjson", _read_ndjson, None, None),
        "agents": ("agents.ndjson", _read_ndjson, None, None),
        "payments": ("payments.ndjson", _read_payment, _dedup_payment, "payment_id"),
        "subscriptions": ("subscriptions.ndjson", _read_sub, _dedup_sub, "id"),
        "plans": ("plans.ndjson", _read_ndjson, None, None),
        "audit": ("audit.ndjson", _read_ndjson, None, None),
    }

    for entity, (filename, reader, deduper, field) in ndjson_files.items():
        filepath = os.path.join(data_dir, filename)
        if os.path.exists(filepath):
            records = reader(filepath)
            if deduper and field:
                recs = deduper(records, field)
                ndjson_count = len(recs)
            else:
                ndjson_count = len(records)
        else:
            ndjson_count = 0
        counts[entity] = {"ndjson": ndjson_count, "db": 0}

    # Count DB
    with session_scope() as session:
        counts["users"]["db"] = session.query(UserModel).count()
        counts["sessions"]["db"] = session.query(SessionModel).count()
        counts["agents"]["db"] = session.query(AgentModel).count()
        counts["payments"]["db"] = session.query(PaymentModel).count()
        counts["subscriptions"]["db"] = session.query(SubscriptionModel).count()
        counts["plans"]["db"] = session.query(PlanModel).count()
        counts["audit"]["db"] = session.query(AuditEventModel).count()

    return counts


def _parse_dt(val: Any) -> datetime | None:
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        dt = datetime.fromisoformat(str(val))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
