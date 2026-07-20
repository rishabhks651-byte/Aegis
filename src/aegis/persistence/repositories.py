"""SQLAlchemy repository implementations.

Each repository converts between ORM models and domain models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, text
from sqlalchemy.orm import Session

from aegis.auth import Session as DomainSession
from aegis.auth import User
from aegis.entitlement import Plan, Subscription, SubscriptionStatus
from aegis.models import Agent, AuditEvent
from aegis.payment import Payment, PaymentStatus, _normalize_utr
from aegis.persistence.database import get_session
from aegis.persistence.models import (
    AgentModel,
    AuditEventModel,
    PaymentModel,
    PlanModel,
    PolicyModel,
    SessionModel,
    SubscriptionModel,
    UserModel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ensure_tz(dt: Any) -> Any:
    """Ensure datetime is timezone-aware (SQLite stores naive)."""
    if isinstance(dt, datetime) and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# UserRepository
# ---------------------------------------------------------------------------


class SqlUserRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create(self, username: str, password_hash: str, role: str = "USER") -> User:
        existing = self.get_by_username(username)
        if existing is not None:
            raise ValueError(f"User {username!r} already exists")
        user_id = str(uuid.uuid4())
        model = UserModel(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role,
            active=True,
            created_at=_now(),
        )
        self._session.add(model)
        self._session.flush()
        return self._to_domain(model)

    def get_by_id(self, user_id: str) -> User | None:
        model = self._session.query(UserModel).filter(UserModel.id == user_id).first()
        return self._to_domain(model) if model else None

    def get_by_username(self, username: str) -> User | None:
        model = self._session.query(UserModel).filter(
            UserModel.username == username
        ).first()
        return self._to_domain(model) if model else None

    def list(self) -> list[User]:
        models = self._session.query(UserModel).all()
        return [self._to_domain(m) for m in models]

    def set_role(self, user_id: str, role: str) -> User:
        model = self._session.query(UserModel).filter(UserModel.id == user_id).first()
        if model is None:
            raise ValueError(f"User {user_id!r} not found")
        from aegis.rbac import AuthorizationService
        AuthorizationService.validate_role(role)
        model.role = role
        self._session.flush()
        return self._to_domain(model)

    def deactivate(self, user_id: str) -> None:
        model = self._session.query(UserModel).filter(UserModel.id == user_id).first()
        if model is None:
            raise ValueError(f"User {user_id!r} not found")
        model.active = False
        self._session.flush()

    @staticmethod
    def _to_domain(model: UserModel) -> User:
        return User(
            id=model.id,
            username=model.username,
            password_hash=model.password_hash,
            created_at=_ensure_tz(model.created_at),
            active=model.active,
            role=model.role,
        )


# ---------------------------------------------------------------------------
# SessionRepository
# ---------------------------------------------------------------------------


class SqlSessionRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create(self, user_id: str, token_hash: str,
               expires_at: Any) -> DomainSession:
        session_id = str(uuid.uuid4())
        model = SessionModel(
            id=session_id,
            token_hash=token_hash,
            user_id=user_id,
            created_at=_now(),
            expires_at=expires_at,
            revoked=False,
        )
        self._session.add(model)
        self._session.flush()
        return self._to_domain(model)

    def get_by_token_hash(self, token_hash: str) -> DomainSession | None:
        model = self._session.query(SessionModel).filter(
            SessionModel.token_hash == token_hash
        ).first()
        return self._to_domain(model) if model else None

    def get_by_id(self, session_id: str) -> DomainSession | None:
        model = self._session.query(SessionModel).filter(
            SessionModel.id == session_id
        ).first()
        return self._to_domain(model) if model else None

    def revoke(self, session_id: str) -> None:
        model = self._session.query(SessionModel).filter(
            SessionModel.id == session_id
        ).first()
        if model is None:
            raise ValueError(f"Session {session_id!r} not found")
        if model.revoked:
            raise ValueError(f"Session {session_id!r} is already revoked")
        model.revoked = True
        self._session.flush()

    @staticmethod
    def _to_domain(model: SessionModel) -> DomainSession:
        return DomainSession(
            session_id=model.id,
            token_hash=model.token_hash,
            user_id=model.user_id,
            created_at=_ensure_tz(model.created_at),
            expires_at=_ensure_tz(model.expires_at),
            revoked=model.revoked,
        )


# ---------------------------------------------------------------------------
# AgentRepository
# ---------------------------------------------------------------------------


class SqlAgentRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def create(self, user_id: str, name: str) -> Agent:
        agent_id = str(uuid.uuid4())
        model = AgentModel(
            id=agent_id,
            name=name,
            user_id=user_id,
            created_at=_now(),
            metadata_json={},
            revoked=False,
        )
        self._session.add(model)
        self._session.flush()
        return self._to_domain(model)

    def get_by_id(self, agent_id: str) -> Agent | None:
        model = self._session.query(AgentModel).filter(
            AgentModel.id == agent_id
        ).first()
        if model is None or model.revoked:
            return None
        return self._to_domain(model)

    def list_for_user(self, user_id: str) -> list[Agent]:
        models = self._session.query(AgentModel).filter(
            AgentModel.user_id == user_id
        ).all()
        return [self._to_domain(m) for m in models]

    def revoke(self, agent_id: str, user_id: str) -> Agent:
        model = self._session.query(AgentModel).filter(
            and_(AgentModel.id == agent_id, AgentModel.user_id == user_id)
        ).first()
        if model is None:
            raise ValueError(f"Agent {agent_id!r} not found")
        if model.revoked:
            return self._to_domain(model)
        model.revoked = True
        model.revoked_at = _now()
        self._session.flush()
        return self._to_domain(model)

    @staticmethod
    def _to_domain(model: AgentModel) -> Agent:
        return Agent(
            id=model.id,
            name=model.name,
            user_id=model.user_id,
            created_at=_ensure_tz(model.created_at),
            metadata=dict(model.metadata_json or {}),
            revoked=model.revoked,
            revoked_at=_ensure_tz(model.revoked_at),
        )


# ---------------------------------------------------------------------------
# PaymentRepository
# ---------------------------------------------------------------------------


class SqlPaymentRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def save(self, payment: Payment) -> None:
        model = self._to_model(payment)
        self._session.add(model)
        self._session.flush()

    def get_by_id(self, payment_id: str) -> Payment | None:
        model = self._session.query(PaymentModel).filter(
            PaymentModel.id == payment_id
        ).first()
        return self._to_domain(model) if model else None

    def get_by_utr(self, normalized_utr: str) -> Payment | None:
        all_payments = self.list_all()
        for p in all_payments:
            if _normalize_utr(p.submitted_utr) == normalized_utr:
                return p
        return None

    def list_for_user(self, user_id: str) -> list[Payment]:
        models = self._session.query(PaymentModel).filter(
            PaymentModel.user_id == user_id
        ).order_by(PaymentModel.submitted_at.desc()).all()
        return [self._to_domain(m) for m in models]

    def list_all(self) -> list[Payment]:
        models = self._session.query(PaymentModel).order_by(
            PaymentModel.submitted_at.desc()
        ).all()
        return [self._to_domain(m) for m in models]

    def overwrite(self, payment: Payment) -> None:
        existing = self._session.query(PaymentModel).filter(
            PaymentModel.id == payment.payment_id
        ).first()
        if existing:
            self._session.delete(existing)
            self._session.flush()
        self.save(payment)

    def get_by_id_for_update(self, payment_id: str) -> Payment | None:
        """Lock the row for update (concurrent safety)."""
        model = self._session.query(PaymentModel).filter(
            PaymentModel.id == payment_id
        ).with_for_update().first()
        return self._to_domain(model) if model else None

    @staticmethod
    def _to_domain(model: PaymentModel) -> Payment:
        return Payment(
            payment_id=model.id,
            user_id=model.user_id,
            plan_id=model.plan_id,
            amount_minor=model.amount_minor,
            currency=model.currency,
            destination_upi=model.destination_upi,
            submitted_utr=model.submitted_utr,
            submitted_at=_ensure_tz(model.submitted_at),
            status=PaymentStatus(model.status),
            verification_method=model.verification_method,
            verified_at=_ensure_tz(model.verified_at),
            rejection_reason=model.rejection_reason,
        )

    @staticmethod
    def _to_model(payment: Payment) -> PaymentModel:
        return PaymentModel(
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


# ---------------------------------------------------------------------------
# SubscriptionRepository
# ---------------------------------------------------------------------------


class SqlSubscriptionRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def save(self, subscription: Subscription) -> None:
        model = self._to_model(subscription)
        self._session.add(model)
        self._session.flush()

    def list_for_user(self, user_id: str) -> list[Subscription]:
        models = self._session.query(SubscriptionModel).filter(
            SubscriptionModel.user_id == user_id
        ).order_by(SubscriptionModel.created_at.asc()).all()
        return [self._to_domain(m) for m in models]

    def get_by_payment(self, payment_id: str) -> Subscription | None:
        model = self._session.query(SubscriptionModel).filter(
            SubscriptionModel.payment_id == payment_id
        ).first()
        return self._to_domain(model) if model else None

    def list_all(self) -> list[Subscription]:
        models = self._session.query(SubscriptionModel).all()
        return [self._to_domain(m) for m in models]

    @staticmethod
    def _to_domain(model: SubscriptionModel) -> Subscription:
        return Subscription(
            id=model.id,
            user_id=model.user_id,
            plan_id=model.plan_id,
            status=SubscriptionStatus(model.status),
            start_time=_ensure_tz(model.start_time),
            end_time=_ensure_tz(model.end_time),
            renewal=model.renewal,
            payment_id=model.payment_id,
            created_at=_ensure_tz(model.created_at),
        )

    @staticmethod
    def _to_model(subscription: Subscription) -> SubscriptionModel:
        return SubscriptionModel(
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


# ---------------------------------------------------------------------------
# PlanRepository
# ---------------------------------------------------------------------------


class SqlPlanRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def save(self, plan: Plan) -> None:
        model = self._to_model(plan)
        existing = self._session.query(PlanModel).filter(
            PlanModel.id == plan.id
        ).first()
        if existing:
            self._session.delete(existing)
            self._session.flush()
        self._session.add(model)
        self._session.flush()

    def get_by_id(self, plan_id: str) -> Plan | None:
        model = self._session.query(PlanModel).filter(
            PlanModel.id == plan_id
        ).first()
        return self._to_domain(model) if model else None

    def list_active(self) -> list[Plan]:
        models = self._session.query(PlanModel).filter(
            PlanModel.active.is_(True)
        ).all()
        return [self._to_domain(m) for m in models]

    def list_all(self) -> list[Plan]:
        models = self._session.query(PlanModel).all()
        return [self._to_domain(m) for m in models]

    @staticmethod
    def _to_domain(model: PlanModel) -> Plan:
        return Plan(
            id=model.id,
            name=model.name,
            version=int(model.version) if model.version else 1,
            active=model.active,
            price_minor=model.price_minor,
            currency=model.currency,
            entitlements=dict(model.entitlements_json or {}),
            created_at=_ensure_tz(model.created_at),
        )

    @staticmethod
    def _to_model(plan: Plan) -> PlanModel:
        return PlanModel(
            id=plan.id,
            name=plan.name,
            version=plan.version,
            active=plan.active,
            price_minor=plan.price_minor,
            currency=plan.currency,
            entitlements_json=dict(plan.entitlements),
            created_at=plan.created_at,
        )


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------


class SqlAuditRepository:
    def __init__(self, session: Session | None = None) -> None:
        self._session = session or get_session()

    def append(self, event: AuditEvent) -> AuditEvent:
        from aegis.audit import compute_hash

        previous = self.last_hash(event.user_id)
        event_hash = compute_hash(event, previous)

        chained = AuditEvent.from_dict({
            **event.to_dict(),
            "previous_hash": previous,
            "hash": event_hash,
        })

        model = self._to_model(chained)
        self._session.add(model)
        self._session.flush()
        return chained

    def list(self, user_id: str) -> list[AuditEvent]:
        models = self._session.query(AuditEventModel).filter(
            AuditEventModel.user_id == user_id
        ).order_by(AuditEventModel.evaluated_at.asc()).all()
        return [self._to_domain(m) for m in models]

    def get(self, event_id: str, user_id: str) -> AuditEvent | None:
        model = self._session.query(AuditEventModel).filter(
            and_(
                AuditEventModel.id == event_id,
                AuditEventModel.user_id == user_id,
            )
        ).first()
        return self._to_domain(model) if model else None

    def verify(self, user_id: str) -> list[dict[str, Any]]:
        from aegis.audit import compute_hash

        events = self.list(user_id)
        if not events:
            return [{"index": 0, "decision_id": "", "valid": True,
                     "error": "Empty log — no integrity data to verify"}]

        results: list[dict[str, Any]] = []
        for i, event in enumerate(events):
            expected_prev = events[i - 1].hash if i > 0 else None
            expected_hash = compute_hash(event, expected_prev)

            if event.previous_hash != expected_prev:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": False,
                    "error": f"previous_hash mismatch: got {event.previous_hash!r}, "
                             f"expected {expected_prev!r}",
                })
            elif event.hash != expected_hash:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": False,
                    "error": f"hash mismatch: got {event.hash!r}, "
                             f"expected {expected_hash!r}",
                })
            else:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": True,
                    "error": None,
                })
        return results

    def last_hash(self, user_id: str) -> str | None:
        model = self._session.query(AuditEventModel).filter(
            AuditEventModel.user_id == user_id
        ).order_by(AuditEventModel.evaluated_at.desc()).first()
        return model.hash if model else None

    @staticmethod
    def _to_domain(model: AuditEventModel) -> AuditEvent:
        ev = model.evaluated_at
        if isinstance(ev, datetime):
            evaluated_at = ev.isoformat()
        else:
            evaluated_at = str(ev) if ev else ""
        return AuditEvent(
            audit_version=str(model.audit_version),
            decision_id=model.id,
            action_id=model.action_id,
            agent_id=model.agent_id,
            agent_name=model.agent_name,
            action_type=model.action_type,
            params=dict(model.params or {}),
            result=model.result,
            matched=model.matched,
            policy_id=model.policy_id,
            policy_name=model.policy_name,
            rule_id=model.rule_id,
            rule_effect=model.rule_effect,
            evaluated_at=evaluated_at,
            reason=model.reason,
            user_id=model.user_id,
            previous_hash=model.previous_hash,
            hash=model.hash,
        )

    @staticmethod
    def _to_model(event: AuditEvent) -> AuditEventModel:
        return AuditEventModel(
            id=event.decision_id,
            audit_version=str(event.audit_version),
            action_id=event.action_id,
            agent_id=event.agent_id,
            agent_name=event.agent_name,
            action_type=event.action_type,
            params=dict(event.params),
            result=event.result,
            matched=event.matched,
            policy_id=event.policy_id,
            policy_name=event.policy_name,
            rule_id=event.rule_id,
            rule_effect=event.rule_effect,
            evaluated_at=str(event.evaluated_at) if event.evaluated_at else "",
            reason=event.reason,
            user_id=event.user_id,
            previous_hash=event.previous_hash,
            hash=event.hash,
        )
