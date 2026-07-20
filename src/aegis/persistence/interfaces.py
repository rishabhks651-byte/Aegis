"""Repository interfaces (ABCs) for all domain entities.

All repositories work with domain models (not ORM rows).
Implementations may be NDJSON-backed or SQL-backed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from aegis.auth import Session, User
from aegis.entitlement import Plan, Subscription
from aegis.models import Agent, AuditEvent
from aegis.payment import Payment


# ---------------------------------------------------------------------------
# UserRepository
# ---------------------------------------------------------------------------


class UserRepository(ABC):
    @abstractmethod
    def create(self, username: str, password_hash: str, role: str = "USER") -> User:
        ...

    @abstractmethod
    def get_by_id(self, user_id: str) -> User | None:
        ...

    @abstractmethod
    def get_by_username(self, username: str) -> User | None:
        ...

    @abstractmethod
    def list(self) -> list[User]:
        ...

    @abstractmethod
    def set_role(self, user_id: str, role: str) -> User:
        ...

    @abstractmethod
    def deactivate(self, user_id: str) -> None:
        ...


# ---------------------------------------------------------------------------
# SessionRepository
# ---------------------------------------------------------------------------


class SessionRepository(ABC):
    @abstractmethod
    def create(self, user_id: str, token_hash: str,
               expires_at: Any) -> Session:
        ...

    @abstractmethod
    def get_by_token_hash(self, token_hash: str) -> Session | None:
        ...

    @abstractmethod
    def get_by_id(self, session_id: str) -> Session | None:
        ...

    @abstractmethod
    def revoke(self, session_id: str) -> None:
        ...


# ---------------------------------------------------------------------------
# AgentRepository
# ---------------------------------------------------------------------------


class AgentRepository(ABC):
    @abstractmethod
    def create(self, user_id: str, name: str) -> Agent:
        ...

    @abstractmethod
    def get_by_id(self, agent_id: str) -> Agent | None:
        ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[Agent]:
        ...

    @abstractmethod
    def revoke(self, agent_id: str, user_id: str) -> Agent:
        ...


# ---------------------------------------------------------------------------
# PolicyRepository
# ---------------------------------------------------------------------------


class PolicyRepository(ABC):
    @abstractmethod
    def save(self, policy: Any) -> None:
        ...

    @abstractmethod
    def get_by_id(self, policy_id: str, user_id: str) -> Any | None:
        ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[Any]:
        ...


# ---------------------------------------------------------------------------
# PaymentRepository
# ---------------------------------------------------------------------------


class PaymentRepository(ABC):
    @abstractmethod
    def save(self, payment: Payment) -> None:
        ...

    @abstractmethod
    def get_by_id(self, payment_id: str) -> Payment | None:
        ...

    @abstractmethod
    def get_by_utr(self, normalized_utr: str) -> Payment | None:
        ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[Payment]:
        ...

    @abstractmethod
    def list_all(self) -> list[Payment]:
        ...

    @abstractmethod
    def overwrite(self, payment: Payment) -> None:
        ...


# ---------------------------------------------------------------------------
# SubscriptionRepository
# ---------------------------------------------------------------------------


class SubscriptionRepository(ABC):
    @abstractmethod
    def save(self, subscription: Subscription) -> None:
        ...

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[Subscription]:
        ...

    @abstractmethod
    def get_by_payment(self, payment_id: str) -> Subscription | None:
        ...

    @abstractmethod
    def list_all(self) -> list[Subscription]:
        ...


# ---------------------------------------------------------------------------
# PlanRepository
# ---------------------------------------------------------------------------


class PlanRepository(ABC):
    @abstractmethod
    def save(self, plan: Plan) -> None:
        ...

    @abstractmethod
    def get_by_id(self, plan_id: str) -> Plan | None:
        ...

    @abstractmethod
    def list_active(self) -> list[Plan]:
        ...

    @abstractmethod
    def list_all(self) -> list[Plan]:
        ...


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------


class AuditRepository(ABC):
    @abstractmethod
    def append(self, event: AuditEvent) -> AuditEvent:
        ...

    @abstractmethod
    def list(self, user_id: str) -> list[AuditEvent]:
        ...

    @abstractmethod
    def get(self, event_id: str, user_id: str) -> AuditEvent | None:
        ...

    @abstractmethod
    def verify(self, user_id: str) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def last_hash(self, user_id: str) -> str | None:
        ...
