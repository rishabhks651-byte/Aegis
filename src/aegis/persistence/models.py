"""SQLAlchemy ORM models for Aegis persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON as SqliteJson
from sqlalchemy.types import JSON

from aegis.persistence.database import Base

# Use JSON type compatible with both SQLite and PostgreSQL
JsonType = JSON().with_variant(SqliteJson, "sqlite")


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    username = Column(String(32), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(32), nullable=False, default="USER")
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    totp_secret = Column(String(512), nullable=True)
    totp_confirmed_at = Column(DateTime(timezone=True), nullable=True)
    last_used_totp_step = Column(Integer, nullable=True)
    recovery_codes = Column(JsonType, nullable=False, default=list)
    recovery_codes_generated_at = Column(DateTime(timezone=True), nullable=True)


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(String(36), primary_key=True)
    name = Column(String(64), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    metadata_json = Column("metadata", JsonType, nullable=False, default=dict)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<AgentModel id={self.id!r} name={self.name!r}>"


class PolicyModel(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    description = Column(Text, nullable=False, default="")
    rules_json = Column("rules", JsonType, nullable=False, default=list)
    priority = Column(Integer, nullable=False, default=0)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    policy_content = Column(Text, nullable=True)


class PaymentModel(Base):
    __tablename__ = "payments"

    id = Column("payment_id", String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    plan_id = Column(String(32), nullable=False)
    amount_minor = Column(Integer, nullable=False)
    currency = Column(String(8), nullable=False, default="INR")
    destination_upi = Column(String(64), nullable=False)
    submitted_utr = Column(Text, nullable=False)
    submitted_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(16), nullable=False, default="PENDING")
    verification_method = Column(String(32), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)

    __table_args__ = (
        # Index for UTR deduplication lookups
        {"sqlite_autoincrement": True},
    )


class SubscriptionModel(Base):
    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    plan_id = Column(String(32), nullable=False)
    status = Column(String(16), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=True)
    renewal = Column(Boolean, nullable=False, default=True)
    payment_id = Column(String(36), nullable=True, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


class PlanModel(Base):
    __tablename__ = "plans"

    id = Column(String(32), primary_key=True)
    name = Column(String(64), nullable=False)
    version = Column(String(16), nullable=False, default="1.0")
    active = Column(Boolean, nullable=False, default=True)
    price_minor = Column(Integer, nullable=False, default=0)
    currency = Column(String(8), nullable=False, default="INR")
    entitlements_json = Column("entitlements", JsonType, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False)


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = Column("decision_id", String(36), primary_key=True)
    audit_version = Column(String(8), nullable=False, default="1.0")
    action_id = Column(String(36), nullable=False, default="")
    agent_id = Column(String(36), nullable=False, default="")
    agent_name = Column(String(64), nullable=False, default="")
    action_type = Column(String(64), nullable=False, default="")
    params = Column(JsonType, nullable=False, default=dict)
    result = Column(String(8), nullable=False, default="")
    matched = Column(Boolean, nullable=False, default=False)
    policy_id = Column(String(64), nullable=True)
    policy_name = Column(String(128), nullable=True)
    rule_id = Column(String(64), nullable=True)
    rule_effect = Column(String(8), nullable=True)
    evaluated_at = Column(String(32), nullable=False, default="")
    reason = Column(Text, nullable=False, default="")
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    previous_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=False)

    __table_args__ = (
        # Index for chain traversal
        {"sqlite_autoincrement": True},
    )
