"""Tests for the persistence layer (database, ORM, repositories, migration)."""

from __future__ import annotations

import os
import tempfile
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from sqlalchemy import text


# ---------------------------------------------------------------------------
# Module-level setup — force file-based SQLite shared across connections
# ---------------------------------------------------------------------------

_TEST_DB_PATH = os.path.join(tempfile.gettempdir(), f"aegis_test_{os.getpid()}.db")

os.environ["AEGIS_STORAGE_BACKEND"] = "database"
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"

# Now it's safe to import persistence modules
from aegis.persistence.database import rebuild_db, init_db
from aegis.persistence.models import Base  # noqa: F401 — ensure ORM models loaded


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_db():
    """Ensure each test starts with a clean database."""
    init_db()
    yield
    rebuild_db()


@pytest.fixture
def session():
    from aegis.persistence.database import get_session
    s = get_session()
    yield s
    s.close()


@pytest.fixture
def user_repo(session):
    from aegis.persistence.repositories import SqlUserRepository
    return SqlUserRepository(session)


@pytest.fixture
def session_repo(session):
    from aegis.persistence.repositories import SqlSessionRepository
    return SqlSessionRepository(session)


@pytest.fixture
def agent_repo(session):
    from aegis.persistence.repositories import SqlAgentRepository
    return SqlAgentRepository(session)


@pytest.fixture
def payment_repo(session):
    from aegis.persistence.repositories import SqlPaymentRepository
    return SqlPaymentRepository(session)


@pytest.fixture
def sub_repo(session):
    from aegis.persistence.repositories import SqlSubscriptionRepository
    return SqlSubscriptionRepository(session)


@pytest.fixture
def plan_repo(session):
    from aegis.persistence.repositories import SqlPlanRepository
    return SqlPlanRepository(session)


@pytest.fixture
def audit_repo(session):
    from aegis.persistence.repositories import SqlAuditRepository
    return SqlAuditRepository(session)


# ---------------------------------------------------------------------------
# Schema & Initialisation
# ---------------------------------------------------------------------------


class TestDatabaseInit:
    def test_init_db_creates_tables(self):
        from aegis.persistence.database import get_engine, Base
        from aegis.persistence import models  # noqa: F401 — load ORM models
        _ = models
        engine = get_engine()
        tables = Base.metadata.tables.keys()
        assert "users" in tables
        assert "sessions" in tables
        assert "agents" in tables
        assert "policies" in tables
        assert "payments" in tables
        assert "subscriptions" in tables
        assert "plans" in tables
        assert "audit_events" in tables

    def test_rebuild_db_drops_and_recreates(self, session):
        from aegis.persistence.database import rebuild_db
        from aegis.persistence.models import UserModel
        session.add(UserModel(id="u1", username="test", password_hash="pw",
                              role="USER", active=True, created_at=datetime.now(timezone.utc)))
        session.commit()
        assert session.query(UserModel).count() == 1
        rebuild_db()
        assert session.query(UserModel).count() == 0

    def test_session_scope_commits(self):
        from aegis.persistence.database import session_scope
        from aegis.persistence.models import UserModel
        with session_scope() as s:
            s.add(UserModel(id="u2", username="scope_test", password_hash="pw",
                            role="USER", active=True, created_at=datetime.now(timezone.utc)))
        from aegis.persistence.database import get_session
        assert get_session().query(UserModel).filter(UserModel.id == "u2").count() == 1

    def test_session_scope_rollback_on_error(self):
        from aegis.persistence.database import session_scope
        from aegis.persistence.models import UserModel
        try:
            with session_scope() as s:
                s.add(UserModel(id="u3", username="rollback_test", password_hash="pw",
                                role="USER", active=True, created_at=datetime.now(timezone.utc)))
                raise ValueError("force rollback")
        except ValueError:
            pass
        from aegis.persistence.database import get_session
        assert get_session().query(UserModel).filter(UserModel.id == "u3").count() == 0


# ---------------------------------------------------------------------------
# UserRepository
# ---------------------------------------------------------------------------


class TestSqlUserRepository:
    def test_create_and_get_by_id(self, user_repo):
        user = user_repo.create("alice", "hash1")
        loaded = user_repo.get_by_id(user.id)
        assert loaded is not None
        assert loaded.username == "alice"
        assert loaded.password_hash == "hash1"
        assert loaded.role == "USER"
        assert loaded.active is True

    def test_create_duplicate_username_raises(self, user_repo):
        user_repo.create("bob", "hash1")
        with pytest.raises(ValueError, match="already exists"):
            user_repo.create("bob", "hash2")

    def test_get_by_username(self, user_repo):
        user = user_repo.create("charlie", "hash1")
        loaded = user_repo.get_by_username("charlie")
        assert loaded is not None
        assert loaded.id == user.id

    def test_get_by_username_nonexistent(self, user_repo):
        assert user_repo.get_by_username("nobody") is None

    def test_list(self, user_repo):
        user_repo.create("a", "h1")
        user_repo.create("b", "h2")
        users = user_repo.list()
        assert len(users) == 2

    def test_set_role(self, user_repo):
        user = user_repo.create("dave", "hash1")
        updated = user_repo.set_role(user.id, "ADMIN")
        assert updated.role == "ADMIN"

    def test_set_role_invalid_raises(self, user_repo):
        user = user_repo.create("eve", "hash1")
        with pytest.raises(ValueError):
            user_repo.set_role(user.id, "NONEXISTENT")

    def test_deactivate(self, user_repo):
        user = user_repo.create("frank", "hash1")
        user_repo.deactivate(user.id)
        loaded = user_repo.get_by_id(user.id)
        assert loaded is not None
        assert loaded.active is False

    def test_deactivate_nonexistent_raises(self, user_repo):
        with pytest.raises(ValueError, match="not found"):
            user_repo.deactivate("no-such-user")


# ---------------------------------------------------------------------------
# SessionRepository
# ---------------------------------------------------------------------------


class TestSqlSessionRepository:
    def test_create_and_get_by_token_hash(self, session_repo, user_repo):
        user = user_repo.create("session_user", "hash1")
        sess = session_repo.create(user.id, "token_hash_abc", datetime.now(timezone.utc))
        loaded = session_repo.get_by_token_hash("token_hash_abc")
        assert loaded is not None
        assert loaded.user_id == user.id
        assert loaded.revoked is False

    def test_get_by_id(self, session_repo, user_repo):
        user = user_repo.create("session_user2", "hash1")
        sess = session_repo.create(user.id, "tok2", datetime.now(timezone.utc))
        loaded = session_repo.get_by_id(sess.session_id)
        assert loaded is not None

    def test_revoke(self, session_repo, user_repo):
        user = user_repo.create("session_user3", "hash1")
        sess = session_repo.create(user.id, "tok3", datetime.now(timezone.utc))
        session_repo.revoke(sess.session_id)
        loaded = session_repo.get_by_id(sess.session_id)
        assert loaded.revoked is True

    def test_revoke_twice_raises(self, session_repo, user_repo):
        user = user_repo.create("session_user4", "hash1")
        sess = session_repo.create(user.id, "tok4", datetime.now(timezone.utc))
        session_repo.revoke(sess.session_id)
        with pytest.raises(ValueError, match="already revoked"):
            session_repo.revoke(sess.session_id)


# ---------------------------------------------------------------------------
# AgentRepository
# ---------------------------------------------------------------------------


class TestSqlAgentRepository:
    def test_create_and_get(self, agent_repo, user_repo):
        user = user_repo.create("agent_user", "hash1")
        agent = agent_repo.create(user.id, "TestAgent")
        loaded = agent_repo.get_by_id(agent.id)
        assert loaded is not None
        assert loaded.name == "TestAgent"
        assert loaded.user_id == user.id
        assert loaded.revoked is False

    def test_get_revoked_returns_none(self, agent_repo, user_repo):
        user = user_repo.create("agent_user2", "hash1")
        agent = agent_repo.create(user.id, "RevocableAgent")
        agent_repo.revoke(agent.id, user.id)
        loaded = agent_repo.get_by_id(agent.id)
        assert loaded is None

    def test_list_for_user(self, agent_repo, user_repo):
        user = user_repo.create("agent_user3", "hash1")
        agent_repo.create(user.id, "A1")
        agent_repo.create(user.id, "A2")
        agents = agent_repo.list_for_user(user.id)
        assert len(agents) == 2

    def test_revoke(self, agent_repo, user_repo):
        user = user_repo.create("agent_user4", "hash1")
        agent = agent_repo.create(user.id, "ToRevoke")
        revoked = agent_repo.revoke(agent.id, user.id)
        assert revoked.revoked is True
        assert revoked.revoked_at is not None


# ---------------------------------------------------------------------------
# PaymentRepository
# ---------------------------------------------------------------------------


class TestSqlPaymentRepository:
    def test_save_and_get(self, payment_repo, user_repo, plan_repo):
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("pay_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        payment = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=user.id,
            plan_id="pro",
            amount_minor=999,
            currency="INR",
            destination_upi="pay@aegis",
            submitted_utr="UTR123",
            submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        loaded = payment_repo.get_by_id(payment.payment_id)
        assert loaded is not None
        assert loaded.status == PaymentStatus.PENDING
        assert loaded.submitted_utr == "UTR123"

    def test_get_by_utr(self, payment_repo, user_repo, plan_repo):
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("pay_user2", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        payment = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=user.id,
            plan_id="pro",
            amount_minor=999,
            currency="INR",
            destination_upi="pay@aegis",
            submitted_utr="UTR-ABC-123",
            submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        loaded = payment_repo.get_by_utr("UTR-ABC-123")
        assert loaded is not None
        assert loaded.payment_id == payment.payment_id

    def test_list_for_user(self, payment_repo, user_repo, plan_repo):
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("pay_user3", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        for i in range(3):
            payment_repo.save(Payment(
                payment_id=str(uuid.uuid4()),
                user_id=user.id,
                plan_id="pro", amount_minor=999, currency="INR",
                destination_upi="pay@aegis",
                submitted_utr=f"UTR{i}", submitted_at=datetime.now(timezone.utc),
                status=PaymentStatus.PENDING,
            ))
        payments = payment_repo.list_for_user(user.id)
        assert len(payments) == 3

    def test_overwrite(self, payment_repo, user_repo, plan_repo):
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("pay_user4", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        pid = str(uuid.uuid4())
        payment = Payment(
            payment_id=pid, user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="UTR_OLD", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        updated = Payment(
            payment_id=pid, user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="UTR_NEW", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.VERIFIED, verification_method="manual",
            verified_at=datetime.now(timezone.utc),
        )
        payment_repo.overwrite(updated)
        loaded = payment_repo.get_by_id(pid)
        assert loaded.status == PaymentStatus.VERIFIED
        assert loaded.submitted_utr == "UTR_NEW"


# ---------------------------------------------------------------------------
# SubscriptionRepository
# ---------------------------------------------------------------------------


class TestSqlSubscriptionRepository:
    def test_save_and_list(self, sub_repo, user_repo, plan_repo, payment_repo):
        from aegis.entitlement import Plan, Subscription, SubscriptionStatus
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("sub_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        payment = Payment(
            payment_id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="UTR_SUB", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.VERIFIED,
        )
        payment_repo.save(payment)
        sub = Subscription(
            id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            end_time=None, renewal=True,
            payment_id=payment.payment_id,
            created_at=datetime.now(timezone.utc),
        )
        sub_repo.save(sub)
        subs = sub_repo.list_for_user(user.id)
        assert len(subs) == 1
        assert subs[0].status == SubscriptionStatus.ACTIVE

    def test_get_by_payment(self, sub_repo, user_repo, plan_repo, payment_repo):
        from aegis.entitlement import Plan, Subscription, SubscriptionStatus
        from aegis.payment import Payment, PaymentStatus
        user = user_repo.create("sub_user2", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        payment = Payment(
            payment_id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="UTR_SUB2", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.VERIFIED,
        )
        payment_repo.save(payment)
        sub = Subscription(
            id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            end_time=None, renewal=True,
            payment_id=payment.payment_id,
            created_at=datetime.now(timezone.utc),
        )
        sub_repo.save(sub)
        loaded = sub_repo.get_by_payment(payment.payment_id)
        assert loaded is not None
        assert loaded.id == sub.id


# ---------------------------------------------------------------------------
# PlanRepository
# ---------------------------------------------------------------------------


class TestSqlPlanRepository:
    def test_save_and_get(self, plan_repo):
        from aegis.entitlement import Plan
        plan = Plan(id="free", name="Free", version=1, active=True,
                    price_minor=0, currency="INR", entitlements={"agents.max": 1})
        plan_repo.save(plan)
        loaded = plan_repo.get_by_id("free")
        assert loaded is not None
        assert loaded.name == "Free"
        assert loaded.price_minor == 0

    def test_list_active(self, plan_repo):
        from aegis.entitlement import Plan
        plan_repo.save(Plan(id="p1", name="P1", version=1, active=True,
                            price_minor=0, currency="INR", entitlements={}))
        plan_repo.save(Plan(id="p2", name="P2", version=1, active=False,
                            price_minor=0, currency="INR", entitlements={}))
        active = plan_repo.list_active()
        assert len(active) == 1
        assert active[0].id == "p1"

    def test_save_updates_existing(self, plan_repo):
        from aegis.entitlement import Plan
        plan_repo.save(Plan(id="p1", name="Original", version=1, active=True,
                            price_minor=0, currency="INR", entitlements={}))
        plan_repo.save(Plan(id="p1", name="Updated", version=2, active=True,
                            price_minor=0, currency="INR", entitlements={}))
        loaded = plan_repo.get_by_id("p1")
        assert loaded.name == "Updated"
        assert loaded.version == 2


# ---------------------------------------------------------------------------
# AuditRepository
# ---------------------------------------------------------------------------


class TestSqlAuditRepository:
    def test_append_and_list(self, audit_repo, user_repo):
        from aegis.models import AuditEvent
        user = user_repo.create("audit_user", "hash1")
        event = AuditEvent(
            audit_version="1.0",
            decision_id=str(uuid.uuid4()),
            action_id="act1",
            agent_id="ag1",
            agent_name="Agent1",
            action_type="test_action",
            params={},
            result="ALLOW",
            matched=True,
            policy_id="pol1",
            policy_name="TestPolicy",
            rule_id="rule1",
            rule_effect="ALLOW",
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            reason="test",
            user_id=user.id,
        )
        chained = audit_repo.append(event)
        events = audit_repo.list(user.id)
        assert len(events) == 1
        assert chained.hash is not None
        assert len(chained.hash) == 64  # SHA-256 hex

    def test_verify_integrity(self, audit_repo, user_repo):
        from aegis.models import AuditEvent
        user = user_repo.create("audit_user2", "hash1")
        for i in range(5):
            event = AuditEvent(
                audit_version="1.0",
                decision_id=str(uuid.uuid4()),
                action_id=f"act{i}",
                agent_id="ag1",
                agent_name="Agent1",
                action_type="test",
                params={},
                result="ALLOW",
                matched=True,
                policy_id="pol1",
                policy_name="TestPolicy",
                rule_id=f"rule{i}",
                rule_effect="ALLOW",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                reason=f"event {i}",
                user_id=user.id,
            )
            audit_repo.append(event)
        results = audit_repo.verify(user.id)
        assert len(results) == 5
        assert all(r["valid"] for r in results)

    def test_verify_detects_tamper(self, session, audit_repo, user_repo):
        from aegis.models import AuditEvent
        user = user_repo.create("audit_user3", "hash1")
        for i in range(3):
            event = AuditEvent(
                audit_version="1.0",
                decision_id=str(uuid.uuid4()),
                action_id=f"act{i}",
                agent_id="ag1",
                agent_name="Agent1",
                action_type="test",
                params={},
                result="ALLOW",
                matched=True,
                policy_id="pol1",
                policy_name="TestPolicy",
                rule_id=f"rule{i}",
                rule_effect="ALLOW",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                reason=f"event {i}",
                user_id=user.id,
            )
            audit_repo.append(event)
        # Tamper with the second event's result
        from aegis.persistence.models import AuditEventModel
        tampered = session.query(AuditEventModel).filter(
            AuditEventModel.action_id == "act1"
        ).first()
        tampered.result = "DENY"
        session.commit()
        results = audit_repo.verify(user.id)
        # Event 0 is still valid (unchanged)
        # Event 1 content changed → its hash doesn't match → invalid
        # Event 2's hash still matches (depends on event 1's stored hash, not its content)
        assert not results[1]["valid"]

    def test_last_hash(self, audit_repo, user_repo):
        from aegis.models import AuditEvent
        user = user_repo.create("audit_user4", "hash1")
        assert audit_repo.last_hash(user.id) is None
        for i in range(2):
            event = AuditEvent(
                audit_version="1.0",
                decision_id=str(uuid.uuid4()),
                action_id=f"act{i}",
                agent_id="ag1",
                agent_name="Agent1",
                action_type="test",
                params={},
                result="ALLOW",
                matched=True,
                policy_id="pol1",
                policy_name="TestPolicy",
                rule_id=f"rule{i}",
                rule_effect="ALLOW",
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                reason=f"event {i}",
                user_id=user.id,
            )
            audit_repo.append(event)
        last = audit_repo.last_hash(user.id)
        assert last is not None
        assert len(last) == 64


# ---------------------------------------------------------------------------
# Transactional tests
# ---------------------------------------------------------------------------


class TestTransactions:
    def test_atomic_payment_verify_and_subscription_create(self, session, user_repo, plan_repo,
                                                           payment_repo, sub_repo):
        """Simulate the critical payment verification transaction."""
        from aegis.entitlement import Plan, Subscription, SubscriptionStatus
        from aegis.payment import Payment, PaymentStatus

        user = user_repo.create("tx_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        pid = str(uuid.uuid4())
        payment = Payment(
            payment_id=pid, user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="TX_UTR", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        session.commit()  # persist so other sessions can see it

        # Atomic transaction
        from aegis.persistence.database import session_scope
        from aegis.persistence.repositories import SqlPaymentRepository, SqlSubscriptionRepository
        with session_scope() as tx:
            pay_repo = SqlPaymentRepository(tx)
            sub_repo_tx = SqlSubscriptionRepository(tx)
            p = pay_repo.get_by_id_for_update(pid)
            assert p is not None
            updated = Payment(
                payment_id=pid, user_id=user.id, plan_id="pro",
                amount_minor=999, currency="INR", destination_upi="pay@aegis",
                submitted_utr="TX_UTR", submitted_at=p.submitted_at,
                status=PaymentStatus.VERIFIED, verification_method="manual",
                verified_at=datetime.now(timezone.utc),
            )
            pay_repo.overwrite(updated)
            sub = Subscription(
                id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
                status=SubscriptionStatus.ACTIVE,
                start_time=datetime.now(timezone.utc),
                end_time=None, renewal=True,
                payment_id=pid, created_at=datetime.now(timezone.utc),
            )
            sub_repo_tx.save(sub)

        loaded_pay = payment_repo.get_by_id(pid)
        assert loaded_pay.status == PaymentStatus.VERIFIED
        loaded_sub = sub_repo.get_by_payment(pid)
        assert loaded_sub is not None
        assert loaded_sub.status == SubscriptionStatus.ACTIVE

    def test_transaction_rollback_on_failure(self, session, user_repo, plan_repo, payment_repo):
        """If subscription creation fails, payment status must NOT change."""
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus

        user = user_repo.create("tx_rollback_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        pid = str(uuid.uuid4())
        payment = Payment(
            payment_id=pid, user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="ROLL_UTR", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        session.commit()

        from aegis.persistence.database import session_scope
        from aegis.persistence.repositories import SqlPaymentRepository
        try:
            with session_scope() as tx:
                pay_repo = SqlPaymentRepository(tx)
                p = pay_repo.get_by_id_for_update(pid)
                updated = Payment(
                    payment_id=pid, user_id=user.id, plan_id="pro",
                    amount_minor=999, currency="INR", destination_upi="pay@aegis",
                    submitted_utr="ROLL_UTR", submitted_at=p.submitted_at,
                    status=PaymentStatus.VERIFIED, verification_method="manual",
                    verified_at=datetime.now(timezone.utc),
                )
                pay_repo.overwrite(updated)
                raise RuntimeError("Simulated failure after payment update")
        except RuntimeError:
            pass

        loaded = payment_repo.get_by_id(pid)
        assert loaded.status == PaymentStatus.PENDING


# ---------------------------------------------------------------------------
# Concurrency tests
# ---------------------------------------------------------------------------


class TestConcurrency:
    @pytest.mark.xfail(reason="SQLite does not support SELECT FOR UPDATE; requires PostgreSQL")
    def test_double_verify_race(self, session, user_repo, plan_repo, payment_repo):
        """Simulate two concurrent verifiers — only one should succeed."""
        from aegis.entitlement import Plan, Subscription, SubscriptionStatus
        from aegis.payment import Payment, PaymentStatus
        import threading

        user = user_repo.create("race_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        pid = str(uuid.uuid4())
        payment = Payment(
            payment_id=pid, user_id=user.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="RACE_UTR", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        session.commit()

        results: list[bool] = []
        lock = threading.Lock()

        def verifier() -> None:
            from aegis.persistence.database import session_scope
            from aegis.persistence.repositories import SqlPaymentRepository
            try:
                with session_scope() as tx:
                    pay_repo = SqlPaymentRepository(tx)
                    p = pay_repo.get_by_id_for_update(pid)
                    if p is None or p.status != PaymentStatus.PENDING:
                        with lock:
                            results.append(False)
                        return
                    updated = Payment(
                        payment_id=pid, user_id=user.id, plan_id="pro",
                        amount_minor=999, currency="INR", destination_upi="pay@aegis",
                        submitted_utr="RACE_UTR", submitted_at=p.submitted_at,
                        status=PaymentStatus.VERIFIED, verification_method="manual",
                        verified_at=datetime.now(timezone.utc),
                    )
                    pay_repo.overwrite(updated)
                with lock:
                    results.append(True)
            except Exception:
                with lock:
                    results.append(False)

        t1 = threading.Thread(target=verifier)
        t2 = threading.Thread(target=verifier)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        successes = sum(results)
        assert successes == 1, f"Expected exactly 1 verifier to succeed, got {successes}"

    @pytest.mark.xfail(reason="SQLite does not support SELECT FOR UPDATE; requires PostgreSQL SERIALIZABLE isolation")
    def test_duplicate_utr_race(self, session, user_repo, plan_repo, payment_repo):
        """Two concurrent submits with same (normalized) UTR — only one should succeed."""
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus
        import threading

        user = user_repo.create("dup_race_user", "hash1")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        session.commit()

        results: list[bool] = []
        lock = threading.Lock()
        utr = "DUP-UTR-999"

        def submitter() -> None:
            from aegis.persistence.database import session_scope
            from aegis.persistence.repositories import SqlPaymentRepository
            try:
                with session_scope() as tx:
                    pay_repo = SqlPaymentRepository(tx)
                    existing = pay_repo.get_by_utr("DUP-UTR-999")
                    if existing:
                        with lock:
                            results.append(False)
                        return
                    pay_repo.save(Payment(
                        payment_id=str(uuid.uuid4()), user_id=user.id, plan_id="pro",
                        amount_minor=999, currency="INR", destination_upi="pay@aegis",
                        submitted_utr=utr, submitted_at=datetime.now(timezone.utc),
                        status=PaymentStatus.PENDING,
                    ))
                with lock:
                    results.append(True)
            except Exception:
                with lock:
                    results.append(False)

        t1 = threading.Thread(target=submitter)
        t2 = threading.Thread(target=submitter)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        successes = sum(results)
        assert successes == 1, f"Expected exactly 1 submit to succeed, got {successes}"
        # Verify only one payment with that UTR exists
        all_payments = payment_repo.list_all()
        matching = [p for p in all_payments if p.submitted_utr == utr]
        assert len(matching) == 1

    def test_concurrent_role_change(self, session, user_repo):
        """Two concurrent role changes — final state should be one of the valid roles."""
        import threading

        user = user_repo.create("role_race_user", "hash1")
        session.commit()
        results: list[str] = []
        lock = threading.Lock()

        def changer(role: str) -> None:
            from aegis.persistence.database import session_scope
            from aegis.persistence.repositories import SqlUserRepository
            try:
                with session_scope() as tx:
                    repo = SqlUserRepository(tx)
                    repo.set_role(user.id, role)
                with lock:
                    results.append(role)
            except Exception:
                pass

        t1 = threading.Thread(target=changer, args=("ADMIN",))
        t2 = threading.Thread(target=changer, args=("PAYMENT_VERIFIER",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        loaded = user_repo.get_by_id(user.id)
        assert loaded.role in ("ADMIN", "PAYMENT_VERIFIER")


# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------


class TestMigration:
    def test_migrate_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from aegis.persistence.migration import migrate
            result = migrate(tmpdir)
            assert result.total == 0
            assert result.users == 0

    def test_migrate_with_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create NDJSON data
            from datetime import timedelta
            users = [
                {"id": "u1", "username": "alice", "password_hash": "h1",
                 "role": "USER", "active": True,
                 "created_at": datetime.now(timezone.utc).isoformat()},
                {"id": "u2", "username": "bob", "password_hash": "h2",
                 "role": "ADMIN", "active": True,
                 "created_at": datetime.now(timezone.utc).isoformat()},
            ]
            with open(os.path.join(tmpdir, "users.ndjson"), "w") as f:
                for u in users:
                    f.write(json.dumps(u) + "\n")

            from aegis.persistence.migration import migrate, verify_migration
            result = migrate(tmpdir)
            assert result.users == 2
            assert result.total == 2

            counts = verify_migration(tmpdir)
            assert counts["users"]["ndjson"] == 2
            assert counts["users"]["db"] == 2

    def test_migrate_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            users = [
                {"id": "u1", "username": "alice", "password_hash": "h1",
                 "role": "USER", "active": True,
                 "created_at": datetime.now(timezone.utc).isoformat()},
            ]
            with open(os.path.join(tmpdir, "users.ndjson"), "w") as f:
                for u in users:
                    f.write(json.dumps(u) + "\n")

            from aegis.persistence.migration import migrate
            r1 = migrate(tmpdir)
            assert r1.users == 1
            r2 = migrate(tmpdir)
            assert r2.users == 0  # already migrated, no new records
            r3 = migrate(tmpdir, rebuild=True)
            assert r3.users == 1  # rebuilt then migrated

    def test_migrate_with_rebuild(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            users = [
                {"id": "u1", "username": "alice", "password_hash": "h1",
                 "role": "USER", "active": True,
                 "created_at": datetime.now(timezone.utc).isoformat()},
            ]
            with open(os.path.join(tmpdir, "users.ndjson"), "w") as f:
                for u in users:
                    f.write(json.dumps(u) + "\n")

            from aegis.persistence.migration import migrate, verify_migration
            result = migrate(tmpdir, rebuild=True)
            assert result.users == 1
            counts = verify_migration(tmpdir)
            assert counts["users"]["ndjson"] == counts["users"]["db"]


# ---------------------------------------------------------------------------
# Security tests
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_cannot_access_other_users_payments(self, session, user_repo, plan_repo, payment_repo):
        from aegis.entitlement import Plan
        from aegis.payment import Payment, PaymentStatus

        user1 = user_repo.create("sec_user1", "hash1")
        user2 = user_repo.create("sec_user2", "hash2")
        plan = Plan(id="pro", name="Pro", version=1, active=True, price_minor=999,
                    currency="INR", entitlements={"agents.max": 10})
        plan_repo.save(plan)
        payment = Payment(
            payment_id=str(uuid.uuid4()), user_id=user1.id, plan_id="pro",
            amount_minor=999, currency="INR", destination_upi="pay@aegis",
            submitted_utr="SEC_UTR", submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        payment_repo.save(payment)
        user2_payments = payment_repo.list_for_user(user2.id)
        assert len(user2_payments) == 0

    def test_cannot_list_other_users_agents(self, session, user_repo, agent_repo):
        user1 = user_repo.create("sec_agent_user1", "hash1")
        user2 = user_repo.create("sec_agent_user2", "hash2")
        agent_repo.create(user1.id, "SecretAgent")
        user2_agents = agent_repo.list_for_user(user2.id)
        assert len(user2_agents) == 0


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------


class TestRegression:
    def test_orm_model_str(self):
        from aegis.persistence.models import UserModel
        m = UserModel(id="x", username="test", password_hash="pw",
                      role="USER", active=True, created_at=datetime.now(timezone.utc))
        s = str(m)
        assert "UserModel" in s

    def test_session_scope_creates_tables(self):
        from aegis.persistence.database import session_scope, get_engine
        engine = get_engine()
        from aegis.persistence.models import Base
        # Verify tables exist by querying
        with engine.connect() as conn:
            result = conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ))
            tables = [row[0] for row in result]
        assert "users" in tables
        assert "audit_events" in tables

    def test_fk_enforcement(self, session):
        from aegis.persistence.models import SessionModel
        from datetime import timedelta
        from sqlalchemy.exc import IntegrityError
        # Verify FK violation raises
        with pytest.raises(IntegrityError):
            session.add(SessionModel(
                id="fk_test", token_hash="h", user_id="nonexistent",
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
                revoked=False,
            ))
            session.commit()
        session.rollback()
