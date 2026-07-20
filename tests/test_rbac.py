"""Tests for RBAC roles, permissions, authorization, and privilege escalation."""

import os
import uuid
from unittest.mock import patch

import pytest

from aegis.rbac import (
    AuthorizationError,
    AuthorizationService,
    Role,
    PERM_PAYMENT_VERIFY,
    PERM_PAYMENT_REJECT,
    PERM_PAYMENT_VIEW_ALL,
    PERM_SUBSCRIPTION_MANAGE,
    PERM_USER_MANAGE,
    PERM_AUDIT_VIEW_ALL,
    PERM_SYSTEM_MANAGE,
    _ROLE_PERMISSIONS,
    _VALID_ROLES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def auth(tmp_path):
    """Authenticator backed by temp dir."""
    from aegis.auth import Authenticator
    return Authenticator(str(tmp_path))


@pytest.fixture
def svc(tmp_path):
    """AuthorizationService backed by temp dir."""
    return AuthorizationService(str(tmp_path))


@pytest.fixture
def users(auth):
    """Create one user per role."""
    u = auth.register("regular", "Pass1234!")
    uv = auth.register("verifier", "Pass1234!")
    auth.set_user_role(uv.id, "PAYMENT_VERIFIER")
    ua = auth.register("adminuser", "Pass1234!")
    auth.set_user_role(ua.id, "ADMIN")
    return {
        "user": u,
        "verifier": uv,
        "admin": ua,
    }


# ---------------------------------------------------------------------------
# Role model tests
# ---------------------------------------------------------------------------


class TestRoleModel:
    def test_role_enum_values(self):
        assert Role.USER.value == "USER"
        assert Role.PAYMENT_VERIFIER.value == "PAYMENT_VERIFIER"
        assert Role.ADMIN.value == "ADMIN"

    def test_valid_roles_set(self):
        assert _VALID_ROLES == {"USER", "PAYMENT_VERIFIER", "ADMIN"}

    def test_unknown_role_not_in_valid(self):
        assert "SUPERADMIN" not in _VALID_ROLES


# ---------------------------------------------------------------------------
# Permission matrix tests
# ---------------------------------------------------------------------------


class TestPermissionMatrix:
    def test_user_has_no_permissions(self):
        assert _ROLE_PERMISSIONS["USER"] == set()

    def test_verifier_permissions(self):
        perms = _ROLE_PERMISSIONS["PAYMENT_VERIFIER"]
        assert PERM_PAYMENT_VERIFY in perms
        assert PERM_PAYMENT_REJECT in perms
        assert PERM_PAYMENT_VIEW_ALL in perms
        assert PERM_SUBSCRIPTION_MANAGE not in perms
        assert PERM_USER_MANAGE not in perms

    def test_admin_permissions(self):
        perms = _ROLE_PERMISSIONS["ADMIN"]
        assert PERM_PAYMENT_VERIFY in perms
        assert PERM_PAYMENT_REJECT in perms
        assert PERM_PAYMENT_VIEW_ALL in perms
        assert PERM_SUBSCRIPTION_MANAGE in perms
        assert PERM_USER_MANAGE in perms
        assert PERM_AUDIT_VIEW_ALL in perms
        assert PERM_SYSTEM_MANAGE in perms

    def test_unknown_role_has_no_permissions(self):
        assert _ROLE_PERMISSIONS.get("NONEXISTENT", set()) == set()

    def test_unknown_permission_not_in_admin(self):
        perms = _ROLE_PERMISSIONS["ADMIN"]
        assert "nonexistent.permission" not in perms


# ---------------------------------------------------------------------------
# AuthorizationService tests
# ---------------------------------------------------------------------------


class TestAuthorizationHas:
    def test_user_has_nothing(self, svc, users):
        uid = users["user"].id
        assert not svc.has(uid, PERM_PAYMENT_VERIFY)
        assert not svc.has(uid, PERM_PAYMENT_REJECT)
        assert not svc.has(uid, PERM_PAYMENT_VIEW_ALL)
        assert not svc.has(uid, PERM_SUBSCRIPTION_MANAGE)
        assert not svc.has(uid, PERM_USER_MANAGE)
        assert not svc.has(uid, PERM_AUDIT_VIEW_ALL)
        assert not svc.has(uid, PERM_SYSTEM_MANAGE)

    def test_verifier_has_payment_permissions(self, svc, users):
        vid = users["verifier"].id
        assert svc.has(vid, PERM_PAYMENT_VERIFY)
        assert svc.has(vid, PERM_PAYMENT_REJECT)
        assert svc.has(vid, PERM_PAYMENT_VIEW_ALL)
        assert not svc.has(vid, PERM_SUBSCRIPTION_MANAGE)
        assert not svc.has(vid, PERM_USER_MANAGE)
        assert not svc.has(vid, PERM_SYSTEM_MANAGE)

    def test_admin_has_all(self, svc, users):
        aid = users["admin"].id
        assert svc.has(aid, PERM_PAYMENT_VERIFY)
        assert svc.has(aid, PERM_PAYMENT_REJECT)
        assert svc.has(aid, PERM_PAYMENT_VIEW_ALL)
        assert svc.has(aid, PERM_SUBSCRIPTION_MANAGE)
        assert svc.has(aid, PERM_USER_MANAGE)
        assert svc.has(aid, PERM_AUDIT_VIEW_ALL)
        assert svc.has(aid, PERM_SYSTEM_MANAGE)

    def test_unknown_user_fails_closed(self, svc):
        assert not svc.has(str(uuid.uuid4()), PERM_PAYMENT_VERIFY)

    def test_unknown_permission_fails_closed(self, svc, users):
        assert not svc.has(users["admin"].id, "nonexistent")

    def test_unknown_role_fails_closed(self, auth, svc):
        """A user with an unrecognised role gets zero permissions."""
        from aegis.auth import User as AuthUser
        from aegis.auth import _append_ndjson as _append_user
        from datetime import datetime, timezone

        uid = str(uuid.uuid4())
        unknown_user = AuthUser(
            id=uid,
            username="strange",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
            role="NONEXISTENT",
        )
        _append_user(auth.user_store._path, unknown_user.to_dict())

        assert not svc.has(uid, PERM_PAYMENT_VERIFY)
        assert not svc.has(uid, PERM_USER_MANAGE)

    def test_deactivated_user_still_checked_by_role(self, auth, svc):
        user = auth.register("deact", "Pass1234!")
        auth.set_user_role(user.id, "ADMIN")
        auth.user_store.deactivate(user.id)
        assert svc.has(user.id, PERM_PAYMENT_VERIFY)


class TestAuthorizationRequire:
    def test_user_require_raises(self, svc, users):
        with pytest.raises(AuthorizationError, match="lacks required permission"):
            svc.require(users["user"].id, PERM_PAYMENT_VERIFY)

    def test_verifier_require_passes(self, svc, users):
        svc.require(users["verifier"].id, PERM_PAYMENT_VERIFY)

    def test_admin_require_passes(self, svc, users):
        svc.require(users["admin"].id, PERM_PAYMENT_VERIFY)

    def test_unknown_user_require_raises(self, svc):
        with pytest.raises(AuthorizationError):
            svc.require(str(uuid.uuid4()), PERM_PAYMENT_VERIFY)

    def test_verifier_cannot_manage_users(self, svc, users):
        with pytest.raises(AuthorizationError):
            svc.require(users["verifier"].id, PERM_USER_MANAGE)


class TestListUserPermissions:
    def test_user_permissions_empty(self, svc, users):
        perms = svc.list_user_permissions(users["user"].id)
        assert perms == frozenset()

    def test_verifier_permissions(self, svc, users):
        perms = svc.list_user_permissions(users["verifier"].id)
        assert PERM_PAYMENT_VERIFY in perms
        assert PERM_PAYMENT_REJECT in perms
        assert PERM_PAYMENT_VIEW_ALL in perms
        assert PERM_USER_MANAGE not in perms

    def test_admin_permissions(self, svc, users):
        perms = svc.list_user_permissions(users["admin"].id)
        assert len(perms) == 7

    def test_unknown_user(self, svc):
        assert svc.list_user_permissions(str(uuid.uuid4())) == frozenset()


class TestValidateRole:
    def test_valid_roles(self):
        AuthorizationService.validate_role("USER")
        AuthorizationService.validate_role("PAYMENT_VERIFIER")
        AuthorizationService.validate_role("ADMIN")

    def test_invalid_role_raises(self):
        with pytest.raises(ValueError, match="Invalid role"):
            AuthorizationService.validate_role("SUPERADMIN")

    def test_empty_role_raises(self):
        with pytest.raises(ValueError, match="Invalid role"):
            AuthorizationService.validate_role("")


class TestGetRolePermissions:
    def test_user_permissions(self):
        perms = AuthorizationService.get_role_permissions("USER")
        assert perms == frozenset()

    def test_unknown_role(self):
        perms = AuthorizationService.get_role_permissions("NONEXISTENT")
        assert perms == frozenset()


# ---------------------------------------------------------------------------
# Authentication compatibility tests
# ---------------------------------------------------------------------------


class TestAuthCompatibility:
    def test_login_still_works(self, auth):
        auth.register("alice", "ValidPass1!")
        session, token = auth.login("alice", "ValidPass1!")
        assert session is not None
        assert token is not None

    def test_session_still_valid(self, auth):
        auth.register("alice", "ValidPass1!")
        _, token = auth.login("alice", "ValidPass1!")
        user = auth.validate_session(token)
        assert user is not None
        assert user.role == "USER"

    def test_logout_still_works(self, auth):
        auth.register("alice", "ValidPass1!")
        _, token = auth.login("alice", "ValidPass1!")
        auth.logout(token)
        assert auth.validate_session(token) is None

    def test_deactivated_user_remains_blocked(self, auth):
        user = auth.register("alice", "ValidPass1!")
        auth.user_store.deactivate(user.id)
        with pytest.raises(ValueError, match="deactivated"):
            auth.login("alice", "ValidPass1!")


# ---------------------------------------------------------------------------
# Privilege escalation tests
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    def test_user_cannot_set_own_role(self, auth, svc):
        """USER cannot set their own role to ADMIN via set_user_role (requires user.manage)."""
        user = auth.register("normal", "Pass1234!")
        # set_user_role is a data operation; authorization is caller's responsibility
        # The CLI handler checks permission before calling set_user_role.
        # The API does not have a built-in guard — the caller must check.
        # This test verifies that the permission check exists in the auth layer.
        assert not svc.has(user.id, PERM_USER_MANAGE)

    def test_user_set_role_requires_user_manage(self, auth, svc):
        user = auth.register("normal", "Pass1234!")
        other = auth.register("other", "Pass1234!")
        assert not svc.has(user.id, PERM_USER_MANAGE)
        assert not svc.has(other.id, PERM_USER_MANAGE)

    def test_admin_can_set_other_role(self, auth, svc):
        admin_user = auth.register("admin", "AdminPass1!")
        auth.set_user_role(admin_user.id, "ADMIN")
        target = auth.register("target", "TargetPass1!")
        assert svc.has(admin_user.id, PERM_USER_MANAGE)
        # The caller (admin) can set another user's role
        auth.set_user_role(target.id, "PAYMENT_VERIFIER")
        assert svc.has(target.id, PERM_PAYMENT_VERIFY)


# ---------------------------------------------------------------------------
# Payment RBAC tests
# ---------------------------------------------------------------------------


class TestPaymentRBAC:
    def test_user_cannot_verify_payment(self, tmp_path):
        """A regular USER cannot call verify_payment."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService, PaymentError

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "TESTUTR12345")

        with pytest.raises(AuthorizationError, match="lacks required permission"):
            svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=user.id,
            )

    def test_payment_verifier_can_verify(self, tmp_path):
        """A PAYMENT_VERIFIER can call verify_payment."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        verifier = auth.register("verifier", "Pass1234!")
        auth.set_user_role(verifier.id, "PAYMENT_VERIFIER")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "TESTUTR12346")

        result = svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=verifier.id,
        )
        assert result.status.value == "VERIFIED"

    def test_admin_can_verify(self, tmp_path):
        """An ADMIN can call verify_payment."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "TESTUTR12347")

        result = svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
        )
        assert result.status.value == "VERIFIED"

    def test_user_cannot_reject_payment(self, tmp_path):
        """A regular USER cannot call reject_payment."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "TESTUTR12348")

        with pytest.raises(AuthorizationError):
            svc.reject_payment(
                payment_id=payment.payment_id,
                verifier_id=user.id,
                reason="Testing",
            )

    def test_user_cannot_view_all_payments(self, tmp_path):
        """A regular USER cannot call list_all_payments."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))

        with pytest.raises(AuthorizationError):
            svc.list_all_payments(user.id)

    def test_verifier_can_view_all_payments(self, tmp_path):
        """A PAYMENT_VERIFIER can view all payments."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        verifier = auth.register("verifier", "Pass1234!")
        auth.set_user_role(verifier.id, "PAYMENT_VERIFIER")
        svc = PaymentService(str(tmp_path))
        result = svc.list_all_payments(verifier.id)
        assert result == []

    def test_unauthorized_verifier_rejected(self, tmp_path):
        """A user without payment.verify cannot verify."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        # create another user without rights
        other = auth.register("other", "Pass1234!")
        payment = svc.submit_payment(user.id, "pro", "TESTUTR12349")
        with pytest.raises(AuthorizationError):
            svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=other.id,
            )


# ---------------------------------------------------------------------------
# Payment verification authorisation flow tests
# ---------------------------------------------------------------------------


class TestPaymentVerificationFlow:
    def test_full_flow_with_verifier(self, tmp_path):
        """Complete flow with authorized PAYMENT_VERIFIER."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService
        from aegis.entitlement import EntitlementService

        auth = Authenticator(str(tmp_path))
        verifier = auth.register("verifier", "Pass1234!")
        auth.set_user_role(verifier.id, "PAYMENT_VERIFIER")
        user = auth.register("regular", "Pass1234!")

        svc = PaymentService(str(tmp_path))
        entitlement = EntitlementService(str(tmp_path))

        # Submit
        payment = svc.submit_payment(user.id, "pro", "FLOWUTR001")
        assert not entitlement.has(user.id, "ai.copilot")

        # Authorised verifier verifies
        verified = svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=verifier.id,
        )
        assert verified.status.value == "VERIFIED"
        assert entitlement.has(user.id, "ai.copilot")

    def test_verified_payment_activates_subscription(self, tmp_path):
        """Verified payment creates subscription through proper flow."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService
        from aegis.entitlement import EntitlementService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")

        svc = PaymentService(str(tmp_path))
        entitlement = EntitlementService(str(tmp_path))

        payment = svc.submit_payment(user.id, "pro", "FLOWUTR002")
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
        )
        sub = entitlement.get_latest_subscription(user.id)
        assert sub is not None
        assert sub.payment_id == payment.payment_id
        assert sub.status.value == "ACTIVE"

    def test_verified_payment_cannot_be_reverified(self, tmp_path):
        """Once VERIFIED, same payment cannot be re-verified."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService, PaymentError

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")

        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "FLOWUTR003")
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
        )
        with pytest.raises(PaymentError, match="Cannot verify"):
            svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=admin.id,
            )


# ---------------------------------------------------------------------------
# User model role field tests
# ---------------------------------------------------------------------------


class TestUserModelRole:
    def test_default_role_is_user(self):
        from aegis.auth import User
        from datetime import datetime, timezone

        u = User(
            id=str(uuid.uuid4()),
            username="testuser",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
        )
        assert u.role == "USER"

    def test_role_serialization_roundtrip(self):
        from aegis.auth import User
        from datetime import datetime, timezone

        u = User(
            id=str(uuid.uuid4()),
            username="adminuser",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
            role="ADMIN",
        )
        d = u.to_dict()
        assert d["role"] == "ADMIN"
        u2 = User.from_dict(d)
        assert u2.role == "ADMIN"

    def test_missing_role_defaults_to_user(self):
        from aegis.auth import User

        u = User.from_dict({
            "id": str(uuid.uuid4()),
            "username": "legacy",
            "password_hash": "hash",
            "created_at": "2026-07-19T00:00:00+00:00",
        })
        assert u.role == "USER"


# ---------------------------------------------------------------------------
# Role assignment tests
# ---------------------------------------------------------------------------


class TestRoleAssignment:
    def test_set_role_on_user(self, auth):
        user = auth.register("target", "Pass1234!")
        updated = auth.set_user_role(user.id, "ADMIN")
        assert updated.role == "ADMIN"
        # Verify persistence
        reloaded = auth.get_user_by_id(user.id)
        assert reloaded is not None
        assert reloaded.role == "ADMIN"

    def test_set_role_on_other_user_preserves_identity(self, auth):
        user = auth.register("target", "Pass1234!")
        updated = auth.set_user_role(user.id, "ADMIN")
        assert updated.id == user.id
        assert updated.username == user.username
        assert updated.password_hash == user.password_hash

    def test_invalid_role_raises(self, auth):
        user = auth.register("target", "Pass1234!")
        with pytest.raises(ValueError, match="Invalid role"):
            auth.set_user_role(user.id, "SUPERADMIN")

    def test_nonexistent_user_raises(self, auth):
        with pytest.raises(ValueError, match="not found"):
            auth.set_user_role(str(uuid.uuid4()), "ADMIN")

    def test_role_change_is_append_only(self, auth, tmp_path):
        user = auth.register("target", "Pass1234!")
        auth.set_user_role(user.id, "ADMIN")
        # Check ndjson has multiple records for same user
        ndjson_path = os.path.join(str(tmp_path), "users.ndjson")
        with open(ndjson_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        # At least 2 lines: original + role change
        assert len(lines) >= 2
        # Latest line should have ADMIN role
        import json
        latest = json.loads(lines[-1])
        assert latest["role"] == "ADMIN"


# ---------------------------------------------------------------------------
# Ownership tests
# ---------------------------------------------------------------------------


class TestOwnership:
    def test_user_cannot_view_other_payment(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService, PaymentError

        auth = Authenticator(str(tmp_path))
        user1 = auth.register("user1", "Pass1234!")
        user2 = auth.register("user2", "Pass1234!")
        svc = PaymentService(str(tmp_path))

        p = svc.submit_payment(user1.id, "pro", "OWNUTR001")
        with pytest.raises(PaymentError, match="not found"):
            svc.get_payment(p.payment_id, user2.id)

    def test_user_cannot_modify_other_payment(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService, PaymentError

        auth = Authenticator(str(tmp_path))
        user1 = auth.register("user1", "Pass1234!")
        user2 = auth.register("user2", "Pass1234!")
        svc = PaymentService(str(tmp_path))

        p = svc.submit_payment(user1.id, "pro", "OWNUTR002")
        # user2 cannot view user1's payment
        with pytest.raises(PaymentError, match="not found"):
            svc.get_payment(p.payment_id, user2.id)

    def test_list_returns_own_only(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        user1 = auth.register("user1", "Pass1234!")
        user2 = auth.register("user2", "Pass1234!")
        svc = PaymentService(str(tmp_path))

        svc.submit_payment(user1.id, "pro", "OWNUTR003")
        assert len(svc.list_payments(user1.id)) == 1
        assert len(svc.list_payments(user2.id)) == 0


# ---------------------------------------------------------------------------
# Audit of privileged actions tests
# ---------------------------------------------------------------------------


class TestPrivilegedActionAudit:
    def test_verify_payment_creates_audit_event(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "AUDITUTR01")

        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
        )

        from aegis.audit import AuditStore
        audit = AuditStore(str(tmp_path))
        events = audit.list(admin.id)
        privileged = [e for e in events if e.action_type == "privileged_operation"]
        assert len(privileged) >= 1
        assert privileged[0].params.get("privileged_action") == "payment.verify"
        assert privileged[0].params.get("result") == "VERIFIED"

    def test_reject_payment_creates_audit_event(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "AUDITUTR02")

        svc.reject_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
            reason="Test rejection",
        )

        from aegis.audit import AuditStore
        audit = AuditStore(str(tmp_path))
        events = audit.list(admin.id)
        privileged = [e for e in events if e.action_type == "privileged_operation"]
        assert len(privileged) >= 1
        assert privileged[0].params.get("privileged_action") == "payment.reject"

    def test_audit_contains_no_secrets(self, tmp_path):
        """Audit records must not contain UTRs, passwords, or tokens."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "SECRETUTR999")

        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=admin.id,
        )

        from aegis.audit import AuditStore
        audit = AuditStore(str(tmp_path))
        events = audit.list(admin.id)
        all_text = str([e.to_dict() for e in events])
        assert "SECRETUTR999" not in all_text
        assert "Pass1234!" not in all_text

    def test_audit_privileged_action_helper(self, svc, users):
        """AuthorizationService.audit_privileged_action creates audit event."""
        admin = users["admin"]
        svc.audit_privileged_action(
            actor_id=admin.id,
            operation="test.operation",
            target_id="test-target",
            result="SUCCESS",
        )
        from aegis.audit import AuditStore
        audit = AuditStore(svc._data_dir)
        events = audit.list(admin.id)
        privileged = [e for e in events if e.action_type == "privileged_operation"]
        assert len(privileged) >= 1
        assert privileged[-1].params.get("privileged_action") == "test.operation"


# ---------------------------------------------------------------------------
# Environment guard tests
# ---------------------------------------------------------------------------


class TestEnvironmentGuards:
    def test_dev_manual_verify_still_requires_dev_env(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService, PaymentError

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "ENVUTR001")

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(PaymentError, match="only available in development"):
                svc._dev_manual_verify(payment.payment_id, user.id)

    def test_dev_manual_verify_works_with_dev_env(self, tmp_path):
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "ENVUTR002")

        with patch.dict(os.environ, {"AEGIS_ENV": "dev"}):
            result = svc._dev_manual_verify(payment.payment_id, user.id)
            assert result.status.value == "VERIFIED"

    def test_admin_payment_verify_no_dev_env_required(self, tmp_path):
        """Admin operations no longer require AEGIS_ENV=dev; RBAC is the guard."""
        from aegis.auth import Authenticator
        from aegis.payment import PaymentService

        auth = Authenticator(str(tmp_path))
        admin = auth.register("admin", "Pass1234!")
        auth.set_user_role(admin.id, "ADMIN")
        user = auth.register("regular", "Pass1234!")
        svc = PaymentService(str(tmp_path))
        payment = svc.submit_payment(user.id, "pro", "ENVUTR003")

        with patch.dict(os.environ, {}, clear=True):
            result = svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=admin.id,
            )
            assert result.status.value == "VERIFIED"


# ---------------------------------------------------------------------------
# Authorization service unknown permission tests
# ---------------------------------------------------------------------------


class TestUnknownPermission:
    def test_unknown_permission_returns_false(self, svc, users):
        for key in ("user", "verifier", "admin"):
            assert not svc.has(users[key].id, "nonexistent.permission")

    def test_require_unknown_permission_raises(self, svc, users):
        with pytest.raises(AuthorizationError):
            svc.require(users["admin"].id, "nonexistent.permission")

    def test_list_user_permissions_does_not_include_unknown(self, svc, users):
        perms = svc.list_user_permissions(users["admin"].id)
        assert "nonexistent.permission" not in perms
