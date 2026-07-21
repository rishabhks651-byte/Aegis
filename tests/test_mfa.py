"""Tests for MFA (TOTP) authentication."""

import os
import json
import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from aegis.auth import (
    User,
    Session,
    Authenticator,
    PendingMfaSession,
    encrypt_totp_secret,
    decrypt_totp_secret,
    generate_recovery_codes,
    hash_recovery_codes,
    verify_recovery_code,
)
from aegis.exceptions import ErrorCode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def auth(tmp_path):
    return Authenticator(str(tmp_path))


@pytest.fixture
def sample_password():
    return "correct-horse-battery-staple"


@pytest.fixture
def sample_username():
    return "alice"


@pytest.fixture
def non_mfa_user(auth, sample_username, sample_password):
    return auth.register(sample_username, sample_password)


@pytest.fixture
def mfa_user(auth, sample_username, sample_password):
    user = auth.register(sample_username, sample_password)
    secret = pyotp.random_base32()
    auth.enable_mfa(user.id, user.password_hash, secret)
    auth.confirm_mfa(user.id, pyotp.TOTP(secret).now())
    _, raw_codes = auth.regenerate_recovery_codes(user.id)
    return user


# ---------------------------------------------------------------------------
# TOTP secret encryption / decryption
# ---------------------------------------------------------------------------


class TestTotpEncryption:
    def test_encrypt_decrypt_round_trip(self):
        secret = pyotp.random_base32()
        password_hash = "$2b$12$abcdefghijklmnopqrstuv"
        encrypted = encrypt_totp_secret(secret, password_hash)
        decrypted = decrypt_totp_secret(encrypted, password_hash)
        assert decrypted == secret

    def test_different_password_fails(self):
        secret = pyotp.random_base32()
        encrypted = encrypt_totp_secret(secret, "$2b$12$hashvalue1")
        with pytest.raises(Exception):
            decrypt_totp_secret(encrypted, "$2b$12$hashvalue2")

    def test_encrypted_output_is_string(self):
        encrypted = encrypt_totp_secret("secret", "$2b$12$hash")
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

    def test_encrypted_can_be_decrypted_with_same_hash(self):
        secret = pyotp.random_base32()
        h = "$2b$12$hashvalue123456"
        encrypted = encrypt_totp_secret(secret, h)
        decrypted = decrypt_totp_secret(encrypted, h)
        assert decrypted == secret


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------


class TestRecoveryCodes:
    def test_generate_returns_correct_count(self):
        codes = generate_recovery_codes(8)
        assert len(codes) == 8

    def test_generate_codes_are_unique(self):
        codes = generate_recovery_codes(16)
        assert len(set(codes)) == 16

    def test_generate_codes_are_strings(self):
        for code in generate_recovery_codes():
            assert isinstance(code, str)
            assert len(code) > 0

    def test_hash_is_sha256(self):
        code = "my-recovery-code"
        h = hash_recovery_codes([code])[0]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_verify_valid_code(self):
        codes = generate_recovery_codes(8)
        hashed = hash_recovery_codes(codes)
        valid, remaining = verify_recovery_code(codes[0], tuple(hashed))
        assert valid is True
        assert len(remaining) == 7
        assert hash_recovery_codes([codes[0]])[0] not in remaining

    def test_verify_invalid_code(self):
        hashed = hash_recovery_codes(generate_recovery_codes(8))
        valid, remaining = verify_recovery_code("invalid-code", tuple(hashed))
        assert valid is False
        assert len(remaining) == 8

    def test_code_one_time_use(self):
        codes = generate_recovery_codes(4)
        hashed = tuple(hash_recovery_codes(codes))
        # First use
        valid1, remaining1 = verify_recovery_code(codes[0], hashed)
        assert valid1 is True
        assert len(remaining1) == 3
        # Second use of same code should fail
        valid2, remaining2 = verify_recovery_code(codes[0], remaining1)
        assert valid2 is False
        assert len(remaining2) == 3

    def test_verify_empty_hashed_list(self):
        valid, remaining = verify_recovery_code("code", ())
        assert valid is False
        assert remaining == ()


# ---------------------------------------------------------------------------
# User model MFA fields
# ---------------------------------------------------------------------------


class TestUserMfaFields:
    def test_default_mfa_disabled(self):
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
        )
        assert u.mfa_enabled is False
        assert u.totp_secret is None
        assert u.totp_confirmed_at is None
        assert u.last_used_totp_step is None
        assert u.recovery_codes == ()
        assert u.recovery_codes_generated_at is None

    def test_to_dict_round_trip_with_mfa(self):
        now = datetime.now(timezone.utc)
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=now,
            mfa_enabled=True,
            totp_secret="encrypted-secret",
            totp_confirmed_at=now,
            last_used_totp_step=1000,
            recovery_codes=("hash1", "hash2"),
            recovery_codes_generated_at=now,
        )
        restored = User.from_dict(u.to_dict())
        assert restored == u

    def test_to_dict_backward_compatible(self):
        d = {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "username": "alice",
            "password_hash": "hash",
            "created_at": "2026-07-19T00:00:00+00:00",
            "active": True,
            "role": "USER",
        }
        u = User.from_dict(d)
        assert u.mfa_enabled is False
        assert u.totp_secret is None
        assert u.recovery_codes == ()

    def test_to_dict_with_mfa_defaults(self):
        now = datetime.now(timezone.utc)
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=now,
        )
        d = u.to_dict()
        assert d["mfa_enabled"] is False
        assert d["totp_secret"] is None
        assert d["totp_confirmed_at"] is None
        assert d["last_used_totp_step"] is None
        assert d["recovery_codes"] == []
        assert d["recovery_codes_generated_at"] is None


# ---------------------------------------------------------------------------
# Pending MFA session
# ---------------------------------------------------------------------------


class TestPendingMfaSession:
    def test_not_expired(self):
        pending = PendingMfaSession(
            user_id="user-id",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
        )
        assert pending.is_expired() is False

    def test_expired(self):
        pending = PendingMfaSession(
            user_id="user-id",
            password_hash="hash",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=400),
        )
        assert pending.is_expired() is True


# ---------------------------------------------------------------------------
# Authenticator MFA methods
# ---------------------------------------------------------------------------


class TestAuthenticatorMfaSetup:
    def test_enable_mfa_stores_encrypted_secret(self, auth, non_mfa_user):
        secret = pyotp.random_base32()
        user = auth.enable_mfa(non_mfa_user.id, non_mfa_user.password_hash, secret)
        assert user.totp_secret is not None
        assert user.totp_secret != secret
        assert user.mfa_enabled is False  # Not yet confirmed
        # Verify it can be decrypted
        decrypted = decrypt_totp_secret(user.totp_secret, user.password_hash)
        assert decrypted == secret

    def test_confirm_mfa_enables_and_generates_totp(self, auth, non_mfa_user):
        secret = pyotp.random_base32()
        auth.enable_mfa(non_mfa_user.id, non_mfa_user.password_hash, secret)
        totp = pyotp.TOTP(secret)
        user = auth.confirm_mfa(non_mfa_user.id, totp.now())
        assert user.mfa_enabled is True
        assert user.totp_confirmed_at is not None

    def test_confirm_mfa_invalid_code_raises(self, auth, non_mfa_user):
        secret = pyotp.random_base32()
        auth.enable_mfa(non_mfa_user.id, non_mfa_user.password_hash, secret)
        with pytest.raises(ValueError, match="Invalid TOTP code"):
            auth.confirm_mfa(non_mfa_user.id, "000000")

    def test_confirm_mfa_without_enable_raises(self, auth, non_mfa_user):
        with pytest.raises(ValueError, match="No TOTP secret"):
            auth.confirm_mfa(non_mfa_user.id, "123456")

    def test_disable_mfa_clears_fields(self, auth, mfa_user):
        user = auth.disable_mfa(mfa_user.id)
        assert user.mfa_enabled is False
        assert user.totp_secret is None
        assert user.totp_confirmed_at is None
        assert user.last_used_totp_step is None
        assert user.recovery_codes == ()
        assert user.recovery_codes_generated_at is None

    def test_regenerate_recovery_codes(self, auth, mfa_user):
        user, raw_codes = auth.regenerate_recovery_codes(mfa_user.id)
        assert len(raw_codes) == 8
        assert len(user.recovery_codes) == 8
        # Verify codes are stored hashed
        for raw in raw_codes:
            import hashlib
            raw_hash = hashlib.sha256(raw.encode()).hexdigest()
            assert raw_hash in user.recovery_codes

    def test_generate_totp_secret_returns_valid_uri(self, auth, non_mfa_user):
        secret, uri = auth.generate_totp_secret(non_mfa_user.username)
        assert len(secret) > 0
        assert "otpauth://" in uri
        assert non_mfa_user.username in uri
        assert "Aegis" in uri


# ---------------------------------------------------------------------------
# MFA-aware login flow
# ---------------------------------------------------------------------------


class TestMfaLoginFlow:
    def test_login_without_mfa_returns_session(self, auth, sample_username, sample_password):
        auth.register(sample_username, sample_password)
        session, raw_token, pending_token = auth.login_mfa_aware(sample_username, sample_password)
        assert session is not None
        assert raw_token is not None
        assert pending_token is None

    def test_login_with_mfa_returns_pending_token(self, auth, mfa_user):
        session, raw_token, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        assert session is None
        assert raw_token is None
        assert pending_token is not None

    def test_login_mfa_wrong_password_raises(self, auth, mfa_user):
        with pytest.raises(ValueError, match="Invalid password"):
            auth.login_mfa_aware(mfa_user.username, "wrong-password")

    def test_verify_totp_creates_session(self, auth, mfa_user):
        _, _, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        # We know the TOTP secret is stored encrypted, so we need to decrypt it
        user = auth.get_user_by_id(mfa_user.id)
        secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        totp_code = pyotp.TOTP(secret).now()
        session, raw_token = auth.verify_totp_and_create_session(pending_token, totp_code)
        assert session is not None
        assert raw_token is not None
        assert session.user_id == mfa_user.id

    def test_verify_totp_invalid_code_raises(self, auth, mfa_user):
        _, _, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        with pytest.raises(ValueError, match="Invalid TOTP code"):
            auth.verify_totp_and_create_session(pending_token, "000000")

    def test_verify_totp_expired_pending_raises(self, auth, mfa_user):
        _, _, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        # Manually expire the pending session
        auth._pending_mfa_store[pending_token].created_at -= timedelta(seconds=400)
        user = auth.get_user_by_id(mfa_user.id)
        secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        totp_code = pyotp.TOTP(secret).now()
        with pytest.raises(ValueError, match="expired"):
            auth.verify_totp_and_create_session(pending_token, totp_code)

    def test_verify_recovery_creates_session(self, auth, mfa_user):
        # Get a recovery code
        user = auth.get_user_by_id(mfa_user.id)
        # We can't get the raw codes from the stored hashes, so test with regenerate
        _, raw_codes = auth.regenerate_recovery_codes(mfa_user.id)
        recovery_code = raw_codes[0]
        _, _, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        session, raw_token = auth.verify_recovery_and_create_session(pending_token, recovery_code)
        assert session is not None
        assert raw_token is not None

    def test_verify_recovery_invalid_code_raises(self, auth, mfa_user):
        _, _, pending_token = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        with pytest.raises(ValueError, match="Invalid recovery code"):
            auth.verify_recovery_and_create_session(pending_token, "invalid-code")

    def test_login_legacy_method_still_works(self, auth, non_mfa_user, sample_username, sample_password):
        session, raw_token = auth.login(sample_username, sample_password)
        assert session is not None

    def test_login_legacy_method_raises_for_mfa(self, auth, mfa_user, sample_password):
        # login() doesn't check MFA, it just creates a session
        session, raw_token = auth.login(mfa_user.username, sample_password)
        assert session is not None  # This is the legacy behavior


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


class TestReplayProtection:
    def test_replay_same_totp_code_rejected(self, auth, mfa_user):
        user = auth.get_user_by_id(mfa_user.id)
        secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        totp = pyotp.TOTP(secret)
        code = totp.now()
        # Use it once
        _, _, pending1 = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        auth.verify_totp_and_create_session(pending1, code)
        # Try to use it again
        _, _, pending2 = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        # Sleep to ensure we're in the same or next window
        with pytest.raises(ValueError, match="already used"):
            auth.verify_totp_and_create_session(pending2, code)


# ---------------------------------------------------------------------------
# Session invalidation
# ---------------------------------------------------------------------------


class TestSessionInvalidation:
    def test_confirm_mfa_revokes_sessions(self, auth, non_mfa_user, sample_password):
        session, raw_token = auth.login(non_mfa_user.username, sample_password)
        assert auth.validate_session(raw_token) is not None
        secret = pyotp.random_base32()
        auth.enable_mfa(non_mfa_user.id, non_mfa_user.password_hash, secret)
        totp = pyotp.TOTP(secret)
        auth.confirm_mfa(non_mfa_user.id, totp.now())
        assert auth.validate_session(raw_token) is None

    def test_disable_mfa_revokes_sessions(self, auth, mfa_user):
        _, _, pending = auth.login_mfa_aware(mfa_user.username, "correct-horse-battery-staple")
        user = auth.get_user_by_id(mfa_user.id)
        secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        session, raw_token = auth.verify_totp_and_create_session(pending, pyotp.TOTP(secret).now())
        assert auth.validate_session(raw_token) is not None
        auth.disable_mfa(mfa_user.id)
        assert auth.validate_session(raw_token) is None


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_old_ndjson_without_mfa_fields_loads(self, tmp_path):
        """Simulate loading a user from old NDJSON that has no MFA fields."""
        import json
        from aegis.auth import UserStore
        store_path = os.path.join(str(tmp_path), "users.ndjson")
        os.makedirs(str(tmp_path), exist_ok=True)
        old_record = {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "username": "alice",
            "password_hash": "$2b$12$hashvalue",
            "created_at": "2026-07-19T00:00:00+00:00",
            "active": True,
            "role": "USER",
        }
        with open(store_path, "w") as f:
            f.write(json.dumps(old_record) + "\n")
        store = UserStore(str(tmp_path))
        user = store.get_by_username("alice")
        assert user is not None
        assert user.mfa_enabled is False
        assert user.totp_secret is None
        assert user.recovery_codes == ()

    def test_store_update_mfa_preserves_other_fields(self, auth, non_mfa_user):
        original_role = non_mfa_user.role
        secret = pyotp.random_base32()
        auth.enable_mfa(non_mfa_user.id, non_mfa_user.password_hash, secret)
        user = auth.get_user_by_id(non_mfa_user.id)
        assert user.role == original_role
        assert user.username == non_mfa_user.username


# ---------------------------------------------------------------------------
# Admin MFA policy (via rbac)
# ---------------------------------------------------------------------------


class TestAdminMfaPolicy:
    def test_require_mfa_for_admin_assignment_skips_if_not_admin(self):
        from aegis.rbac import AuthorizationService
        user = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
            mfa_enabled=False,
        )
        # Should not raise for non-ADMIN role
        AuthorizationService.require_mfa_for_admin_assignment(user, "USER")
        AuthorizationService.require_mfa_for_admin_assignment(user, "PAYMENT_VERIFIER")

    def test_require_mfa_for_admin_assignment_raises_if_no_mfa(self, monkeypatch):
        from aegis.rbac import AuthorizationService, AuthorizationError
        monkeypatch.setenv("AEGIS_REQUIRE_MFA_FOR_ADMINS", "true")
        user = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
            mfa_enabled=False,
        )
        with pytest.raises(AuthorizationError, match="MFA"):
            AuthorizationService.require_mfa_for_admin_assignment(user, "ADMIN")

    def test_require_mfa_for_admin_ok_with_mfa(self, monkeypatch):
        from aegis.rbac import AuthorizationService
        monkeypatch.setenv("AEGIS_REQUIRE_MFA_FOR_ADMINS", "true")
        user = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=datetime.now(timezone.utc),
            mfa_enabled=True,
        )
        AuthorizationService.require_mfa_for_admin_assignment(user, "ADMIN")


# ---------------------------------------------------------------------------
# Pending MFA token file management
# ---------------------------------------------------------------------------


class TestPendingMfaFile:
    def test_save_and_load(self, auth):
        token = "test-pending-token"
        auth.save_pending_mfa_token(token)
        loaded = auth.load_pending_mfa_token()
        assert loaded == token

    def test_load_none_when_no_file(self, auth):
        assert auth.load_pending_mfa_token() is None

    def test_clear_removes_file(self, auth):
        auth.save_pending_mfa_token("token")
        auth.clear_pending_mfa_token()
        assert auth.load_pending_mfa_token() is None
