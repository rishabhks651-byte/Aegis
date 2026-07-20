"""Tests for the authentication module."""

import os
import json
from datetime import datetime, timezone, timedelta
from dataclasses import FrozenInstanceError

import pytest

from aegis.auth import (
    User,
    Session,
    hash_password,
    verify_password,
    create_session_token,
    UserStore,
    SessionStore,
    Authenticator,
    _validate_username,
    _validate_password_strength,
    _SESSION_TTL_HOURS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_store(tmp_path):
    """Return a UserStore backed by a temporary directory."""
    return UserStore(str(tmp_path))


@pytest.fixture
def tmp_session_store(tmp_path):
    return SessionStore(str(tmp_path))


@pytest.fixture
def auth(tmp_path):
    """Return an Authenticator backed by a temporary directory."""
    return Authenticator(str(tmp_path))


@pytest.fixture
def sample_password():
    return "correct-horse-battery-staple"


@pytest.fixture
def sample_username():
    return "alice"


# ---------------------------------------------------------------------------
# Username & password validation
# ---------------------------------------------------------------------------


class TestUsernameValidation:
    def test_valid_usernames(self) -> None:
        for name in ["alice", "bob_1", "dev-user", "a" * 32, "ABC123"]:
            _validate_username(name)

    def test_too_short(self) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            _validate_username("ab")

    def test_too_long(self) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            _validate_username("a" * 33)

    def test_space_not_allowed(self) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            _validate_username("alice bob")

    def test_dot_not_allowed(self) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            _validate_username("alice.bob")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            _validate_username("")


class TestPasswordValidation:
    def test_long_enough(self) -> None:
        _validate_password_strength("12345678")

    def test_too_short(self) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            _validate_password_strength("1234567")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            _validate_password_strength("")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


class TestHashPassword:
    def test_hash_not_plaintext(self) -> None:
        h = hash_password("secret")
        assert "secret" not in h

    def test_starts_with_bcrypt_prefix(self) -> None:
        h = hash_password("secret")
        assert h.startswith("$2b$") or h.startswith("$2a$")

    def test_same_password_different_hash(self) -> None:
        h1 = hash_password("secret")
        h2 = hash_password("secret")
        assert h1 != h2


class TestVerifyPassword:
    def test_correct_password(self) -> None:
        h = hash_password("my-password")
        assert verify_password("my-password", h) is True

    def test_wrong_password(self) -> None:
        h = hash_password("my-password")
        assert verify_password("wrong-password", h) is False

    def test_empty_password_fails(self) -> None:
        h = hash_password("my-password")
        assert verify_password("", h) is False

    def test_invalid_hash_returns_false(self) -> None:
        assert verify_password("x", "$2b$12$invalidhash...") is False


# ---------------------------------------------------------------------------
# Session token generation
# ---------------------------------------------------------------------------


class TestSessionToken:
    def test_token_is_string(self) -> None:
        raw, h = create_session_token()
        assert isinstance(raw, str)
        assert len(raw) > 0

    def test_token_has_sufficient_length(self) -> None:
        raw, _ = create_session_token()
        assert len(raw) >= 32

    def test_hash_differs_from_raw(self) -> None:
        raw, h = create_session_token()
        assert h != raw

    def test_hash_is_sha256(self) -> None:
        raw, h = create_session_token()
        assert len(h) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in h)

    def test_consecutive_tokens_differ(self) -> None:
        raw1, _ = create_session_token()
        raw2, _ = create_session_token()
        assert raw1 != raw2


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------


class TestUserModel:
    def test_create_valid(self) -> None:
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="$2b$12$abcdefghijklmnopqrstuv",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
        assert u.username == "alice"
        assert u.active is True

    def test_default_active(self) -> None:
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="bob",
            password_hash="hash",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
        assert u.active is True

    def test_explicit_inactive(self) -> None:
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="bob",
            password_hash="hash",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
            active=False,
        )
        assert u.active is False

    def test_naive_datetime_raises(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            User(
                id="550e8400-e29b-41d4-a716-446655440000",
                username="alice",
                password_hash="hash",
                created_at=datetime(2026, 7, 19),
            )

    def test_frozen(self) -> None:
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="hash",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
        with pytest.raises(FrozenInstanceError):
            u.username = "bob"  # type: ignore[misc]

    def test_to_dict(self) -> None:
        u = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="$2b$12$hashvalue",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
        d = u.to_dict()
        assert d["username"] == "alice"
        assert d["password_hash"] == "$2b$12$hashvalue"
        assert d["active"] is True
        assert d["created_at"].endswith("+00:00")

    def test_from_dict_round_trip(self) -> None:
        original = User(
            id="550e8400-e29b-41d4-a716-446655440000",
            username="alice",
            password_hash="$2b$12$hashvalue",
            created_at=datetime(2026, 7, 19, tzinfo=timezone.utc),
            active=False,
        )
        restored = User.from_dict(original.to_dict())
        assert restored == original


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------


class TestSessionModel:
    def test_create_valid(self) -> None:
        now = datetime(2026, 7, 19, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc123",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
        assert s.revoked is False

    def test_is_expired_true(self) -> None:
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2020, 1, 2, tzinfo=timezone.utc),
        )
        assert s.is_expired() is True

    def test_is_expired_false(self) -> None:
        far_future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=far_future,
            expires_at=far_future + timedelta(hours=1),
        )
        assert s.is_expired() is False

    def test_is_valid_valid(self) -> None:
        far_future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=far_future,
            expires_at=far_future + timedelta(hours=1),
        )
        assert s.is_valid() is True

    def test_is_valid_revoked(self) -> None:
        far_future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=far_future,
            expires_at=far_future + timedelta(hours=1),
            revoked=True,
        )
        assert s.is_valid() is False

    def test_is_valid_expired(self) -> None:
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2020, 1, 2, tzinfo=timezone.utc),
        )
        assert s.is_valid() is False

    def test_frozen(self) -> None:
        now = datetime(2026, 7, 19, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="abc",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
        with pytest.raises(FrozenInstanceError):
            s.revoked = True  # type: ignore[misc]

    def test_to_dict(self) -> None:
        now = datetime(2026, 7, 19, tzinfo=timezone.utc)
        s = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="sha256hash",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=now,
            expires_at=now + timedelta(hours=24),
            revoked=True,
        )
        d = s.to_dict()
        assert d["token_hash"] == "sha256hash"
        assert d["revoked"] is True

    def test_from_dict_round_trip(self) -> None:
        now = datetime(2026, 7, 19, tzinfo=timezone.utc)
        original = Session(
            session_id="550e8400-e29b-41d4-a716-446655440000",
            token_hash="sha256hash",
            user_id="660e8400-e29b-41d4-a716-446655440001",
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
        restored = Session.from_dict(original.to_dict())
        assert restored == original


# ---------------------------------------------------------------------------
# UserStore
# ---------------------------------------------------------------------------


class TestUserStore:
    def test_create_and_get_by_username(self, tmp_store, sample_password) -> None:
        user = tmp_store.create("alice", sample_password)
        found = tmp_store.get_by_username("alice")
        assert found is not None
        assert found.id == user.id
        assert found.username == "alice"

    def test_create_and_get_by_id(self, tmp_store, sample_password) -> None:
        user = tmp_store.create("bob", sample_password)
        found = tmp_store.get_by_id(user.id)
        assert found is not None
        assert found.username == "bob"

    def test_duplicate_username_raises(self, tmp_store, sample_password) -> None:
        tmp_store.create("alice", sample_password)
        with pytest.raises(ValueError, match="already exists"):
            tmp_store.create("alice", sample_password)

    def test_get_nonexistent_user(self, tmp_store) -> None:
        assert tmp_store.get_by_username("nobody") is None
        assert tmp_store.get_by_id("550e8400-e29b-41d4-a716-446655440000") is None

    def test_password_not_stored_in_plaintext(self, tmp_store, sample_password) -> None:
        user = tmp_store.create("alice", sample_password)
        assert sample_password not in user.password_hash

    def test_deactivate(self, tmp_store, sample_password) -> None:
        user = tmp_store.create("alice", sample_password)
        tmp_store.deactivate(user.id)
        deactivated = tmp_store.get_by_id(user.id)
        assert deactivated is not None
        assert deactivated.active is False

    def test_deactivate_nonexistent_raises(self, tmp_store) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_store.deactivate("550e8400-e29b-41d4-a716-446655440000")

    def test_persistence_across_instances(self, tmp_path, sample_password) -> None:
        store1 = UserStore(str(tmp_path))
        store1.create("alice", sample_password)

        store2 = UserStore(str(tmp_path))
        found = store2.get_by_username("alice")
        assert found is not None

    def test_latest_record_wins_on_id(self, tmp_store, sample_password) -> None:
        user = tmp_store.create("alice", sample_password)
        tmp_store.deactivate(user.id)
        found = tmp_store.get_by_id(user.id)
        assert found is not None
        assert found.active is False

    def test_invalid_username_raises_in_store(self, tmp_store, sample_password) -> None:
        with pytest.raises(ValueError, match="Username must be"):
            tmp_store.create("ab", sample_password)

    def test_weak_password_raises_in_store(self, tmp_store) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            tmp_store.create("alice", "1234567")


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------


class TestSessionStore:
    def test_create_and_get_by_token(self, tmp_session_store) -> None:
        session, raw_token = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        found = tmp_session_store.get_by_token(raw_token)
        assert found is not None
        assert found.session_id == session.session_id

    def test_get_by_id(self, tmp_session_store) -> None:
        session, _ = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        found = tmp_session_store.get_by_id(session.session_id)
        assert found is not None

    def test_get_by_unknown_token(self, tmp_session_store) -> None:
        assert tmp_session_store.get_by_token("invalid-token") is None

    def test_revoke(self, tmp_session_store) -> None:
        session, raw_token = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        tmp_session_store.revoke(session.session_id)
        revoked = tmp_session_store.get_by_token(raw_token)
        assert revoked is not None
        assert revoked.revoked is True

    def test_revoke_by_token(self, tmp_session_store) -> None:
        _, raw_token = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        tmp_session_store.revoke_by_token(raw_token)
        found = tmp_session_store.get_by_token(raw_token)
        assert found is not None
        assert found.revoked is True

    def test_revoke_nonexistent_raises(self, tmp_session_store) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_session_store.revoke("550e8400-e29b-41d4-a716-446655440000")

    def test_revoke_by_token_nonexistent_raises(self, tmp_session_store) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_session_store.revoke_by_token("bad-token")

    def test_persistence_across_instances(self, tmp_path) -> None:
        store1 = SessionStore(str(tmp_path))
        session, raw_token = store1.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )

        store2 = SessionStore(str(tmp_path))
        found = store2.get_by_token(raw_token)
        assert found is not None
        assert found.session_id == session.session_id

    def test_stores_hash_not_raw(self, tmp_session_store) -> None:
        session, raw_token = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        assert raw_token != session.token_hash
        assert raw_token not in session.to_dict().values()

    def test_default_ttl(self, tmp_session_store) -> None:
        session, _ = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        delta = session.expires_at - session.created_at
        assert delta == timedelta(hours=_SESSION_TTL_HOURS)


# ---------------------------------------------------------------------------
# Authenticator (high-level flow)
# ---------------------------------------------------------------------------


class TestAuthenticator:
    def test_register_and_login(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        session, raw_token = auth.login("alice", sample_password)
        assert session is not None
        assert raw_token is not None

    def test_register_duplicate_raises(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        with pytest.raises(ValueError, match="already exists"):
            auth.register("alice", sample_password)

    def test_login_wrong_password(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        with pytest.raises(ValueError, match="Invalid password"):
            auth.login("alice", "wrong-password")

    def test_login_nonexistent_user(self, auth) -> None:
        with pytest.raises(ValueError, match="not found"):
            auth.login("nobody", "password123")

    def test_validate_session_valid(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        user = auth.validate_session(raw_token)
        assert user is not None
        assert user.username == "alice"

    def test_validate_session_invalid_token(self, auth) -> None:
        user = auth.validate_session("bad-token")
        assert user is None

    def test_validate_session_empty_token(self, auth) -> None:
        user = auth.validate_session("")
        assert user is None

    def test_validate_session_after_logout(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.logout(raw_token)
        user = auth.validate_session(raw_token)
        assert user is None

    def test_logout_revokes_session(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.logout(raw_token)
        session = auth.get_session_by_token(raw_token)
        assert session is not None
        assert session.revoked is True

    def test_logout_twice_raises(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.logout(raw_token)
        with pytest.raises(ValueError):
            auth.logout(raw_token)

    def test_deactivated_user_cannot_login(self, auth, sample_password) -> None:
        user = auth.register("alice", sample_password)
        auth.user_store.deactivate(user.id)
        with pytest.raises(ValueError, match="deactivated"):
            auth.login("alice", sample_password)

    def test_get_user_by_id(self, auth, sample_password) -> None:
        user = auth.register("alice", sample_password)
        found = auth.get_user_by_id(user.id)
        assert found is not None
        assert found.username == "alice"

    def test_get_user_by_id_nonexistent(self, auth) -> None:
        assert auth.get_user_by_id("550e8400-e29b-41d4-a716-446655440000") is None


# ---------------------------------------------------------------------------
# Session token file management
# ---------------------------------------------------------------------------


class TestSessionFile:
    def test_save_and_load(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.save_session_token(raw_token)
        loaded = auth.load_session_token()
        assert loaded == raw_token

    def test_load_none_when_no_file(self, auth) -> None:
        assert auth.load_session_token() is None

    def test_clear_removes_file(self, auth, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.save_session_token(raw_token)
        auth.clear_session_token()
        assert auth.load_session_token() is None

    def test_clear_when_no_file(self, auth) -> None:
        auth.clear_session_token()
        assert auth.load_session_token() is None

    def test_file_path_under_data_dir(self, tmp_path) -> None:
        a = Authenticator(str(tmp_path))
        p = a._session_file_path()
        assert os.path.dirname(p) == str(tmp_path)
        assert os.path.basename(p) == "session"


# ---------------------------------------------------------------------------
# Integration: full flow via CLI handlers
# ---------------------------------------------------------------------------


class TestCliAuthFlow:
    """Test the high-level flow through CLI handler functions."""

    def test_full_flow(self, auth, sample_password) -> None:
        # register
        user = auth.register("alice", sample_password)
        assert user.username == "alice"

        # login
        session, raw_token = auth.login("alice", sample_password)
        assert session is not None
        auth.save_session_token(raw_token)

        # whoami (validate)
        loaded_token = auth.load_session_token()
        assert loaded_token == raw_token
        validated = auth.validate_session(loaded_token)
        assert validated is not None
        assert validated.username == "alice"

        # logout
        auth.logout(raw_token)
        auth.clear_session_token()
        assert auth.load_session_token() is None
        assert auth.validate_session(raw_token) is None


# ---------------------------------------------------------------------------
# Security invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_password_hash_not_reversible(self, sample_password) -> None:
        h = hash_password(sample_password)
        assert sample_password not in h
        assert "correct" not in h
        assert "horse" not in h

    def test_session_token_high_entropy(self) -> None:
        import math
        raw, _ = create_session_token()
        # token_urlsafe(32) = 32 bytes = 256 bits of entropy
        # Base64 encoded = ceil(32*8/6) = 43 chars
        assert len(raw) == 43
        # Each char is one of 64 values → log2(64) = 6 bits per char
        # Total entropy = 43 * 6 = 258 bits (slightly more than 256 due to padding)
        entropy_bits = len(raw) * math.log2(64)
        assert entropy_bits >= 256

    def test_session_does_not_expose_raw_token(self, tmp_session_store) -> None:
        _, raw_token = tmp_session_store.create(
            "550e8400-e29b-41d4-a716-446655440000"
        )
        records_path = tmp_session_store._path
        with open(records_path, "r") as f:
            content = f.read()
        assert raw_token not in content

    def test_bcrypt_rounds_are_reasonable(self) -> None:
        """Bcrypt with 12 rounds should take ~0.25s, not instant (no 4 rounds)."""
        import time
        start = time.time()
        hash_password("benchmark")
        elapsed = time.time() - start
        # With rounds=12, should be > 0.05s on any modern hardware
        assert elapsed >= 0.01, "Bcrypt rounds may be too low"
