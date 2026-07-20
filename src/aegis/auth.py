"""Local user authentication for Aegis.

Provides user registration, password hashing (bcrypt), session
management, and file-based storage for users and sessions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
_MIN_PASSWORD_LENGTH = 8
_SESSION_TTL_HOURS = 24


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_username(value: str) -> None:
    if not _USERNAME_RE.match(value):
        raise ValueError(
            f"Username must be 3-32 chars, letters/digits/underscore/hyphen: "
            f"{value!r}"
        )


def _validate_password_strength(password: str) -> None:
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters"
        )


def _validate_tz_aware(dt: datetime, field_name: str) -> None:
    if dt.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")


def _normalize_dt(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc)


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class User:
    """A registered Aegis user (human operator)."""

    id: str
    username: str
    password_hash: str
    created_at: datetime
    active: bool = True
    role: str = "USER"

    def __post_init__(self) -> None:
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "password_hash": self.password_hash,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> User:
        return cls(
            id=data["id"],
            username=data["username"],
            password_hash=data["password_hash"],
            created_at=_parse_iso(data["created_at"]),
            active=data.get("active", True),
            role=data.get("role", "USER"),
        )


@dataclass(frozen=True)
class Session:
    """An authenticated user session."""

    session_id: str
    token_hash: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False

    def __post_init__(self) -> None:
        _validate_tz_aware(self.created_at, "created_at")
        _validate_tz_aware(self.expires_at, "expires_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))
        object.__setattr__(self, "expires_at", _normalize_dt(self.expires_at))

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "token_hash": self.token_hash,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        return cls(
            session_id=data["session_id"],
            token_hash=data["token_hash"],
            user_id=data["user_id"],
            created_at=_parse_iso(data["created_at"]),
            expires_at=_parse_iso(data["expires_at"]),
            revoked=data.get("revoked", False),
        )


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password using bcrypt with a random salt (12 rounds)."""
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash. Returns True if valid."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Session token generation
# ---------------------------------------------------------------------------

def create_session_token() -> tuple[str, str]:
    """Generate a cryptographically secure session token.

    Returns:
        (raw_token, token_hash)
        Store the hash, give the raw token to the caller (user).
    """
    raw = secrets.token_urlsafe(32)
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, h


# ---------------------------------------------------------------------------
# NDJSON helpers
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
    records: list[dict[str, Any]], field: str = "id"
) -> dict[str, dict[str, Any]]:
    """Latest record for each value of *field* wins (append-only dedup)."""
    result: dict[str, dict[str, Any]] = {}
    for r in records:
        result[r[field]] = r
    return result


# ---------------------------------------------------------------------------
# User store
# ---------------------------------------------------------------------------

class UserStore:
    """Append-only NDJSON-backed user storage."""

    def __init__(self, storage_dir: str) -> None:
        self._path = os.path.join(storage_dir, "users.ndjson")

    def create(self, username: str, password: str) -> User:
        _validate_username(username)
        _validate_password_strength(password)

        existing = self.get_by_username(username)
        if existing is not None:
            raise ValueError(f"User {username!r} already exists")

        user = User(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=hash_password(password),
            created_at=datetime.now(timezone.utc),
        )
        _append_ndjson(self._path, user.to_dict())
        return user

    def get_by_username(self, username: str) -> User | None:
        for r in self._list_raw():
            if r["username"] == username:
                return User.from_dict(r)
        return None

    def get_by_id(self, user_id: str) -> User | None:
        for r in self._list_raw():
            if r["id"] == user_id:
                return User.from_dict(r)
        return None

    def deactivate(self, user_id: str) -> None:
        user = self.get_by_id(user_id)
        if user is None:
            raise ValueError(f"User {user_id!r} not found")
        deactivated = User(
            id=user.id,
            username=user.username,
            password_hash=user.password_hash,
            created_at=user.created_at,
            active=False,
            role=user.role,
        )
        _append_ndjson(self._path, deactivated.to_dict())

    def set_role(self, user_id: str, role: str) -> User:
        """Update a user's role (append-only pattern).

        Caller is responsible for authorization.  Raises ``ValueError``
        if the user is not found or the role is invalid.
        """
        from aegis.rbac import AuthorizationService

        user = self.get_by_id(user_id)
        if user is None:
            raise ValueError(f"User {user_id!r} not found")
        AuthorizationService.validate_role(role)

        updated = User(
            id=user.id,
            username=user.username,
            password_hash=user.password_hash,
            created_at=user.created_at,
            active=user.active,
            role=role,
        )
        _append_ndjson(self._path, updated.to_dict())
        return updated

    def _list_raw(self) -> list[dict[str, Any]]:
        records = _read_ndjson(self._path)
        deduped = _dedup_by_field(records, "id")
        return list(deduped.values())


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

class SessionStore:
    """Append-only NDJSON-backed session storage."""

    def __init__(self, storage_dir: str) -> None:
        self._path = os.path.join(storage_dir, "sessions.ndjson")

    def create(self, user_id: str) -> tuple[Session, str]:
        now = datetime.now(timezone.utc)
        raw_token, token_hash = create_session_token()

        session = Session(
            session_id=str(uuid.uuid4()),
            token_hash=token_hash,
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(hours=_SESSION_TTL_HOURS),
        )
        _append_ndjson(self._path, session.to_dict())
        return session, raw_token

    def get_by_token(self, raw_token: str) -> Session | None:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        for s in self._list_raw():
            if s["token_hash"] == token_hash:
                return Session.from_dict(s)
        return None

    def get_by_id(self, session_id: str) -> Session | None:
        for s in self._list_raw():
            if s["session_id"] == session_id:
                return Session.from_dict(s)
        return None

    def revoke(self, session_id: str) -> None:
        session = self.get_by_id(session_id)
        if session is None:
            raise ValueError(f"Session {session_id!r} not found")
        if session.revoked:
            raise ValueError(f"Session {session_id!r} is already revoked")
        revoked = Session(
            session_id=session.session_id,
            token_hash=session.token_hash,
            user_id=session.user_id,
            created_at=session.created_at,
            expires_at=session.expires_at,
            revoked=True,
        )
        _append_ndjson(self._path, revoked.to_dict())

    def revoke_by_token(self, raw_token: str) -> None:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        for s in self._list_raw():
            if s["token_hash"] == token_hash:
                self.revoke(s["session_id"])
                return
        raise ValueError("Session not found")

    def _list_raw(self) -> list[dict[str, Any]]:
        records = _read_ndjson(self._path)
        deduped = _dedup_by_field(records, "session_id")
        return list(deduped.values())


# ---------------------------------------------------------------------------
# Authenticator (high-level API)
# ---------------------------------------------------------------------------

class Authenticator:
    """High-level authentication API for CLI and other consumers."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        self.user_store = UserStore(data_dir)
        self.session_store = SessionStore(data_dir)

    # -- Registration / login / logout ---------------------------------------

    def register(self, username: str, password: str) -> User:
        """Create a new user account."""
        return self.user_store.create(username, password)

    def login(self, username: str, password: str) -> tuple[Session, str]:
        """Authenticate a user and create a session.

        Returns:
            (Session, raw_token). The raw_token must be saved by the caller
            and presented on subsequent requests.

        Raises:
            ValueError: user not found or wrong password.
        """
        user = self.user_store.get_by_username(username)
        if user is None:
            raise ValueError(f"User {username!r} not found")
        if not user.active:
            raise ValueError(f"User {username!r} is deactivated")
        if not verify_password(password, user.password_hash):
            raise ValueError("Invalid password")
        session, raw_token = self.session_store.create(user.id)
        return session, raw_token

    def logout(self, raw_token: str) -> None:
        """Revoke the session identified by the raw token."""
        self.session_store.revoke_by_token(raw_token)

    # -- Session validation --------------------------------------------------

    def get_session_by_token(self, raw_token: str) -> Session | None:
        return self.session_store.get_by_token(raw_token)

    def get_user_by_id(self, user_id: str) -> User | None:
        return self.user_store.get_by_id(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        return self.user_store.get_by_username(username)

    def set_user_role(self, user_id: str, role: str) -> User:
        """Set a user's role.  Caller must authorize first."""
        return self.user_store.set_role(user_id, role)

    def validate_session(self, raw_token: str) -> User | None:
        """Return the User if raw_token corresponds to a valid session."""
        if not raw_token:
            return None
        session = self.session_store.get_by_token(raw_token)
        if session is None:
            return None
        if not session.is_valid():
            return None
        return self.user_store.get_by_id(session.user_id)

    # -- Session token file management ---------------------------------------

    def _session_file_path(self) -> str:
        return os.path.join(self.data_dir, "session")

    def save_session_token(self, raw_token: str) -> None:
        path = self._session_file_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(raw_token)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def load_session_token(self) -> str | None:
        path = self._session_file_path()
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or None

    def clear_session_token(self) -> None:
        path = self._session_file_path()
        if os.path.exists(path):
            os.remove(path)
