"""Local user authentication for Aegis.

Provides user registration, password hashing (bcrypt), session
management, MFA (TOTP) support, and file-based storage.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import pyotp
from cryptography.fernet import Fernet


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
    mfa_enabled: bool = False
    totp_secret: str | None = None
    totp_confirmed_at: datetime | None = None
    last_used_totp_step: int | None = None
    recovery_codes: tuple[str, ...] = ()
    recovery_codes_generated_at: datetime | None = None

    def __post_init__(self) -> None:
        _validate_tz_aware(self.created_at, "created_at")
        object.__setattr__(self, "created_at", _normalize_dt(self.created_at))
        if self.totp_confirmed_at is not None:
            _validate_tz_aware(self.totp_confirmed_at, "totp_confirmed_at")
            object.__setattr__(self, "totp_confirmed_at", _normalize_dt(self.totp_confirmed_at))
        if self.recovery_codes_generated_at is not None:
            _validate_tz_aware(self.recovery_codes_generated_at, "recovery_codes_generated_at")
            object.__setattr__(self, "recovery_codes_generated_at", _normalize_dt(self.recovery_codes_generated_at))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "username": self.username,
            "password_hash": self.password_hash,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
            "role": self.role,
            "mfa_enabled": self.mfa_enabled,
            "totp_secret": self.totp_secret,
            "totp_confirmed_at": self.totp_confirmed_at.isoformat() if self.totp_confirmed_at else None,
            "last_used_totp_step": self.last_used_totp_step,
            "recovery_codes": list(self.recovery_codes),
            "recovery_codes_generated_at": self.recovery_codes_generated_at.isoformat() if self.recovery_codes_generated_at else None,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> User:
        totp_confirmed_at = _parse_iso(data["totp_confirmed_at"]) if data.get("totp_confirmed_at") else None
        recovery_codes_generated_at = _parse_iso(data["recovery_codes_generated_at"]) if data.get("recovery_codes_generated_at") else None
        return cls(
            id=data["id"],
            username=data["username"],
            password_hash=data["password_hash"],
            created_at=_parse_iso(data["created_at"]),
            active=data.get("active", True),
            role=data.get("role", "USER"),
            mfa_enabled=data.get("mfa_enabled", False),
            totp_secret=data.get("totp_secret"),
            totp_confirmed_at=totp_confirmed_at,
            last_used_totp_step=data.get("last_used_totp_step"),
            recovery_codes=tuple(data.get("recovery_codes", [])),
            recovery_codes_generated_at=recovery_codes_generated_at,
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
# TOTP secret encryption / decryption
# ---------------------------------------------------------------------------

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_totp_key(password_hash: str) -> bytes:
    """Derive a 32-byte Fernet key from the user's *password_hash* using scrypt.

    The derived key is deterministic for a given password_hash, which is
    stable unless the user changes their password (at which point any
    existing TOTP secret becomes unrecoverable — this is by design).
    """
    salt = b"aegis-totp-v1"
    raw = hashlib.scrypt(
        password_hash.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw)


def encrypt_totp_secret(secret: str, password_hash: str) -> str:
    """Encrypt *secret* with a key derived from *password_hash*.

    Returns a Fernet-encrypted token string.
    """
    key = _derive_totp_key(password_hash)
    f = Fernet(key)
    return f.encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(encrypted: str, password_hash: str) -> str:
    """Decrypt a Fernet-encrypted TOTP secret.

    Raises ``cryptography.fernet.InvalidToken`` if the key is wrong or
    data is corrupted.
    """
    key = _derive_totp_key(password_hash)
    f = Fernet(key)
    return f.decrypt(encrypted.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_BYTES = 10  # 10 bytes → 14 base64 chars (no padding)


def generate_recovery_codes(count: int = _RECOVERY_CODE_COUNT) -> list[str]:
    """Generate *count* cryptographically random recovery codes.

    Each code is a human-readable base64 string (no padding).
    """
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_urlsafe(_RECOVERY_CODE_BYTES)
        codes.append(raw)
    return codes


def _hash_recovery_code(code: str) -> str:
    """Return the SHA-256 hex digest of a recovery code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def hash_recovery_codes(codes: list[str]) -> list[str]:
    """Return a list of SHA-256 hashes for the given recovery codes."""
    return [_hash_recovery_code(c) for c in codes]


def verify_recovery_code(
    code: str, hashed_codes: tuple[str, ...]
) -> tuple[bool, tuple[str, ...]]:
    """Verify *code* against *hashed_codes*.

    Returns:
        (is_valid, remaining_hashed_codes)
        If valid, the consumed code's hash is removed from the tuple.
    """
    code_hash = _hash_recovery_code(code)
    remaining: list[str] = []
    found = False
    for h in hashed_codes:
        if not found and h == code_hash:
            found = True
        else:
            remaining.append(h)
    return found, tuple(remaining)


# ---------------------------------------------------------------------------
# Pending MFA session (pre-auth state)
# ---------------------------------------------------------------------------

_PENDING_MFA_TTL_SECONDS = 300  # 5 minutes


@dataclass
class PendingMfaSession:
    """A session awaiting MFA verification after password auth."""

    user_id: str
    password_hash: str
    created_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.created_at + timedelta(
            seconds=_PENDING_MFA_TTL_SECONDS
        )


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
            mfa_enabled=user.mfa_enabled,
            totp_secret=user.totp_secret,
            totp_confirmed_at=user.totp_confirmed_at,
            last_used_totp_step=user.last_used_totp_step,
            recovery_codes=user.recovery_codes,
            recovery_codes_generated_at=user.recovery_codes_generated_at,
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
            mfa_enabled=user.mfa_enabled,
            totp_secret=user.totp_secret,
            totp_confirmed_at=user.totp_confirmed_at,
            last_used_totp_step=user.last_used_totp_step,
            recovery_codes=user.recovery_codes,
            recovery_codes_generated_at=user.recovery_codes_generated_at,
        )
        _append_ndjson(self._path, updated.to_dict())
        return updated

    _UNSET = object()  # sentinel for "don't change this field"

    def update_mfa(
        self,
        user_id: str,
        *,
        mfa_enabled: bool | None = None,
        totp_secret: str | object = _UNSET,
        totp_confirmed_at: datetime | object = _UNSET,
        last_used_totp_step: int | object = _UNSET,
        recovery_codes: tuple[str, ...] | object = _UNSET,
        recovery_codes_generated_at: datetime | object = _UNSET,
    ) -> User:
        """Update MFA-related fields on a user (append-only pattern).

        Only fields passed as keyword arguments are changed; others retain
        their current values.  Pass a value of ``None`` to clear a field.
        """
        user = self.get_by_id(user_id)
        if user is None:
            raise ValueError(f"User {user_id!r} not found")

        new_mfa = mfa_enabled if mfa_enabled is not None else user.mfa_enabled
        new_secret = totp_secret if totp_secret is not self._UNSET else user.totp_secret
        new_confirmed = totp_confirmed_at if totp_confirmed_at is not self._UNSET else user.totp_confirmed_at
        new_step = last_used_totp_step if last_used_totp_step is not self._UNSET else user.last_used_totp_step
        new_codes = recovery_codes if recovery_codes is not self._UNSET else user.recovery_codes
        new_codes_gen = recovery_codes_generated_at if recovery_codes_generated_at is not self._UNSET else user.recovery_codes_generated_at

        updated = User(
            id=user.id,
            username=user.username,
            password_hash=user.password_hash,
            created_at=user.created_at,
            active=user.active,
            role=user.role,
            mfa_enabled=new_mfa,
            totp_secret=new_secret,
            totp_confirmed_at=new_confirmed,
            last_used_totp_step=new_step,
            recovery_codes=new_codes,
            recovery_codes_generated_at=new_codes_gen,
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

    def revoke_all_for_user(self, user_id: str) -> int:
        """Revoke all non-revoked sessions for *user_id*.

        Returns the number of sessions revoked.
        """
        count = 0
        for s in self._list_raw():
            if s["user_id"] == user_id and not s.get("revoked", False):
                self.revoke(s["session_id"])
                count += 1
        return count

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
        self._pending_mfa_store: dict[str, PendingMfaSession] = {}

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

    # -- Pending MFA session file management ----------------------------------

    def _pending_mfa_file_path(self) -> str:
        return os.path.join(self.data_dir, "pending_mfa")

    def save_pending_mfa_token(self, token: str) -> None:
        path = self._pending_mfa_file_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(token)

    def load_pending_mfa_token(self) -> str | None:
        path = self._pending_mfa_file_path()
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or None

    def clear_pending_mfa_token(self) -> None:
        path = self._pending_mfa_file_path()
        if os.path.exists(path):
            os.remove(path)

    # -- MFA-aware login ------------------------------------------------------

    def login_mfa_aware(
        self, username: str, password: str
    ) -> tuple[Session | None, str | None, str | None]:
        """Authenticate a user, supporting MFA.

        Returns:
            (session, raw_token, pending_mfa_token)
            If the user has MFA enabled, *session* and *raw_token* are None
            and *pending_mfa_token* is set (caller must verify via TOTP).
            Otherwise, *session* and *raw_token* are set as normal.

        Raises:
            ValueError: user not found, deactivated, or wrong password.
        """
        user = self.user_store.get_by_username(username)
        if user is None:
            raise ValueError(f"User {username!r} not found")
        if not user.active:
            raise ValueError(f"User {username!r} is deactivated")
        if not verify_password(password, user.password_hash):
            raise ValueError("Invalid password")

        if user.mfa_enabled:
            pending_token = secrets.token_urlsafe(32)
            pending = PendingMfaSession(
                user_id=user.id,
                password_hash=user.password_hash,
                created_at=datetime.now(timezone.utc),
            )
            self._pending_mfa_store[pending_token] = pending
            return None, None, pending_token

        session, raw_token = self.session_store.create(user.id)
        return session, raw_token, None

    def get_pending_mfa_session(self, token: str) -> PendingMfaSession | None:
        """Look up a pending MFA session by token, checking expiry."""
        pending = self._pending_mfa_store.get(token)
        if pending is None:
            return None
        if pending.is_expired():
            self._pending_mfa_store.pop(token, None)
            return None
        return pending

    def consume_pending_mfa_token(self, token: str) -> None:
        self._pending_mfa_store.pop(token, None)

    # -- TOTP verification ----------------------------------------------------

    def verify_totp_and_create_session(
        self, pending_token: str, totp_code: str
    ) -> tuple[Session, str]:
        """Verify a TOTP code and create a session.

        Raises:
            ValueError: invalid/expired pending token or wrong TOTP code.
        """
        pending = self.get_pending_mfa_session(pending_token)
        if pending is None:
            raise ValueError("Invalid or expired pending MFA token")
        self.consume_pending_mfa_token(pending_token)

        user = self.user_store.get_by_id(pending.user_id)
        if user is None or not user.active:
            raise ValueError("User not found or deactivated")
        if not user.mfa_enabled or not user.totp_secret:
            raise ValueError("MFA is not enabled for this user")

        try:
            secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        except Exception:
            raise ValueError("Could not decrypt TOTP secret")

        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            raise ValueError("Invalid TOTP code")

        # Replay protection: ensure step is strictly increasing
        now_step = int(datetime.now(timezone.utc).timestamp()) // 30
        if user.last_used_totp_step is not None and now_step <= user.last_used_totp_step:
            raise ValueError("TOTP code already used (replay detected)")

        # Update last used step
        self.user_store.update_mfa(
            user.id,
            last_used_totp_step=now_step,
        )

        session, raw_token = self.session_store.create(user.id)
        return session, raw_token

    def verify_recovery_and_create_session(
        self, pending_token: str, recovery_code: str
    ) -> tuple[Session, str]:
        """Verify a recovery code and create a session.

        Raises:
            ValueError: invalid/expired pending token or wrong recovery code.
        """
        pending = self.get_pending_mfa_session(pending_token)
        if pending is None:
            raise ValueError("Invalid or expired pending MFA token")
        self.consume_pending_mfa_token(pending_token)

        user = self.user_store.get_by_id(pending.user_id)
        if user is None or not user.active:
            raise ValueError("User not found or deactivated")
        if not user.mfa_enabled:
            raise ValueError("MFA is not enabled for this user")

        valid, remaining = verify_recovery_code(recovery_code, user.recovery_codes)
        if not valid:
            raise ValueError("Invalid recovery code")

        # Update remaining recovery codes
        self.user_store.update_mfa(
            user.id,
            recovery_codes=remaining,
            recovery_codes_generated_at=user.recovery_codes_generated_at,
        )

        session, raw_token = self.session_store.create(user.id)
        return session, raw_token

    # -- MFA setup / management -----------------------------------------------

    def generate_totp_secret(self, username: str) -> tuple[str, str]:
        """Generate a new TOTP secret and its provisioning URI.

        Returns:
            (secret, provisioning_uri)
        """
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Aegis",
        )
        return secret, uri

    def enable_mfa(
        self, user_id: str, password_hash: str, totp_secret: str
    ) -> User:
        """Encrypt and store the TOTP secret (MFA remains disabled until confirmed)."""
        encrypted = encrypt_totp_secret(totp_secret, password_hash)
        return self.user_store.update_mfa(
            user_id,
            totp_secret=encrypted,
        )

    def confirm_mfa(self, user_id: str, totp_code: str) -> User:
        """Confirm MFA setup by verifying a TOTP code, then enable MFA.

        Revokes all existing sessions so the user must re-login with MFA.
        """
        user = self.user_store.get_by_id(user_id)
        if user is None:
            raise ValueError(f"User {user_id!r} not found")
        if not user.totp_secret:
            raise ValueError("No TOTP secret stored. Call enable_mfa first.")

        try:
            secret = decrypt_totp_secret(user.totp_secret, user.password_hash)
        except Exception:
            raise ValueError("Could not decrypt TOTP secret")

        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            raise ValueError("Invalid TOTP code")

        # Revoke existing sessions — MFA state change invalidates them
        self.session_store.revoke_all_for_user(user_id)

        return self.user_store.update_mfa(
            user_id,
            mfa_enabled=True,
            totp_confirmed_at=datetime.now(timezone.utc),
        )

    def disable_mfa(self, user_id: str) -> User:
        """Disable MFA and clear all MFA fields.

        Revokes all existing sessions so the user must re-login.
        """
        self.session_store.revoke_all_for_user(user_id)
        return self.user_store.update_mfa(
            user_id,
            mfa_enabled=False,
            totp_secret=None,
            totp_confirmed_at=None,
            last_used_totp_step=None,
            recovery_codes=(),
            recovery_codes_generated_at=None,
        )

    def regenerate_recovery_codes(self, user_id: str) -> tuple[User, list[str]]:
        """Generate new recovery codes, hash them, and store.

        Returns:
            (updated_user, raw_codes) — caller must show *raw_codes* to the
            user exactly once.
        """
        raw_codes = generate_recovery_codes()
        hashed = hash_recovery_codes(raw_codes)
        user = self.user_store.update_mfa(
            user_id,
            recovery_codes=tuple(hashed),
            recovery_codes_generated_at=datetime.now(timezone.utc),
        )
        return user, raw_codes
