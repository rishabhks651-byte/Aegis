"""Centralised configuration for Aegis.

All environment-variable configuration should be read through this
module so there is a single source of truth for every setting.
"""

from __future__ import annotations

import os
import platform


def _default_data_dir() -> str:
    """Return the platform-appropriate default data directory."""
    system = platform.system()
    if system == "Windows":
        return os.path.join(
            os.environ.get("APPDATA", os.path.expanduser("~")), "Aegis"
        )
    if system == "Darwin":
        return os.path.join(
            os.path.expanduser("~"), "Library", "Application Support", "Aegis"
        )
    return os.path.join(os.path.expanduser("~"), ".aegis")


def get_data_dir(override: str | None = None) -> str:
    """Return the effective data directory.

    Priority:
        1. *override* argument (CLI --data-dir flag)
        2. ``AEGIS_DATA_DIR`` environment variable
        3. Platform-appropriate default
    """
    if override:
        return override
    return os.environ.get("AEGIS_DATA_DIR", _default_data_dir())


def is_dev_mode() -> bool:
    """Return True when ``AEGIS_ENV`` is ``dev`` or ``development``."""
    return os.environ.get("AEGIS_ENV", "").lower() in ("dev", "development")


def get_storage_backend() -> str:
    """Return the storage backend identifier.

    Validates against known backends.  Falls back to ``"file"``.
    """
    raw = os.environ.get("AEGIS_STORAGE_BACKEND", "file").strip().lower()
    if raw not in ("file", "database"):
        raw = "file"
    return raw


def get_database_url(data_dir: str) -> str:
    """Return the resolved database URL.

    If the default relative path is used, it is resolved under *data_dir*.
    """
    url = os.environ.get("AEGIS_DATABASE_URL", "sqlite:///aegis.db").strip()
    if url == "sqlite:///aegis.db":
        db_path = os.path.join(data_dir, "aegis.db")
        url = f"sqlite:///{db_path}"
    return url


def get_cors_origins(raw: str | None = None) -> list[str] | None:
    """Parse CORS origins from a comma-separated string or ``AEGIS_CORS_ORIGINS``."""
    val = raw or os.environ.get("AEGIS_CORS_ORIGINS", "")
    if val:
        return [o.strip() for o in val.split(",") if o.strip()]
    return None


def get_upi_id() -> str:
    """Return the configured UPI ID."""
    return os.environ.get("AEGIS_UPI_ID", "8882781255@ptsbi")


def get_env_var(name: str, default: str = "") -> str:
    """Safely read an env var with a default."""
    return os.environ.get(name, default).strip()


def get_require_mfa_for_admins() -> bool:
    """Return True when ADMIN users must have MFA enabled."""
    val = os.environ.get("AEGIS_REQUIRE_MFA_FOR_ADMINS", "").strip().lower()
    return val in ("1", "true", "yes")
