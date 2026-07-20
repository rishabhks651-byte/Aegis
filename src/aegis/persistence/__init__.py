"""Persistence layer for Aegis — database and NDJSON backends."""

from __future__ import annotations

import os

STORAGE_BACKEND: str = os.environ.get("AEGIS_STORAGE_BACKEND", "file").strip().lower()
DATABASE_URL: str = os.environ.get("AEGIS_DATABASE_URL", "sqlite:///aegis.db").strip()
"""PostgreSQL example: postgresql://user:pass@localhost/aegis"""
