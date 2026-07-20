"""Sensitive-data redaction utilities."""

from __future__ import annotations


def redact_utr(utr: str, visible_chars: int = 4) -> str:
    """Redact a UTR, showing only the last *visible_chars* characters."""
    if len(utr) <= visible_chars:
        return "****"
    return "****" + utr[-visible_chars:]


def redact_token(token: str, visible_chars: int = 8) -> str:
    """Redact a bearer token, showing only the last *visible_chars* characters."""
    if len(token) <= visible_chars:
        return "****"
    return "****" + token[-visible_chars:]


def redact_email(email: str) -> str:
    """Redact an email address, showing only domain part."""
    if "@" not in email:
        return redact_string(email)
    local, domain = email.rsplit("@", 1)
    return f"****@{domain}"


def redact_string(value: str, visible_chars: int = 4) -> str:
    """Redact a generic string, keeping only the last *visible_chars* chars."""
    if not value:
        return value
    if len(value) <= visible_chars:
        return "****"
    return "****" + value[-visible_chars:]
