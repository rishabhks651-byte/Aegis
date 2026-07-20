"""Aegis error codes and exception hierarchy for production use."""

from __future__ import annotations

import enum
import sys


class ErrorCode(enum.IntEnum):
    """Semantic exit codes for CLI and API consumers.

    Codes follow UNIX convention: 0 = success, nonzero = failure.
    Ranges:
        1–9    generic / catch-all errors
        10–19  authentication / session errors
        20–29  authorization / permission errors
        30–39  validation errors
        40–49  resource errors (not found, conflict, limit)
        50–59  domain-specific errors (payment, policy, etc.)
        60–69  I/O and storage errors
        70–79  configuration errors
        80–89  signal / interruption
    """

    SUCCESS = 0
    GENERIC_ERROR = 1

    # Auth / session (10–19)
    NOT_LOGGED_IN = 10
    SESSION_EXPIRED = 11
    AUTH_FAILED = 12
    PASSWORDS_DO_NOT_MATCH = 13

    # Authorization (20–29)
    PERMISSION_DENIED = 20
    SELF_ROLE_CHANGE = 21

    # Validation (30–39)
    INVALID_ROLE = 30
    INVALID_INPUT = 31
    INVALID_JSON = 32

    # Resource (40–49)
    NOT_FOUND = 40
    LIMIT_REACHED = 41
    CONFLICT = 42

    # Domain (50–59)
    PAYMENT_ERROR = 50
    ALLOWLIST_ERROR = 51
    NETWORK_ERROR = 52
    FS_ERROR = 53
    AI_ERROR = 54
    ENTITLEMENT_ERROR = 55

    # I/O (60–69)
    IO_ERROR = 60
    INTEGRITY_ERROR = 61

    # Config (70–79)
    CONFIG_ERROR = 70

    # Signal / interruption (80–89)
    INTERRUPTED = 80


class AegisError(Exception):
    """Base exception for all Aegis errors with an associated error code."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.GENERIC_ERROR) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def exit(self) -> None:
        """Print to stderr and exit with the appropriate code."""
        print(f"Error: {self.message}", file=sys.stderr)
        sys.exit(self.code.value)
