"""Role-based access control for Aegis.

Architecture
------------
User -> Role -> Permissions -> Authorization

Roles are assigned to users. Each role maps to a set of permissions.
The AuthorizationService centralises all permission checks, fail-closed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aegis.audit import AuditStore
from aegis.models import AuditEvent
from aegis.settings import get_require_mfa_for_admins

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class Role(Enum):
    """Supported roles. Unknown roles fail closed (no permissions)."""

    USER = "USER"
    PAYMENT_VERIFIER = "PAYMENT_VERIFIER"
    ADMIN = "ADMIN"


# ---------------------------------------------------------------------------
# Permission constants
# ---------------------------------------------------------------------------

PERM_PAYMENT_VERIFY = "payment.verify"
PERM_PAYMENT_REJECT = "payment.reject"
PERM_PAYMENT_VIEW_ALL = "payment.view_all"
PERM_SUBSCRIPTION_MANAGE = "subscription.manage"
PERM_USER_MANAGE = "user.manage"
PERM_AUDIT_VIEW_ALL = "audit.view_all"
PERM_SYSTEM_MANAGE = "system.manage"

# ---------------------------------------------------------------------------
# Permission matrix: role -> set of permissions
# ---------------------------------------------------------------------------

_ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.USER.value: set(),
    Role.PAYMENT_VERIFIER.value: {
        PERM_PAYMENT_VERIFY,
        PERM_PAYMENT_REJECT,
        PERM_PAYMENT_VIEW_ALL,
    },
    Role.ADMIN.value: {
        PERM_PAYMENT_VERIFY,
        PERM_PAYMENT_REJECT,
        PERM_PAYMENT_VIEW_ALL,
        PERM_SUBSCRIPTION_MANAGE,
        PERM_USER_MANAGE,
        PERM_AUDIT_VIEW_ALL,
        PERM_SYSTEM_MANAGE,
    },
}

# Valid role strings for validation
_VALID_ROLES = {r.value for r in Role}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthorizationError(Exception):
    """Raised when a user lacks the required permission."""


# ---------------------------------------------------------------------------
# AuthorizationService
# ---------------------------------------------------------------------------


class AuthorizationService:
    """Central authorization service.

    Usage::

        svc = AuthorizationService(data_dir)
        svc.require(user_id, "payment.verify")   # raises on failure
        svc.has(user_id, "payment.verify")        # -> bool
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._audit_store = AuditStore(data_dir)

    # -- public API ----------------------------------------------------------

    def has(self, user_id: str, permission: str) -> bool:
        """Check if *user_id* has *permission*.  Fail-closed.

        Unknown role  -> False (no permissions).
        Unknown permission -> False (not in the role's set).
        Unknown user -> False.
        """
        user = self._load_user(user_id)
        if user is None:
            return False
        perms = _ROLE_PERMISSIONS.get(user.role)
        if perms is None:
            return False
        return permission in perms

    def require(self, user_id: str, permission: str) -> None:
        """Raise ``AuthorizationError`` if *user_id* lacks *permission*."""
        if not self.has(user_id, permission):
            raise AuthorizationError(
                f"User {user_id!r} lacks required permission {permission!r}"
            )

    # -- privileged action auditing ------------------------------------------

    def audit_privileged_action(
        self,
        actor_id: str,
        operation: str,
        target_id: str,
        result: str,
        *,
        target_user_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Record a privileged action in the audit log.

        Never stores secrets (passwords, tokens, API keys, UTRs).
        """
        params: dict[str, Any] = {
            "privileged_action": operation,
            "target_id": target_id,
            "result": result,
        }
        if target_user_id is not None:
            params["target_user_id"] = target_user_id

        event = AuditEvent(
            decision_id=str(uuid.uuid4()),
            action_id=str(uuid.uuid4()),
            action_type="privileged_operation",
            params=params,
            result="",
            matched=False,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            reason=reason or f"Privileged action {operation} on {target_id}",
            user_id=actor_id,
        )
        try:
            self._audit_store.append(event)
        except Exception:
            pass  # audit failures must not break the user-facing operation

    # -- internal ------------------------------------------------------------

    def _load_user(self, user_id: str) -> Any | None:
        """Load a User model by ID, or None if not found."""
        from aegis.auth import UserStore

        store = UserStore(self._data_dir)
        return store.get_by_id(user_id)

    @staticmethod
    def validate_role(role: str) -> None:
        """Raise ``ValueError`` if *role* is not a valid role string."""
        if role not in _VALID_ROLES:
            raise ValueError(
                f"Invalid role {role!r}; must be one of {sorted(_VALID_ROLES)}"
            )

    @staticmethod
    def get_role_permissions(role: str) -> frozenset[str]:
        """Return the set of permissions for *role* (fail-closed: empty)."""
        return frozenset(_ROLE_PERMISSIONS.get(role, set()))

    def list_user_permissions(self, user_id: str) -> frozenset[str]:
        """Return all permissions for *user_id*."""
        user = self._load_user(user_id)
        if user is None:
            return frozenset()
        return frozenset(_ROLE_PERMISSIONS.get(user.role, set()))

    @staticmethod
    def require_mfa_for_admin_assignment(user: Any, new_role: str) -> None:
        """Check that MFA is enabled when assigning ADMIN role under policy.

        Raises ``AuthorizationError`` if *new_role* is ADMIN, the policy
        ``AEGIS_REQUIRE_MFA_FOR_ADMINS`` is active and *user* does not have
        MFA enabled.
        """
        if new_role != Role.ADMIN.value:
            return
        if not get_require_mfa_for_admins():
            return
        if not getattr(user, "mfa_enabled", False):
            raise AuthorizationError(
                f"User {user.id!r} must have MFA enabled before being assigned "
                f"the ADMIN role (AEGIS_REQUIRE_MFA_FOR_ADMINS is set)"
            )
