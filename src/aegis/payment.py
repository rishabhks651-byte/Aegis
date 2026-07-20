"""Payment domain and verification architecture.

Core principle
--------------
A user-submitted UTR is NOT proof of payment.
Only an explicit trusted verification may transition a payment to VERIFIED.

Lifecycle::

    Payment Intent
         ↓
    Payment Record: PENDING
         ↓
    Trusted Verification
         ↓
    VERIFIED / REJECTED / FAILED
         ↓
    Only VERIFIED → Subscription Activation → Entitlements
"""

from __future__ import annotations

import json
import os
import os.path
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aegis.entitlement import EntitlementService, Subscription
from aegis.rbac import AuthorizationService, PERM_PAYMENT_REJECT, PERM_PAYMENT_VERIFY, PERM_PAYMENT_VIEW_ALL

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

UPI_ID: str = os.environ.get("AEGIS_UPI_ID", "8882781255@ptsbi")
"""The destination UPI ID for this project. Configurable via AEGIS_UPI_ID."""

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PaymentError(Exception):
    """Raised when a payment operation fails."""


class VerificationError(PaymentError):
    """Raised when verification fails."""


# ---------------------------------------------------------------------------
# Payment status
# ---------------------------------------------------------------------------


class PaymentStatus(Enum):
    """Explicit verification states.

    Unknown values fail closed (not treated as PENDING or VERIFIED).
    """

    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


# ---------------------------------------------------------------------------
# Payment model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Payment:
    """A payment record submitted by a user, awaiting or resolved by verification."""

    payment_id: str
    user_id: str
    plan_id: str
    amount_minor: int
    currency: str
    destination_upi: str
    submitted_utr: str
    submitted_at: datetime
    status: PaymentStatus
    verification_method: str | None = None
    verified_at: datetime | None = None
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        from aegis.models import _validate_uuid, _validate_tz_aware, _normalize_dt

        _validate_uuid(self.payment_id, "payment_id")
        _validate_uuid(self.user_id, "user_id")
        if not self.plan_id or not self.plan_id.strip():
            raise ValueError("plan_id must be non-empty")
        if not isinstance(self.amount_minor, int) or self.amount_minor < 0:
            raise ValueError("amount_minor must be a non-negative integer")
        if not self.currency or not isinstance(self.currency, str):
            raise ValueError("currency must be a non-empty string")
        if not self.destination_upi or not self.destination_upi.strip():
            raise ValueError("destination_upi must be non-empty")
        if not self.submitted_utr or not self.submitted_utr.strip():
            raise ValueError("submitted_utr must be non-empty")
        if not isinstance(self.status, PaymentStatus):
            raise TypeError(f"status must be a PaymentStatus: {self.status!r}")
        if self.verification_method is not None and not self.verification_method.strip():
            raise ValueError("verification_method must be non-empty if provided")
        if self.rejection_reason is not None and not self.rejection_reason.strip():
            raise ValueError("rejection_reason must be non-empty if provided")
        _validate_tz_aware(self.submitted_at, "submitted_at")
        object.__setattr__(self, "submitted_at", _normalize_dt(self.submitted_at))
        if self.verified_at is not None:
            _validate_tz_aware(self.verified_at, "verified_at")
            object.__setattr__(self, "verified_at", _normalize_dt(self.verified_at))

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "payment_id": self.payment_id,
            "user_id": self.user_id,
            "plan_id": self.plan_id,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "destination_upi": self.destination_upi,
            "submitted_utr": self.submitted_utr,
            "submitted_at": self.submitted_at.isoformat(),
            "status": self.status.value,
        }
        if self.verification_method is not None:
            d["verification_method"] = self.verification_method
        if self.verified_at is not None:
            d["verified_at"] = self.verified_at.isoformat()
        if self.rejection_reason is not None:
            d["rejection_reason"] = self.rejection_reason
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Payment:
        from aegis.models import _parse_iso
        return cls(
            payment_id=data["payment_id"],
            user_id=data["user_id"],
            plan_id=data["plan_id"],
            amount_minor=data["amount_minor"],
            currency=data["currency"],
            destination_upi=data["destination_upi"],
            submitted_utr=data["submitted_utr"],
            submitted_at=_parse_iso(data["submitted_at"]),
            status=PaymentStatus(data["status"]),
            verification_method=data.get("verification_method"),
            verified_at=_parse_iso(data["verified_at"])
            if data.get("verified_at")
            else None,
            rejection_reason=data.get("rejection_reason"),
        )


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """Structured outcome of a payment verification.

    Only a result with ``status == VERIFIED`` and all trusted fields
    populated should be treated as trusted verification evidence.
    """

    status: PaymentStatus
    verified_amount: int | None = None
    verified_currency: str | None = None
    verified_destination: str | None = None
    verified_utr: str | None = None
    verification_reference: str | None = None
    reason: str | None = None


# ---------------------------------------------------------------------------
# UTR validation
# ---------------------------------------------------------------------------

# UTR formats vary by bank and payment system (NEFT, RTGS, IMPS, UPI).
# Validator is conservative: allows alphanumeric, spaces, hyphens, dots, slashes.
_UTR_PATTERN = re.compile(r"^[A-Za-z0-9 \.\-/]+$")
_UTR_MIN_LENGTH = 4
_UTR_MAX_LENGTH = 50


def _normalize_utr(raw: str) -> str:
    """Normalize a UTR for comparison (uppercase, collapse whitespace)."""
    return " ".join(raw.upper().split())


def _validate_utr(raw: str) -> str:
    """Validate and normalize a UTR. Raises ValueError on invalid input."""
    if not raw or not raw.strip():
        raise ValueError("UTR must not be empty")
    stripped = raw.strip()
    if len(stripped) > _UTR_MAX_LENGTH:
        raise ValueError(f"UTR must not exceed {_UTR_MAX_LENGTH} characters")
    if not _UTR_PATTERN.match(stripped):
        raise ValueError("UTR contains invalid characters")
    normalized = _normalize_utr(stripped)
    if len(normalized) < _UTR_MIN_LENGTH:
        raise ValueError(f"UTR must be at least {_UTR_MIN_LENGTH} characters")
    return normalized


# ---------------------------------------------------------------------------
# Payment verifier abstraction
# ---------------------------------------------------------------------------


class PaymentVerifier(ABC):
    """Abstract interface for payment verification providers.

    Implementations must never auto-verify.  They must require explicit
    trusted evidence before returning a VERIFIED result.
    """

    @abstractmethod
    def verify(self, payment: Payment) -> VerificationResult:
        """Attempt verification of *payment*.

        Implementations that require manual intervention (e.g.
        :class:`ManualVerifier`) MUST raise ``VerificationError``
        or return ``REJECTED`` / ``FAILED`` — they must never
        auto-return ``VERIFIED`` without trusted evidence.
        """

    @property
    @abstractmethod
    def method_name(self) -> str:
        """Human-readable name of this verification method (e.g. ``"manual"``)."""


class ManualVerifier(PaymentVerifier):
    """Manual verification workflow.

    This verifier NEVER auto-verifies.  It must be explicitly driven
    by an authorized verifier via :meth:`confirm_verification`.
    """

    @property
    def method_name(self) -> str:
        return "manual"

    def verify(self, payment: Payment) -> VerificationResult:
        """Always raises — manual verification requires explicit action."""
        raise VerificationError(
            "Manual verification requires an authorized verifier to confirm"
        )

    def confirm_verification(
        self,
        payment_id: str,
        verifier_id: str,
        *,
        approved: bool,
        verified_amount: int | None = None,
        verified_currency: str | None = None,
        verified_destination: str | None = None,
        verified_utr: str | None = None,
        reason: str | None = None,
    ) -> VerificationResult:
        """Produce a trusted verification result.

        Only call this when an authorized verifier has independently
        confirmed the payment externally.

        Parameters
        ----------
        payment_id : str
            The payment being verified.
        verifier_id : str
            Identity of the authorized verifier (for audit trail).
        approved : bool
            ``True`` to mark VERIFIED, ``False`` to mark REJECTED.
        verified_amount, verified_currency, verified_destination, verified_utr :
            Trusted evidence obtained from external verification.
        reason : str, optional
            Human-readable justification (required when ``approved=False``).
        """
        if approved:
            return VerificationResult(
                status=PaymentStatus.VERIFIED,
                verified_amount=verified_amount,
                verified_currency=verified_currency,
                verified_destination=verified_destination,
                verified_utr=verified_utr,
                verification_reference=f"manual:{verifier_id}",
                reason=reason,
            )
        return VerificationResult(
            status=PaymentStatus.REJECTED,
            reason=reason or "Rejected by verifier",
            verification_reference=f"manual:{verifier_id}",
        )


# ---------------------------------------------------------------------------
# NDJSON helpers (local copies)
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
    records: list[dict[str, Any]], field: str = "payment_id",
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for r in records:
        result[r[field]] = r
    return result


# ---------------------------------------------------------------------------
# PaymentService
# ---------------------------------------------------------------------------


class PaymentService:
    """Central gateway for payment operations.

    Production path (only path available without AEGIS_ENV=dev)::

        submit_payment() → PENDING
        verify_payment() / reject_payment()  [admin only]
        VERIFIED → subscription activated via EntitlementService

    The service never auto-verifies.  It uses a :class:`ManualVerifier`
    that requires explicit authorized confirmation.
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._payments_path = os.path.join(data_dir, "payments.ndjson")
        self._subs_path = os.path.join(data_dir, "subscriptions.ndjson")
        self._entitlement = EntitlementService(data_dir)
        self._verifier: PaymentVerifier = ManualVerifier()

    @property
    def _authz(self) -> AuthorizationService:
        """Lazy authorization service."""
        if not hasattr(self, "_authz_svc"):
            object.__setattr__(self, "_authz_svc", AuthorizationService(self._data_dir))
        return self._authz_svc  # type: ignore[has-type]

    def _audit_privileged(
        self, actor_id: str, operation: str, target_id: str,
        result: str, *, target_user_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        self._authz.audit_privileged_action(
            actor_id=actor_id, operation=operation, target_id=target_id,
            result=result, target_user_id=target_user_id, reason=reason,
        )

    # -- public API ----------------------------------------------------------

    def submit_payment(
        self,
        user_id: str,
        plan_id: str,
        utr: str,
        *,
        skip_dup_check: bool = False,
    ) -> Payment:
        """Submit a payment for verification.

        Returns a PENDING payment record.  Does NOT activate any subscription.
        Duplicate UTR detection prevents:
        1. Same UTR submitted twice by the same user (returns existing).
        2. Same UTR submitted by a different user (rejected as potential fraud).
        3. Already-verified UTR being reused (rejected).

        Parameters
        ----------
        skip_dup_check : bool
            Testing only.  When true, skips duplicate detection.
        """
        try:
            normalized_utr = _validate_utr(utr)
        except ValueError as e:
            raise PaymentError(str(e))

        # Duplicate detection
        existing = self._find_payment_by_utr(normalized_utr)
        if existing is not None and not skip_dup_check:
            if existing.user_id == user_id:
                if existing.status is PaymentStatus.VERIFIED:
                    raise PaymentError("This UTR has already been verified")
                return existing  # idempotent: return same PENDING payment
            raise PaymentError("This UTR has already been submitted by another user")

        # Look up plan for amount validation
        plan = self._entitlement.get_plan(plan_id)
        if plan is None:
            raise PaymentError(f"Plan {plan_id!r} not found")
        if not plan.active:
            raise PaymentError(f"Plan {plan_id!r} is not active")
        if plan.price_minor == 0:
            raise PaymentError("Free plans do not require payment")

        now = datetime.now(timezone.utc)
        payment = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id=plan_id,
            amount_minor=plan.price_minor,
            currency=plan.currency,
            destination_upi=UPI_ID,
            submitted_utr=utr,
            submitted_at=now,
            status=PaymentStatus.PENDING,
        )
        _append_ndjson(self._payments_path, payment.to_dict())
        return payment

    def verify_payment(
        self,
        payment_id: str,
        verifier_id: str,
        *,
        verified_amount: int | None = None,
        verified_currency: str | None = None,
        verified_destination: str | None = None,
        verified_utr: str | None = None,
    ) -> Payment:
        """Transition a PENDING payment to VERIFIED and activate subscription.

        Requires ``payment.verify`` permission on *verifier_id*.
        """
        self._authz.require(verifier_id, PERM_PAYMENT_VERIFY)
        updated = self._execute_verify(
            payment_id=payment_id,
            verifier_id=verifier_id,
            verified_amount=verified_amount,
            verified_currency=verified_currency,
            verified_destination=verified_destination,
            verified_utr=verified_utr,
        )
        self._audit_privileged(
            actor_id=verifier_id,
            operation="payment.verify",
            target_id=payment_id,
            result="VERIFIED",
            target_user_id=updated.user_id,
        )
        return updated

    def _execute_verify(
        self,
        payment_id: str,
        verifier_id: str,
        *,
        verified_amount: int | None = None,
        verified_currency: str | None = None,
        verified_destination: str | None = None,
        verified_utr: str | None = None,
    ) -> Payment:
        """Execute verification logic without authorization checks.

        This is the shared implementation used by ``verify_payment``
        (RBAC-guarded) and ``_dev_manual_verify`` (dev-only bypass).
        """
        payment = self._get_payment(payment_id)
        if payment.status is not PaymentStatus.PENDING:
            raise PaymentError(
                f"Cannot verify payment in status {payment.status.value}"
            )

        result = self._verifier.confirm_verification(
            payment_id=payment_id,
            verifier_id=verifier_id,
            approved=True,
            verified_amount=verified_amount,
            verified_currency=verified_currency,
            verified_destination=verified_destination,
            verified_utr=verified_utr,
        )

        if result.status is not PaymentStatus.VERIFIED:
            raise PaymentError("Verification did not produce VERIFIED status")

        now = datetime.now(timezone.utc)
        updated = Payment(
            payment_id=payment.payment_id,
            user_id=payment.user_id,
            plan_id=payment.plan_id,
            amount_minor=payment.amount_minor,
            currency=payment.currency,
            destination_upi=payment.destination_upi,
            submitted_utr=payment.submitted_utr,
            submitted_at=payment.submitted_at,
            status=PaymentStatus.VERIFIED,
            verification_method=self._verifier.method_name,
            verified_at=now,
        )
        self._overwrite_payment(updated)

        self._entitlement.activate_from_payment(
            user_id=payment.user_id,
            plan_id=payment.plan_id,
            payment_id=payment.payment_id,
        )
        return updated

    def reject_payment(
        self,
        payment_id: str,
        verifier_id: str,
        reason: str,
    ) -> Payment:
        """Transition a PENDING payment to REJECTED.

        Requires ``payment.reject`` permission on *verifier_id*.
        """
        self._authz.require(verifier_id, PERM_PAYMENT_REJECT)
        updated = self._execute_reject(
            payment_id=payment_id, verifier_id=verifier_id, reason=reason,
        )
        self._audit_privileged(
            actor_id=verifier_id,
            operation="payment.reject",
            target_id=payment_id,
            result="REJECTED",
            target_user_id=updated.user_id,
            reason=reason,
        )
        return updated

    def _execute_reject(
        self,
        payment_id: str,
        verifier_id: str,
        reason: str,
    ) -> Payment:
        """Execute rejection logic without authorization checks."""
        if not reason or not reason.strip():
            raise PaymentError("Rejection reason is required")

        payment = self._get_payment(payment_id)
        if payment.status is not PaymentStatus.PENDING:
            raise PaymentError(
                f"Cannot reject payment in status {payment.status.value}"
            )

        result = self._verifier.confirm_verification(
            payment_id=payment_id,
            verifier_id=verifier_id,
            approved=False,
            reason=reason,
        )

        now = datetime.now(timezone.utc)
        updated = Payment(
            payment_id=payment.payment_id,
            user_id=payment.user_id,
            plan_id=payment.plan_id,
            amount_minor=payment.amount_minor,
            currency=payment.currency,
            destination_upi=payment.destination_upi,
            submitted_utr=payment.submitted_utr,
            submitted_at=payment.submitted_at,
            status=PaymentStatus.REJECTED,
            verification_method=self._verifier.method_name,
            verified_at=now,
            rejection_reason=reason,
        )
        self._overwrite_payment(updated)
        return updated

    def get_payment(self, payment_id: str, user_id: str) -> Payment:
        """Return a payment record.  User-isolated."""
        payment = self._get_payment(payment_id)
        if payment.user_id != user_id:
            raise PaymentError("Payment not found")
        return payment

    def list_payments(self, user_id: str) -> list[Payment]:
        """Return all payments for a user, newest first."""
        all_records = _read_ndjson(self._payments_path)
        user_records = [
            r for r in all_records if r.get("user_id") == user_id
        ]
        deduped = _dedup_by_field(user_records, "payment_id")
        payments = [
            Payment.from_dict(r) for r in deduped.values()
        ]
        payments.sort(key=lambda p: p.submitted_at, reverse=True)
        return payments

    def list_all_payments(self, caller_id: str) -> list[Payment]:
        """Return all payments.

        Requires ``payment.view_all`` permission on *caller_id*.
        """
        self._authz.require(caller_id, PERM_PAYMENT_VIEW_ALL)
        records = _read_ndjson(self._payments_path)
        deduped = _dedup_by_field(records, "payment_id")
        payments = [Payment.from_dict(r) for r in deduped.values()]
        payments.sort(key=lambda p: p.submitted_at, reverse=True)
        return payments

    # -- internal ------------------------------------------------------------

    def _get_payment(self, payment_id: str) -> Payment:
        """Look up a payment by ID, raise if not found."""
        all_records = _read_ndjson(self._payments_path)
        for r in all_records:
            if r.get("payment_id") == payment_id:
                return Payment.from_dict(r)
        raise PaymentError(f"Payment {payment_id!r} not found")

    def _find_payment_by_utr(self, normalized_utr: str) -> Payment | None:
        """Find a payment by normalized UTR across all users."""
        all_records = _read_ndjson(self._payments_path)
        for r in all_records:
            payment = Payment.from_dict(r)
            if _normalize_utr(payment.submitted_utr) == normalized_utr:
                return payment
        return None

    def _overwrite_payment(self, payment: Payment) -> None:
        """Replace an existing payment record (dedup by payment_id)."""
        import tempfile
        all_records = _read_ndjson(self._payments_path)
        filtered = [
            r for r in all_records
            if r.get("payment_id") != payment.payment_id
        ]
        filtered.append(payment.to_dict())
        # Atomic write via temp file + rename
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(self._payments_path), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for r in filtered:
                    f.write(json.dumps(r, default=str) + "\n")
            os.replace(tmp_path, self._payments_path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def _dev_manual_verify(self, payment_id: str, user_id: str) -> Payment:
        """Development-only: simulate manual verification (requires AEGIS_ENV=dev).

        This method bypasses RBAC for development convenience.  It is NEVER
        available in production (guarded by AEGIS_ENV=dev).
        """
        from aegis.settings import is_dev_mode
        if not is_dev_mode():
            raise PaymentError(
                "Manual verification is only available in development environment. "
                "Set AEGIS_ENV=dev."
            )

        # Verify that the caller owns this payment
        payment = self.get_payment(payment_id, user_id)
        return self._execute_verify(
            payment_id=payment_id,
            verifier_id=user_id,
            verified_amount=payment.amount_minor,
            verified_currency=payment.currency,
            verified_destination=payment.destination_upi,
            verified_utr=payment.submitted_utr,
        )
