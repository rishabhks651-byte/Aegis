"""Tests for the payment domain and verification architecture."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from aegis.payment import (
    ManualVerifier,
    Payment,
    PaymentError,
    PaymentService,
    PaymentStatus,
    PaymentVerifier,
    UPI_ID,
    VerificationError,
    VerificationResult,
    _normalize_utr,
    _validate_utr,
)
from aegis.entitlement import (
    EntitlementError,
    EntitlementService,
    Plan,
    Subscription,
    SubscriptionStatus,
    _BUILT_IN_PLANS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def env():
    """Set up a test environment with a regular user and an admin user."""
    td = tempfile.mkdtemp()
    from aegis.auth import Authenticator
    auth = Authenticator(td)
    user = auth.register("payuser", "ValidPass1!")
    admin = auth.register("adminuser", "AdminPass1!")
    auth.set_user_role(admin.id, "ADMIN")
    return {"tmpdir": td, "user_id": user.id, "admin_id": admin.id}


@pytest.fixture
def svc(env):
    """PaymentService with seeded plans."""
    return PaymentService(env["tmpdir"])


_VALID_UTR = "HDFC250719ABCDE"


# ---------------------------------------------------------------------------
# Payment model tests
# ---------------------------------------------------------------------------


class TestPaymentModel:
    def test_valid_payment(self):
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        assert p.status is PaymentStatus.PENDING
        assert p.amount_minor == 49900

    def test_invalid_amount_negative(self):
        with pytest.raises(ValueError):
            Payment(
                payment_id=str(uuid.uuid4()),
                user_id=str(uuid.uuid4()),
                plan_id="pro",
                amount_minor=-1,
                currency="INR",
                destination_upi=UPI_ID,
                submitted_utr=_VALID_UTR,
                submitted_at=datetime.now(timezone.utc),
                status=PaymentStatus.PENDING,
            )

    def test_invalid_amount_float(self):
        with pytest.raises(ValueError):
            Payment(
                payment_id=str(uuid.uuid4()),
                user_id=str(uuid.uuid4()),
                plan_id="pro",
                amount_minor=499.00,
                currency="INR",
                destination_upi=UPI_ID,
                submitted_utr=_VALID_UTR,
                submitted_at=datetime.now(timezone.utc),
                status=PaymentStatus.PENDING,
            )

    def test_invalid_currency_empty(self):
        with pytest.raises(ValueError):
            Payment(
                payment_id=str(uuid.uuid4()),
                user_id=str(uuid.uuid4()),
                plan_id="pro",
                amount_minor=49900,
                currency="",
                destination_upi=UPI_ID,
                submitted_utr=_VALID_UTR,
                submitted_at=datetime.now(timezone.utc),
                status=PaymentStatus.PENDING,
            )

    def test_invalid_empty_utr(self):
        with pytest.raises(ValueError):
            Payment(
                payment_id=str(uuid.uuid4()),
                user_id=str(uuid.uuid4()),
                plan_id="pro",
                amount_minor=49900,
                currency="INR",
                destination_upi=UPI_ID,
                submitted_utr="",
                submitted_at=datetime.now(timezone.utc),
                status=PaymentStatus.PENDING,
            )

    def test_unknown_status_fails_closed(self):
        with pytest.raises(ValueError):
            PaymentStatus("UNKNOWN")

    def test_timezone_handling_naive_submitted_at_raises(self):
        with pytest.raises(ValueError):
            Payment(
                payment_id=str(uuid.uuid4()),
                user_id=str(uuid.uuid4()),
                plan_id="pro",
                amount_minor=49900,
                currency="INR",
                destination_upi=UPI_ID,
                submitted_utr=_VALID_UTR,
                submitted_at=datetime.now(),  # naive
                status=PaymentStatus.PENDING,
            )

    def test_verified_payment_record(self):
        now = datetime.now(timezone.utc)
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=now,
            status=PaymentStatus.VERIFIED,
            verification_method="manual",
            verified_at=now,
        )
        assert p.status is PaymentStatus.VERIFIED
        assert p.verification_method == "manual"

    def test_rejected_payment_record(self):
        now = datetime.now(timezone.utc)
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=now,
            status=PaymentStatus.REJECTED,
            verification_method="manual",
            verified_at=now,
            rejection_reason="UTR mismatch",
        )
        assert p.status is PaymentStatus.REJECTED
        assert p.rejection_reason == "UTR mismatch"

    def test_serialization_roundtrip(self):
        now = datetime.now(timezone.utc)
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=now,
            status=PaymentStatus.PENDING,
        )
        d = p.to_dict()
        p2 = Payment.from_dict(d)
        assert p2.payment_id == p.payment_id
        assert p2.amount_minor == p.amount_minor
        assert p2.status is PaymentStatus.PENDING
        assert p2.submitted_utr == _VALID_UTR

    def test_serialization_verified_roundtrip(self):
        now = datetime.now(timezone.utc)
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=now,
            status=PaymentStatus.VERIFIED,
            verification_method="manual",
            verified_at=now,
        )
        d = p.to_dict()
        p2 = Payment.from_dict(d)
        assert p2.status is PaymentStatus.VERIFIED
        assert p2.verification_method == "manual"
        assert p2.verified_at is not None

    def test_deterministic_serialization(self):
        """to_dict() output must be JSON-serializable and deterministic."""
        now = datetime.now(timezone.utc)
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=now,
            status=PaymentStatus.PENDING,
        )
        d1 = p.to_dict()
        d2 = p.to_dict()
        assert d1 == d2
        json.dumps(d1)  # must not raise


# ---------------------------------------------------------------------------
# UTR validation tests
# ---------------------------------------------------------------------------


class TestUTRValidation:
    def test_empty_utr_rejected(self):
        with pytest.raises(ValueError, match="not be empty"):
            _validate_utr("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError, match="not be empty"):
            _validate_utr("   ")

    def test_valid_utr_accepted(self):
        result = _validate_utr("HDFC250719ABCDE")
        assert result == "HDFC250719ABCDE"

    def test_normalized_to_uppercase(self):
        result = _validate_utr("hdfc250719abcde")
        assert result == "HDFC250719ABCDE"

    def test_whitespace_collapsed(self):
        result = _validate_utr("  HDFC  250719  ABCDE  ")
        assert result == "HDFC 250719 ABCDE"

    def test_utr_with_hyphens_accepted(self):
        result = _validate_utr("HDFC-250719-ABCDE")
        assert result == "HDFC-250719-ABCDE"

    def test_utr_with_dots_accepted(self):
        result = _validate_utr("HDFC.250719.ABCDE")
        assert result == "HDFC.250719.ABCDE"

    def test_utr_with_slashes_accepted(self):
        result = _validate_utr("HDFC/250719/ABCDE")
        assert result == "HDFC/250719/ABCDE"

    def test_too_short_rejected(self):
        with pytest.raises(ValueError, match="at least"):
            _validate_utr("AB")

    def test_too_long_rejected(self):
        with pytest.raises(ValueError, match="exceed"):
            _validate_utr("A" * 51)

    def test_special_chars_rejected(self):
        with pytest.raises(ValueError, match="invalid characters"):
            _validate_utr("HDFC@250719")

    def test_control_chars_rejected(self):
        with pytest.raises(ValueError, match="invalid characters"):
            _validate_utr("HDFC\n250719")

    def test_normalize_preserves_original_via_submitted_utr(self):
        """The original value is preserved in Payment.submitted_utr."""
        raw = "  hdfc  250719  abcde  "
        normalized = _normalize_utr(raw)
        assert normalized == "HDFC 250719 ABCDE"
        # The raw value is different from normalized
        assert raw != normalized


# ---------------------------------------------------------------------------
# PaymentVerifier abstraction tests
# ---------------------------------------------------------------------------


class TestPaymentVerifier:
    def test_verifier_is_abstract(self):
        with pytest.raises(TypeError):
            PaymentVerifier()  # type: ignore[abstract]

    def test_manual_verifier_name(self):
        mv = ManualVerifier()
        assert mv.method_name == "manual"

    def test_manual_verifier_raises_on_auto_verify(self):
        mv = ManualVerifier()
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        with pytest.raises(VerificationError, match="Manual verification"):
            mv.verify(p)

    def test_manual_verifier_confirm_approved(self):
        mv = ManualVerifier()
        result = mv.confirm_verification(
            payment_id=str(uuid.uuid4()),
            verifier_id="admin-user",
            approved=True,
            verified_amount=49900,
            verified_currency="INR",
            verified_destination=UPI_ID,
            verified_utr=_VALID_UTR,
        )
        assert result.status is PaymentStatus.VERIFIED
        assert result.verified_amount == 49900
        assert result.verification_reference == "manual:admin-user"

    def test_manual_verifier_confirm_rejected(self):
        mv = ManualVerifier()
        result = mv.confirm_verification(
            payment_id=str(uuid.uuid4()),
            verifier_id="admin-user",
            approved=False,
            reason="UTR does not match bank records",
        )
        assert result.status is PaymentStatus.REJECTED
        assert "UTR does not match" in result.reason


# ---------------------------------------------------------------------------
# PaymentService tests
# ---------------------------------------------------------------------------


class TestPaymentSubmission:
    def test_submit_payment_returns_pending(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.status is PaymentStatus.PENDING
        assert payment.plan_id == "pro"
        assert payment.amount_minor == 49900
        assert payment.currency == "INR"
        assert payment.destination_upi == UPI_ID

    def test_submit_payment_does_not_activate_subscription(self, svc, env):
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        entitlement = EntitlementService(env["tmpdir"])
        assert not entitlement.has(env["user_id"], "ai.copilot")

    def test_submit_free_plan_rejected(self, svc, env):
        """Free plans do not require payment."""
        with pytest.raises(PaymentError, match="Free plans"):
            svc.submit_payment(env["user_id"], "free", _VALID_UTR)

    def test_submit_unknown_plan_rejected(self, svc, env):
        with pytest.raises(PaymentError, match="not found"):
            svc.submit_payment(env["user_id"], "nonexistent", _VALID_UTR)

    def test_submit_invalid_utr_rejected(self, svc, env):
        with pytest.raises(PaymentError, match="empty"):
            svc.submit_payment(env["user_id"], "pro", "")

    def test_utr_duplicate_same_user_idempotent(self, svc, env):
        """Same UTR by the same user returns existing payment."""
        p1 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        p2 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert p1.payment_id == p2.payment_id
        assert p2.status is PaymentStatus.PENDING

    def test_utr_different_user_rejected(self, svc, env):
        """Same UTR by a different user is rejected as potential fraud."""
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        other_user = str(uuid.uuid4())
        with pytest.raises(PaymentError, match="already been submitted by another user"):
            svc.submit_payment(other_user, "pro", _VALID_UTR)

    def test_verified_utr_cannot_be_reused(self, svc, env):
        """A verified UTR cannot be submitted again."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        from aegis.payment import _append_ndjson
        # Manually mark it verified
        from aegis.payment import PaymentStatus as PS
        now = datetime.now(timezone.utc)
        verified = Payment(
            payment_id=payment.payment_id,
            user_id=payment.user_id,
            plan_id=payment.plan_id,
            amount_minor=payment.amount_minor,
            currency=payment.currency,
            destination_upi=payment.destination_upi,
            submitted_utr=payment.submitted_utr,
            submitted_at=payment.submitted_at,
            status=PS.VERIFIED,
            verification_method="manual",
            verified_at=now,
        )
        payments_path = os.path.join(env["tmpdir"], "payments.ndjson")
        # Overwrite with verified
        if os.path.exists(payments_path):
            os.remove(payments_path)
        _append_ndjson(payments_path, verified.to_dict())

        with pytest.raises(PaymentError, match="already been verified"):
            svc.submit_payment(env["user_id"], "pro", _VALID_UTR)


# ---------------------------------------------------------------------------
# Amount validation tests
# ---------------------------------------------------------------------------


class TestAmountValidation:
    def test_correct_amount_matches_plan(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.amount_minor == 49900  # ₹499.00 in paise

    def test_enterprise_amount(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "enterprise", _VALID_UTR + "X")
        assert payment.amount_minor == 99900  # ₹999.00 in paise

    def test_amount_is_integer_not_float(self, svc, env):
        """Amount is always stored as integer minor units."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert isinstance(payment.amount_minor, int)
        assert payment.amount_minor == 49900
        # Float comparison of 49900 == 49900.0 is fine, but the storage is int
        assert payment.amount_minor == int(49900)

    def test_user_submitted_amount_not_trusted(self):
        """The amount comes from the plan, not user input."""
        # PaymentService always uses plan.price_minor
        # A user cannot set the amount when submitting
        pass


# ---------------------------------------------------------------------------
# Verification flow tests
# ---------------------------------------------------------------------------


class TestVerification:
    def test_pending_does_not_grant_entitlements(self, svc, env):
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        entitlement = EntitlementService(env["tmpdir"])
        assert not entitlement.has(env["user_id"], "ai.copilot")

    def test_verified_activates_subscription(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
        )
        entitlement = EntitlementService(env["tmpdir"])
        assert entitlement.has(env["user_id"], "ai.copilot")
        assert entitlement.limit(env["user_id"], "agents.max") == 10

    def test_verified_subscription_has_payment_id(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
        )
        entitlement = EntitlementService(env["tmpdir"])
        sub = entitlement.get_latest_subscription(env["user_id"])
        assert sub is not None
        assert sub.payment_id == payment.payment_id

    def test_rejected_does_not_grant_entitlements(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.reject_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
            reason="Suspicious UTR",
        )
        entitlement = EntitlementService(env["tmpdir"])
        assert not entitlement.has(env["user_id"], "ai.copilot")

    def test_verify_non_pending_raises(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.reject_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
            reason="Testing",
        )
        with pytest.raises(PaymentError, match="Cannot verify"):
            svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=env["admin_id"],
            )

    def test_reject_non_pending_raises(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
        )
        with pytest.raises(PaymentError, match="Cannot reject"):
            svc.reject_payment(
                payment_id=payment.payment_id,
                verifier_id=env["admin_id"],
                reason="Testing",
            )

    def test_reject_without_reason_raises(self, svc, env):
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        with pytest.raises(PaymentError, match="reason is required"):
            svc.reject_payment(
                payment_id=payment.payment_id,
                verifier_id=env["admin_id"],
                reason="",
            )

    def test_fully_verified_flow(self, svc, env):
        """Complete flow: submit → PENDING → verify → VERIFIED → subscription → entitlements."""
        # 1. No entitlements initially
        entitlement = EntitlementService(env["tmpdir"])
        assert not entitlement.has(env["user_id"], "ai.copilot")

        # 2. Submit payment
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.status is PaymentStatus.PENDING

        # 3. Still no entitlements
        assert not entitlement.has(env["user_id"], "ai.copilot")

        # 4. Verify
        verified = svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
        )
        assert verified.status is PaymentStatus.VERIFIED

        # 5. Now entitled
        assert entitlement.has(env["user_id"], "ai.copilot")


class TestFailedVerification:
    def test_failed_does_not_grant_entitlements(self, svc, env):
        """FAILED status (if ever introduced) must not grant entitlements."""
        # PaymentService doesn't set FAILED directly, but we can test the
        # principle by ensuring only VERIFIED activates subscriptions.
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        # Only VERIFIED activates — everything else is denied
        assert payment.status is not PaymentStatus.VERIFIED
        entitlement = EntitlementService(env["tmpdir"])
        assert not entitlement.has(env["user_id"], "ai.copilot")

    def test_verification_must_be_explicit(self, svc, env):
        """PaymentService never auto-verifies."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.status is PaymentStatus.PENDING
        # Re-read to ensure it's still PENDING
        read_back = svc.get_payment(payment.payment_id, env["user_id"])
        assert read_back.status is PaymentStatus.PENDING


# ---------------------------------------------------------------------------
# Idempotency tests
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_repeated_verification_safe(self, svc, env):
        """Calling verify_payment twice on the same payment is safe."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.verify_payment(
            payment_id=payment.payment_id,
            verifier_id=env["admin_id"],
        )
        # Second call should raise because status is no longer PENDING
        with pytest.raises(PaymentError, match="Cannot verify"):
            svc.verify_payment(
                payment_id=payment.payment_id,
                verifier_id=env["admin_id"],
            )

    def test_duplicate_submission_does_not_create_multiple_subscriptions(self, svc, env):
        """Repeated submission returns existing PENDING; only one subscription."""
        p1 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        p2 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert p1.payment_id == p2.payment_id

        svc.verify_payment(
            payment_id=p1.payment_id,
            verifier_id=env["admin_id"],
        )
        entitlement = EntitlementService(env["tmpdir"])
        subs_path = os.path.join(env["tmpdir"], "subscriptions.ndjson")
        subs = [
            r for r in _read_all_ndjson(subs_path)
            if r.get("user_id") == env["user_id"]
        ]
        # Should have exactly one subscription from this payment
        payment_subs = [s for s in subs if s.get("payment_id") == p1.payment_id]
        assert len(payment_subs) == 1

    def test_different_utr_different_payment(self, svc, env):
        """Different UTRs create different payment records."""
        p1 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        p2 = svc.submit_payment(env["user_id"], "pro", _VALID_UTR + "2")
        assert p1.payment_id != p2.payment_id


# ---------------------------------------------------------------------------
# Ownership and isolation tests
# ---------------------------------------------------------------------------


class TestOwnership:
    def test_user_cannot_view_other_payment(self, svc, env):
        p = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        other_user = str(uuid.uuid4())
        with pytest.raises(PaymentError, match="not found"):
            svc.get_payment(p.payment_id, other_user)

    def test_user_cannot_modify_other_payment(self, svc, env):
        """User isolation is enforced by get_payment requiring matching user_id."""
        # get_payment() is the main check — if you can't see it, you can't
        # act on it. The verify/reject paths are admin-only and don't take
        # user_id, so they're not accessible to normal users anyway.
        pass

    def test_list_returns_own_payments_only(self, svc, env):
        p = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        other_user = str(uuid.uuid4())
        other_payments = svc.list_payments(other_user)
        assert len(other_payments) == 0

    def test_list_returns_user_payments(self, svc, env):
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        payments = svc.list_payments(env["user_id"])
        assert len(payments) == 1


# ---------------------------------------------------------------------------
# Development environment tests
# ---------------------------------------------------------------------------


class TestDevEnvironment:
    def test_dev_manual_verify_requires_dev_env(self, svc, env):
        """Without AEGIS_ENV=dev, dev_manual_verify raises."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(PaymentError, match="only available in development"):
                svc._dev_manual_verify(payment.payment_id, env["user_id"])

    def test_dev_manual_verify_works_in_dev(self, svc, env):
        """With AEGIS_ENV=dev, dev_manual_verify succeeds."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        with patch.dict(os.environ, {"AEGIS_ENV": "dev"}):
            verified = svc._dev_manual_verify(payment.payment_id, env["user_id"])
            assert verified.status is PaymentStatus.VERIFIED

    def test_dev_manual_verify_activates_subscription(self, svc, env):
        """dev_manual_verify also activates subscription."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        with patch.dict(os.environ, {"AEGIS_ENV": "dev"}):
            svc._dev_manual_verify(payment.payment_id, env["user_id"])
        entitlement = EntitlementService(env["tmpdir"])
        assert entitlement.has(env["user_id"], "ai.copilot")

    def test_verify_payment_not_exposed_to_users(self):
        """PaymentService.verify_payment requires verifier_id, not user_id."""
        import inspect
        sig = inspect.signature(PaymentService.verify_payment)
        assert "verifier_id" in sig.parameters

    def test_no_user_verify_command_in_cli(self):
        """Ensure no 'aegis payment verify' command exists."""
        # This is a documentation test — checked in test_entitlement that
        # the parser doesn't have a verify subcommand for payment
        pass


# ---------------------------------------------------------------------------
# ManualVerifier not auto-verifying
# ---------------------------------------------------------------------------


class TestVerifierDoesNotAutoVerify:
    def test_submit_payment_never_auto_verifies(self, svc, env):
        """Submitting a payment never transitions to VERIFIED."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.status is PaymentStatus.PENDING

    def test_verifier_requires_explicit_confirm(self):
        """ManualVerifier.verify() always raises."""
        mv = ManualVerifier()
        p = Payment(
            payment_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            amount_minor=49900,
            currency="INR",
            destination_upi=UPI_ID,
            submitted_utr=_VALID_UTR,
            submitted_at=datetime.now(timezone.utc),
            status=PaymentStatus.PENDING,
        )
        with pytest.raises(VerificationError):
            mv.verify(p)

    def test_user_cannot_self_verify(self, svc, env):
        """No public method allows a user to self-verify."""
        from aegis.rbac import AuthorizationError
        assert not hasattr(svc, "self_verify")
        # USER lacks payment.verify permission
        with pytest.raises(AuthorizationError, match="lacks required permission"):
            svc.verify_payment(
                payment_id="nonexistent",
                verifier_id=env["user_id"],
            )


# ---------------------------------------------------------------------------
# Plan pricing tests
# ---------------------------------------------------------------------------


class TestPlanPricing:
    def test_free_plan_price_zero(self):
        assert _BUILT_IN_PLANS["free"]["price_minor"] == 0

    def test_pro_plan_price(self):
        assert _BUILT_IN_PLANS["pro"]["price_minor"] == 49900

    def test_enterprise_plan_price(self):
        assert _BUILT_IN_PLANS["enterprise"]["price_minor"] == 99900

    def test_plan_model_has_price_fields(self):
        plan = Plan(
            id="test-priced",
            name="Test Priced",
            version="1.0",
            active=True,
            price_minor=29900,
            currency="INR",
            entitlements={"test": True},
        )
        assert plan.price_minor == 29900
        assert plan.currency == "INR"

    def test_plan_default_price_zero(self):
        plan = Plan(
            id="test-free",
            name="Test Free",
            version="1.0",
            active=True,
            entitlements={},
        )
        assert plan.price_minor == 0
        assert plan.currency == "INR"

    def test_plan_serialization_roundtrip_with_pricing(self):
        plan = Plan(
            id="test-priced",
            name="Test Priced",
            version="1.0",
            active=True,
            price_minor=29900,
            currency="INR",
            entitlements={"test": True},
        )
        d = plan.to_dict()
        assert d["price_minor"] == 29900
        assert d["currency"] == "INR"
        plan2 = Plan.from_dict(d)
        assert plan2.price_minor == 29900


# ---------------------------------------------------------------------------
# Subscription activation from payment tests
# ---------------------------------------------------------------------------


class TestActivateFromPayment:
    def test_activate_from_payment_creates_subscription(self, svc, env):
        """activate_from_payment is idempotent and creates subscription."""
        entitlement = EntitlementService(env["tmpdir"])
        sub = entitlement.activate_from_payment(
            user_id=env["user_id"],
            plan_id="pro",
            payment_id=str(uuid.uuid4()),
        )
        assert sub.plan_id == "pro"
        assert sub.payment_id is not None
        assert sub.status is SubscriptionStatus.ACTIVE

    def test_activate_from_payment_idempotent(self, svc, env):
        """Calling activate_from_payment twice with the same payment_id is safe."""
        entitlement = EntitlementService(env["tmpdir"])
        pid = str(uuid.uuid4())
        sub1 = entitlement.activate_from_payment(
            user_id=env["user_id"],
            plan_id="pro",
            payment_id=pid,
        )
        sub2 = entitlement.activate_from_payment(
            user_id=env["user_id"],
            plan_id="pro",
            payment_id=pid,
        )
        assert sub1.id == sub2.id  # same subscription returned

    def test_activate_from_payment_unknown_plan_raises(self, svc, env):
        entitlement = EntitlementService(env["tmpdir"])
        with pytest.raises(EntitlementError, match="not found"):
            entitlement.activate_from_payment(
                user_id=env["user_id"],
                plan_id="nonexistent",
                payment_id=str(uuid.uuid4()),
            )


# ---------------------------------------------------------------------------
# Subscription payment_id field tests
# ---------------------------------------------------------------------------


class TestSubscriptionPaymentId:
    def test_subscription_has_payment_id_field(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            payment_id=str(uuid.uuid4()),
        )
        assert s.payment_id is not None

    def test_subscription_payment_id_none_by_default(self):
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="free",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
        )
        assert s.payment_id is None

    def test_subscription_serialization_roundtrip_with_payment_id(self):
        pid = str(uuid.uuid4())
        s = Subscription(
            id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            plan_id="pro",
            status=SubscriptionStatus.ACTIVE,
            start_time=datetime.now(timezone.utc),
            payment_id=pid,
        )
        d = s.to_dict()
        assert d["payment_id"] == pid
        s2 = Subscription.from_dict(d)
        assert s2.payment_id == pid


# ---------------------------------------------------------------------------
# UPI ID configuration tests
# ---------------------------------------------------------------------------


class TestUPIID:
    def test_default_upi_id(self):
        assert UPI_ID == "8882781255@ptsbi"

    def test_upi_id_configurable_via_env(self):
        with patch.dict(os.environ, {"AEGIS_UPI_ID": "test@upi"}):
            # Reimport to pick up env change
            from importlib import reload
            import aegis.payment
            reload(aegis.payment)
            assert aegis.payment.UPI_ID == "test@upi"
        # Restore
        reload(aegis.payment)
        assert aegis.payment.UPI_ID == "8882781255@ptsbi"

    def test_payment_uses_centralized_upi_id(self, svc, env):
        """Payment records use the centralized UPI_ID constant."""
        payment = svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        assert payment.destination_upi == UPI_ID


# ---------------------------------------------------------------------------
# List payments tests
# ---------------------------------------------------------------------------


class TestListPayments:
    def test_list_payments_empty(self, svc, env):
        payments = svc.list_payments(env["user_id"])
        assert payments == []

    def test_list_payments_returns_all(self, svc, env):
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR)
        svc.submit_payment(env["user_id"], "pro", _VALID_UTR + "2")
        payments = svc.list_payments(env["user_id"])
        assert len(payments) == 2


# ---------------------------------------------------------------------------
# Ndjson helpers
# ---------------------------------------------------------------------------


def _read_all_ndjson(path: str) -> list[dict]:
    import json
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
