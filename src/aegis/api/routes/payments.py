from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.dependencies import (
    AuthorizationService,
    PaymentService,
    RateLimiter,
    get_authz,
    get_current_user,
    get_payment_service,
    get_rate_limiter,
    require_rate_limit,
)
from aegis.api.exceptions import Forbidden, NotFound
from aegis.api.schemas import (
    ErrorResponse,
    PaymentListResponse,
    PaymentRejectRequest,
    PaymentResponse,
    PaymentSubmitRequest,
    PaymentVerifyRequest,
)
from aegis.auth import User
from aegis.payment import PaymentError

router = APIRouter(prefix="/api/v1/payments", tags=["Payments"])


@router.post(
    "/submit",
    response_model=PaymentResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Submit a payment for verification",
)
def submit_payment(
    body: PaymentSubmitRequest,
    current_user: User = Depends(get_current_user),
    svc: PaymentService = Depends(get_payment_service),
    _=Depends(require_rate_limit),
) -> PaymentResponse:
    try:
        payment = svc.submit_payment(current_user.id, body.plan_id, body.utr)
    except PaymentError as e:
        raise Forbidden(str(e))
    return _payment_to_response(payment)


@router.get(
    "",
    response_model=PaymentListResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List payments for the current user",
)
def list_payments(
    current_user: User = Depends(get_current_user),
    svc: PaymentService = Depends(get_payment_service),
) -> PaymentListResponse:
    payments = svc.list_payments(current_user.id)
    return PaymentListResponse(payments=[_payment_to_response(p) for p in payments])


@router.get(
    "/{payment_id}",
    response_model=PaymentResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Get payment status",
)
def get_payment(
    payment_id: str,
    current_user: User = Depends(get_current_user),
    svc: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    try:
        payment = svc.get_payment(payment_id, current_user.id)
    except PaymentError:
        raise NotFound("Payment not found")
    return _payment_to_response(payment)


@router.post(
    "/verify",
    response_model=PaymentResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Verify a PENDING payment (authorized verifier)",
)
def verify_payment(
    body: PaymentVerifyRequest,
    current_user: User = Depends(get_current_user),
    svc: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    try:
        payment = svc.verify_payment(
            payment_id=body.payment_id,
            verifier_id=current_user.id,
        )
    except (PaymentError, Exception) as e:
        raise Forbidden(str(e))
    return _payment_to_response(payment)


@router.post(
    "/reject",
    response_model=PaymentResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Reject a PENDING payment (authorized verifier)",
)
def reject_payment(
    body: PaymentRejectRequest,
    current_user: User = Depends(get_current_user),
    svc: PaymentService = Depends(get_payment_service),
) -> PaymentResponse:
    try:
        payment = svc.reject_payment(
            payment_id=body.payment_id,
            verifier_id=current_user.id,
            reason=body.reason,
        )
    except (PaymentError, Exception) as e:
        raise Forbidden(str(e))
    return _payment_to_response(payment)


def _payment_to_response(payment: "Payment") -> PaymentResponse:
    return PaymentResponse(
        payment_id=payment.payment_id,
        plan_id=payment.plan_id,
        amount_minor=payment.amount_minor,
        currency=payment.currency,
        destination_upi=payment.destination_upi,
        submitted_utr=payment.submitted_utr,
        submitted_at=payment.submitted_at,
        status=payment.status.value,
        verification_method=payment.verification_method,
        verified_at=payment.verified_at,
        rejection_reason=payment.rejection_reason,
    )
