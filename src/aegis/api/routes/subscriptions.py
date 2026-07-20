from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.dependencies import (
    EntitlementService,
    get_current_user,
    get_entitlement,
)
from aegis.api.schemas import EntitlementsResponse, ErrorResponse, SubscriptionResponse
from aegis.auth import User

router = APIRouter(prefix="/api/v1/subscriptions", tags=["Subscriptions"])


@router.get(
    "/me",
    response_model=SubscriptionResponse | dict,
    responses={401: {"model": ErrorResponse}},
    summary="Get current subscription status",
)
def my_subscription(
    current_user: User = Depends(get_current_user),
    svc: EntitlementService = Depends(get_entitlement),
) -> SubscriptionResponse | dict:
    sub = svc.get_latest_subscription(current_user.id)
    if sub is None:
        return {}
    plan = svc.get_plan(sub.plan_id)
    return SubscriptionResponse(
        subscription_id=sub.id,
        user_id=sub.user_id,
        plan_id=sub.plan_id,
        plan_name=plan.name if plan else "Unknown",
        status=sub.status.value,
        start_time=sub.start_time,
        end_time=sub.end_time,
        renewal=sub.renewal,
        payment_id=sub.payment_id,
    )


@router.get(
    "/me/entitlements",
    response_model=EntitlementsResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get effective entitlements",
)
def my_entitlements(
    current_user: User = Depends(get_current_user),
    svc: EntitlementService = Depends(get_entitlement),
) -> EntitlementsResponse:
    entitlements = svc.list_entitlements(current_user.id)
    sub = svc.get_latest_subscription(current_user.id)
    plan = svc.get_plan(sub.plan_id) if sub else None
    return EntitlementsResponse(
        user_id=current_user.id,
        plan_id=sub.plan_id if sub else None,
        plan_name=plan.name if plan else None,
        status=sub.status.value if sub else None,
        entitlements=entitlements,
    )


@router.get(
    "/plans",
    response_model=list[dict],
    responses={401: {"model": ErrorResponse}},
    summary="List available subscription plans",
)
def list_plans(
    current_user: User = Depends(get_current_user),
    svc: EntitlementService = Depends(get_entitlement),
) -> list[dict]:
    plans = svc.list_plans()
    return [
        {
            "id": p.id,
            "name": p.name,
            "price_minor": p.price_minor,
            "currency": p.currency,
            "entitlements": p.entitlements,
        }
        for p in plans
    ]
