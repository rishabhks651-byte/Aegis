from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.ai import AIError, AICopilot
from aegis.api.dependencies import get_ai_copilot, get_current_user, require_rate_limit
from aegis.api.exceptions import Forbidden
from aegis.api.schemas import (
    AIExplainRequest,
    AIPolicyDraftRequest,
    AIPolicyReviewRequest,
    AIResponse,
    ErrorResponse,
)
from aegis.auth import User
from aegis.entitlement import EntitlementError

router = APIRouter(prefix="/api/v1/copilot", tags=["AI Copilot"])


@router.post(
    "/explain",
    response_model=AIResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Explain a security decision",
)
def explain_decision(
    body: AIExplainRequest,
    current_user: User = Depends(get_current_user),
    copilot: AICopilot = Depends(get_ai_copilot),
    _=Depends(require_rate_limit),
) -> AIResponse:
    try:
        result = copilot.explain_decision(body.decision_id, current_user.id)
        copilot.record_audit(current_user.id, copilot._outcomes[-1])
    except (AIError, EntitlementError, ValueError) as e:
        raise Forbidden(str(e))
    return AIResponse(content=result)


@router.post(
    "/audit-summary",
    response_model=AIResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Summarise audit events",
)
def audit_summary(
    current_user: User = Depends(get_current_user),
    copilot: AICopilot = Depends(get_ai_copilot),
) -> AIResponse:
    try:
        result = copilot.audit_summary(current_user.id)
        copilot.record_audit(current_user.id, copilot._outcomes[-1])
    except (AIError, EntitlementError) as e:
        raise Forbidden(str(e))
    return AIResponse(content=result)


@router.post(
    "/policy-review",
    response_model=AIResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Analyse a policy for security risks",
)
def policy_review(
    body: AIPolicyReviewRequest,
    current_user: User = Depends(get_current_user),
    copilot: AICopilot = Depends(get_ai_copilot),
    _=Depends(require_rate_limit),
) -> AIResponse:
    try:
        result = copilot.policy_review(body.policy_id, current_user.id)
        copilot.record_audit(current_user.id, copilot._outcomes[-1])
    except (AIError, EntitlementError, ValueError) as e:
        raise Forbidden(str(e))
    return AIResponse(content=result)


@router.post(
    "/policy-draft",
    response_model=AIResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Draft a policy from natural language",
)
def policy_draft(
    body: AIPolicyDraftRequest,
    current_user: User = Depends(get_current_user),
    copilot: AICopilot = Depends(get_ai_copilot),
    _=Depends(require_rate_limit),
) -> AIResponse:
    try:
        result = copilot.policy_draft(body.description, current_user.id)
        copilot.record_audit(current_user.id, copilot._outcomes[-1])
    except (AIError, EntitlementError) as e:
        raise Forbidden(str(e))
    return AIResponse(content=result)
