from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from aegis.api.dependencies import get_current_user, get_gateway
from aegis.api.schemas import ActionEvaluateRequest, ActionEvaluateResponse, ErrorResponse
from aegis.auth import User
from aegis.gateway import Gateway
from aegis.models import Action

router = APIRouter(prefix="/api/v1/actions", tags=["Actions"])


@router.post(
    "/evaluate",
    response_model=ActionEvaluateResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Evaluate an agent action against policy",
)
def evaluate_action(
    body: ActionEvaluateRequest,
    current_user: User = Depends(get_current_user),
    gateway: Gateway = Depends(get_gateway),
) -> ActionEvaluateResponse:
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=body.agent_id,
        action_type=body.action_type,
        params=body.params,
        context=body.context,
        requested_at=datetime.now(timezone.utc),
    )
    decision = gateway.evaluate(
        user_id=current_user.id,
        action=action,
        agent_id=body.agent_id,
        policy_id=body.policy_id,
    )
    return ActionEvaluateResponse(
        action_id=decision.action_id,
        decision_id=decision.decision_id,
        result=decision.result.value,
        matched=decision.matched,
        policy_id=decision.policy_id,
        policy_name=decision.policy_name,
        rule_id=decision.rule_id,
        rule_effect=decision.rule_effect.value if decision.rule_effect else None,
        reason=decision.reason,
        evaluated_at=decision.evaluated_at.isoformat(),
    )
