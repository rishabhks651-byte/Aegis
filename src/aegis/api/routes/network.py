from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from aegis.api.dependencies import get_current_user, get_gateway, require_rate_limit
from aegis.api.exceptions import Forbidden
from aegis.api.schemas import ErrorResponse, NetworkRequest, NetworkResponse
from aegis.auth import User
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult

router = APIRouter(prefix="/api/v1/network", tags=["Network"])


@router.post(
    "/request",
    response_model=NetworkResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Perform a controlled HTTP request",
)
def http_request(
    body: NetworkRequest,
    current_user: User = Depends(get_current_user),
    gateway: Gateway = Depends(get_gateway),
    _=Depends(require_rate_limit),
) -> NetworkResponse:
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=body.agent_id,
        action_type="http_request",
        params={
            "url": body.url,
            "method": body.method,
        },
        requested_at=datetime.now(timezone.utc),
    )
    decision, http_response = gateway.http_request(
        current_user.id, action, body.agent_id, body.policy_id,
        url=body.url,
        method=body.method,
        timeout=body.timeout,
        max_response_size=body.max_response_size,
    )
    if decision.result is DecisionResult.DENY:
        return NetworkResponse(
            action_id=decision.action_id,
            decision_id=decision.decision_id,
            result=decision.result.value,
            reason=decision.reason,
        )
    return NetworkResponse(
        action_id=decision.action_id,
        decision_id=decision.decision_id,
        result=decision.result.value,
        reason=decision.reason,
        status_code=http_response.status_code if http_response else None,
        body=http_response.body if http_response else None,
        elapsed_ms=http_response.elapsed_ms if http_response else None,
        timed_out=http_response.timed_out if http_response else False,
        body_truncated=http_response.body_truncated if http_response else False,
    )
