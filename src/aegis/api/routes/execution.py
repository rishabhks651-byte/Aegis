from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from aegis.api.dependencies import get_current_user, get_gateway, require_rate_limit
from aegis.api.exceptions import Forbidden
from aegis.api.schemas import ErrorResponse, ProcessExecuteRequest, ProcessExecuteResponse
from aegis.auth import User
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult

router = APIRouter(prefix="/api/v1/execution", tags=["Process Execution"])


@router.post(
    "/execute",
    response_model=ProcessExecuteResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Execute an allowlisted process",
)
def execute_process(
    body: ProcessExecuteRequest,
    current_user: User = Depends(get_current_user),
    gateway: Gateway = Depends(get_gateway),
    _=Depends(require_rate_limit),
) -> ProcessExecuteResponse:
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=body.agent_id,
        action_type="execute_process",
        params={
            "executable": body.executable_name,
            "args": list(body.args),
        },
        requested_at=datetime.now(timezone.utc),
    )
    decision, process_result = gateway.execute_process(
        current_user.id, action, body.agent_id, body.policy_id,
        executable_name=body.executable_name,
        process_args=list(body.args),
        timeout=body.timeout,
        output_limit=body.output_limit,
    )
    if decision.result is DecisionResult.DENY:
        return ProcessExecuteResponse(
            action_id=decision.action_id,
            decision_id=decision.decision_id,
            result=decision.result.value,
            reason=decision.reason,
        )
    return ProcessExecuteResponse(
        action_id=decision.action_id,
        decision_id=decision.decision_id,
        result=decision.result.value,
        reason=decision.reason,
        exit_code=process_result.exit_code if process_result else None,
        stdout=process_result.stdout if process_result else None,
        stderr=process_result.stderr if process_result else None,
        execution_time_ms=process_result.execution_time_ms if process_result else None,
        timed_out=process_result.timed_out if process_result else False,
        output_truncated=process_result.output_truncated if process_result else False,
    )
