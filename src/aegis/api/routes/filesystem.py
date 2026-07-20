from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from aegis.api.dependencies import get_current_user, get_filesystem, get_gateway
from aegis.api.exceptions import Forbidden
from aegis.api.schemas import ErrorResponse, FileReadRequest, FileReadResponse
from aegis.auth import User
from aegis.fs import FsError, Filesystem
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult

router = APIRouter(prefix="/api/v1/filesystem", tags=["Filesystem"])


@router.post(
    "/read",
    response_model=FileReadResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Read a file within the allowed scope",
)
def read_file(
    body: FileReadRequest,
    current_user: User = Depends(get_current_user),
    gateway: Gateway = Depends(get_gateway),
    fs: Filesystem = Depends(get_filesystem),
) -> FileReadResponse:
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=body.agent_id,
        action_type="fs_read",
        params={"path": body.path},
        requested_at=datetime.now(timezone.utc),
    )
    decision = gateway.evaluate(current_user.id, action, body.agent_id, body.policy_id)
    if decision.result is DecisionResult.DENY:
        raise Forbidden(decision.reason)
    try:
        content = fs.read_file(body.path)
    except FsError as e:
        raise Forbidden(str(e))
    return FileReadResponse(content=content)
