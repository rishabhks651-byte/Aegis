from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.dependencies import (
    Authenticator,
    EntitlementService,
    get_authenticator,
    get_current_user,
    get_entitlement,
)
from aegis.api.exceptions import Forbidden, NotFound
from aegis.api.schemas import (
    AgentCreateRequest,
    AgentListResponse,
    AgentResponse,
    AgentRevokeResponse,
    ErrorResponse,
)
from aegis.auth import User
from aegis.registry import AgentRegistry

router = APIRouter(prefix="/api/v1/agents", tags=["Agents"])


def _get_registry(
    auth: Authenticator = Depends(get_authenticator),
) -> AgentRegistry:
    return AgentRegistry(auth.data_dir)


@router.post(
    "",
    response_model=AgentResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Create a new agent",
)
def create_agent(
    body: AgentCreateRequest,
    current_user: User = Depends(get_current_user),
    registry: AgentRegistry = Depends(_get_registry),
    entitlement: EntitlementService = Depends(get_entitlement),
) -> AgentResponse:
    max_agents = entitlement.limit(current_user.id, "agents.max")
    if max_agents == 0:
        max_agents = 1  # free plan default
    existing = registry.list_for_user(current_user.id)
    active_count = sum(1 for a in existing if not a.revoked)
    if active_count >= max_agents:
        raise Forbidden(f"Agent limit ({max_agents}) reached. Upgrade your plan.")
    agent = registry.create(current_user.id, body.name)
    return AgentResponse(
        agent_id=agent.id,
        name=agent.name,
        user_id=agent.user_id,
        created_at=agent.created_at,
        revoked=agent.revoked,
        revoked_at=agent.revoked_at,
    )


@router.get(
    "",
    response_model=AgentListResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List agents for the current user",
)
def list_agents(
    current_user: User = Depends(get_current_user),
    registry: AgentRegistry = Depends(_get_registry),
) -> AgentListResponse:
    agents = registry.list_for_user(current_user.id)
    return AgentListResponse(agents=[
        AgentResponse(
            agent_id=a.id,
            name=a.name,
            user_id=a.user_id,
            created_at=a.created_at,
            revoked=a.revoked,
            revoked_at=a.revoked_at,
        )
        for a in agents
    ])


@router.get(
    "/{agent_id}",
    response_model=AgentResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Get agent details",
)
def get_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    registry: AgentRegistry = Depends(_get_registry),
) -> AgentResponse:
    try:
        agent = registry.get_for_user(agent_id, current_user.id)
    except ValueError:
        raise NotFound(f"Agent {agent_id!r} not found")
    return AgentResponse(
        agent_id=agent.id,
        name=agent.name,
        user_id=agent.user_id,
        created_at=agent.created_at,
        revoked=agent.revoked,
        revoked_at=agent.revoked_at,
    )


@router.post(
    "/{agent_id}/revoke",
    response_model=AgentRevokeResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Revoke an agent",
)
def revoke_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    registry: AgentRegistry = Depends(_get_registry),
) -> AgentRevokeResponse:
    try:
        agent = registry.revoke(agent_id, current_user.id)
    except ValueError:
        raise NotFound(f"Agent {agent_id!r} not found")
    return AgentRevokeResponse(
        agent_id=agent.id,
        revoked=agent.revoked,
    )
