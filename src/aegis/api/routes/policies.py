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
    ErrorResponse,
    PolicyApplyRequest,
    PolicyListEntry,
    PolicyListResponse,
    PolicyResponse,
)
from aegis.auth import User
from aegis.policy import PolicyStore, parse_policy_yaml

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])


def _get_store(
    auth: Authenticator = Depends(get_authenticator),
) -> PolicyStore:
    return PolicyStore(auth.data_dir)


@router.post(
    "",
    response_model=PolicyResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Apply a YAML policy",
)
def apply_policy(
    body: PolicyApplyRequest,
    current_user: User = Depends(get_current_user),
    store: PolicyStore = Depends(_get_store),
    entitlement: EntitlementService = Depends(get_entitlement),
) -> PolicyResponse:
    max_policies = entitlement.limit(current_user.id, "policies.max")
    if max_policies == 0:
        max_policies = 3  # free plan default
    existing = store.list_for_user(current_user.id)
    if len(existing) >= max_policies:
        raise Forbidden(f"Policy limit ({max_policies}) reached. Upgrade your plan.")
    try:
        policy = parse_policy_yaml(body.yaml_content, current_user.id)
    except (ValueError, Exception) as e:
        raise Forbidden(str(e))
    store.save(policy)
    return PolicyResponse(
        policy_id=policy.id,
        name=policy.name,
        description=policy.description,
        priority=policy.priority,
        enabled=policy.enabled,
        rules=[r.to_dict() for r in policy.rules],
        created_at=policy.created_at,
    )


@router.get(
    "",
    response_model=PolicyListResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List policies for the current user",
)
def list_policies(
    current_user: User = Depends(get_current_user),
    store: PolicyStore = Depends(_get_store),
) -> PolicyListResponse:
    policies = store.list_for_user(current_user.id)
    return PolicyListResponse(policies=[
        PolicyListEntry(
            policy_id=p.id,
            name=p.name,
            priority=p.priority,
            enabled=p.enabled,
            rules_count=len(p.rules),
        )
        for p in policies
    ])


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Get policy details",
)
def get_policy(
    policy_id: str,
    current_user: User = Depends(get_current_user),
    store: PolicyStore = Depends(_get_store),
) -> PolicyResponse:
    try:
        policy = store.get_by_id(policy_id, current_user.id)
    except ValueError:
        raise NotFound(f"Policy {policy_id!r} not found")
    return PolicyResponse(
        policy_id=policy.id,
        name=policy.name,
        description=policy.description,
        priority=policy.priority,
        enabled=policy.enabled,
        rules=[r.to_dict() for r in policy.rules],
        created_at=policy.created_at,
    )
