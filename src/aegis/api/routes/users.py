from __future__ import annotations

from fastapi import APIRouter, Depends

from aegis.api.dependencies import (
    Authenticator,
    AuthorizationService,
    get_authenticator,
    get_authz,
    get_current_user,
)
from aegis.api.exceptions import Forbidden, NotFound
from aegis.api.schemas import (
    ErrorResponse,
    SetRoleRequest,
    UserListEntry,
)
from aegis.auth import User
from aegis.rbac import PERM_USER_MANAGE

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserListEntry,
    responses={401: {"model": ErrorResponse}},
    summary="Get current user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserListEntry:
    return UserListEntry(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        active=current_user.active,
        created_at=current_user.created_at,
    )


@router.get(
    "/me/permissions",
    response_model=list[str],
    responses={401: {"model": ErrorResponse}},
    summary="Get current user permissions",
)
def get_my_permissions(
    current_user: User = Depends(get_current_user),
    authz: AuthorizationService = Depends(get_authz),
) -> list[str]:
    return sorted(authz.list_user_permissions(current_user.id))


@router.get(
    "",
    response_model=list[UserListEntry],
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List all users (admin)",
)
def list_users(
    current_user: User = Depends(get_current_user),
    authz: AuthorizationService = Depends(get_authz),
    auth: Authenticator = Depends(get_authenticator),
) -> list[UserListEntry]:
    if not authz.has(current_user.id, PERM_USER_MANAGE):
        raise Forbidden("You do not have permission to list users")
    from aegis.auth import _read_ndjson, _dedup_by_field
    import os
    path = os.path.join(auth.data_dir, "users.ndjson")
    records = _read_ndjson(path)
    deduped = _dedup_by_field(records, "id")
    users_list = [auth.user_store.get_by_id(r["id"]) for r in deduped.values()]
    users_list = [u for u in users_list if u is not None]
    return [
        UserListEntry(
            user_id=u.id,
            username=u.username,
            role=u.role,
            active=u.active,
            created_at=u.created_at,
        )
        for u in users_list
    ]


@router.post(
    "/role",
    response_model=UserListEntry,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
    summary="Set a user's role (admin)",
)
def set_role(
    body: SetRoleRequest,
    current_user: User = Depends(get_current_user),
    authz: AuthorizationService = Depends(get_authz),
    auth: Authenticator = Depends(get_authenticator),
) -> UserListEntry:
    if not authz.has(current_user.id, PERM_USER_MANAGE):
        raise Forbidden("You do not have permission to manage user roles")
    target = auth.get_user_by_username(body.username)
    if target is None:
        raise NotFound(f"User {body.username!r} not found")
    if target.id == current_user.id:
        raise Forbidden("You cannot change your own role")
    from aegis.rbac import AuthorizationError, Role
    valid_roles = {r.value for r in Role}
    if body.role.upper() not in valid_roles:
        raise Forbidden(f"Invalid role {body.role!r}")
    try:
        AuthorizationService.require_mfa_for_admin_assignment(target, body.role.upper())
    except AuthorizationError as e:
        raise Forbidden(str(e))
    updated = auth.set_user_role(target.id, body.role.upper())
    authz.audit_privileged_action(
        actor_id=current_user.id,
        operation="user.role.set",
        target_id=target.id,
        result="SUCCESS",
        target_user_id=target.id,
        reason=f"Role changed from {target.role} to {body.role.upper()}",
    )
    return UserListEntry(
        user_id=updated.id,
        username=updated.username,
        role=updated.role,
        active=updated.active,
        created_at=updated.created_at,
    )
