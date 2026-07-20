from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from aegis.api.dependencies import (
    Authenticator,
    AuthorizationService,
    RateLimiter,
    get_authz,
    get_authenticator,
    get_current_user,
    get_rate_limiter,
    require_rate_limit,
)
from aegis.api.exceptions import Unauthorized
from aegis.api.schemas import (
    ErrorResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    MeResponse,
    PermissionsResponse,
)
from aegis.auth import User, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Authenticate with username and password",
)
def login(
    body: LoginRequest,
    auth: Authenticator = Depends(get_authenticator),
    limiter: RateLimiter = Depends(get_rate_limiter),
    _=Depends(require_rate_limit),
) -> LoginResponse:
    """Authenticate and receive a bearer session token.

    Returns generic error on invalid credentials (no username enumeration).
    Password rate limiting is applied per IP.
    """
    user = auth.user_store.get_by_username(body.username)
    if user is None or not user.active:
        raise Unauthorized("Invalid username or password")
    if not verify_password(body.password, user.password_hash):
        raise Unauthorized("Invalid username or password")
    try:
        session, raw_token = auth.session_store.create(user.id)
    except Exception:
        raise Unauthorized("Invalid username or password")
    return LoginResponse(
        token=raw_token,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        role=user.role,
        expires_at=session.expires_at,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Revoke the current session",
)
def logout(
    request: Request,
    auth: Authenticator = Depends(get_authenticator),
) -> LogoutResponse:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[len("Bearer "):].strip()
        try:
            auth.logout(raw_token)
        except Exception:
            pass
    return LogoutResponse()


@router.get(
    "/me",
    response_model=MeResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get the current authenticated user",
)
def me(
    current_user: User = Depends(get_current_user),
) -> MeResponse:
    return MeResponse(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        active=current_user.active,
        created_at=current_user.created_at,
    )


@router.get(
    "/permissions",
    response_model=PermissionsResponse,
    responses={401: {"model": ErrorResponse}},
    summary="List permissions for the current user",
)
def my_permissions(
    current_user: User = Depends(get_current_user),
    authz: AuthorizationService = Depends(get_authz),
) -> PermissionsResponse:
    perms = authz.list_user_permissions(current_user.id)
    return PermissionsResponse(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        permissions=sorted(perms),
    )
