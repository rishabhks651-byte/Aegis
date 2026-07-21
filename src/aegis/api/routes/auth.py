from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Union

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
    MfaConfirmRequest,
    MfaDisableResponse,
    MfaGenerateResponse,
    MfaLoginResponse,
    MfaRecoveryCodesResponse,
    MfaRecoveryRequest,
    MfaSetupConfirmRequest,
    MfaStatusResponse,
    MfaVerifyRequest,
    PermissionsResponse,
)
from aegis.auth import User, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=Union[LoginResponse, MfaLoginResponse],
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Authenticate with username and password",
)
def login(
    body: LoginRequest,
    auth: Authenticator = Depends(get_authenticator),
    limiter: RateLimiter = Depends(get_rate_limiter),
    _=Depends(require_rate_limit),
) -> Union[LoginResponse, MfaLoginResponse]:
    """Authenticate and receive a bearer session token.

    If the user has MFA enabled, returns a ``pending_mfa_token`` instead of
    a session token.  The caller must then call ``/mfa/verify`` or
    ``/mfa/recovery`` with that token to complete authentication.

    Returns generic error on invalid credentials (no username enumeration).
    Password rate limiting is applied per IP.
    """
    user = auth.user_store.get_by_username(body.username)
    if user is None or not user.active:
        raise Unauthorized("Invalid username or password")
    if not verify_password(body.password, user.password_hash):
        raise Unauthorized("Invalid username or password")

    if user.mfa_enabled:
        _, _, pending_token = auth.login_mfa_aware(body.username, body.password)
        return MfaLoginResponse(pending_mfa_token=pending_token)

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


# ---------------------------------------------------------------------------
# MFA endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/mfa/status",
    response_model=MfaStatusResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get MFA status for the current user",
)
def mfa_status(
    current_user: User = Depends(get_current_user),
) -> MfaStatusResponse:
    return MfaStatusResponse(
        mfa_enabled=current_user.mfa_enabled,
        totp_confirmed_at=current_user.totp_confirmed_at,
        recovery_codes_count=len(current_user.recovery_codes),
        recovery_codes_generated_at=current_user.recovery_codes_generated_at,
    )


@router.post(
    "/mfa/setup/generate",
    response_model=MfaGenerateResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Generate a new TOTP secret (MFA setup step 1)",
)
def mfa_generate(
    current_user: User = Depends(get_current_user),
    auth: Authenticator = Depends(get_authenticator),
) -> MfaGenerateResponse:
    secret, uri = auth.generate_totp_secret(current_user.username)
    auth.enable_mfa(current_user.id, current_user.password_hash, secret)
    return MfaGenerateResponse(secret=secret, provisioning_uri=uri)


@router.post(
    "/mfa/setup/confirm",
    response_model=MfaStatusResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Confirm MFA setup by verifying a TOTP code (step 2)",
)
def mfa_confirm(
    body: MfaSetupConfirmRequest,
    current_user: User = Depends(get_current_user),
    auth: Authenticator = Depends(get_authenticator),
) -> MfaStatusResponse:
    try:
        updated = auth.confirm_mfa(current_user.id, body.code)
    except ValueError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))
    return MfaStatusResponse(
        mfa_enabled=updated.mfa_enabled,
        totp_confirmed_at=updated.totp_confirmed_at,
        recovery_codes_count=len(updated.recovery_codes),
        recovery_codes_generated_at=updated.recovery_codes_generated_at,
    )


@router.post(
    "/mfa/verify",
    response_model=LoginResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Verify TOTP code and complete login",
)
def mfa_verify(
    body: MfaVerifyRequest,
    auth: Authenticator = Depends(get_authenticator),
) -> LoginResponse:
    try:
        session, raw_token = auth.verify_totp_and_create_session(
            body.pending_mfa_token, body.code
        )
    except ValueError as e:
        raise Unauthorized(str(e))
    user = auth.get_user_by_id(session.user_id)
    return LoginResponse(
        token=raw_token,
        token_type="bearer",
        user_id=session.user_id,
        username=user.username if user else "",
        role=user.role if user else "USER",
        expires_at=session.expires_at,
    )


@router.post(
    "/mfa/recovery",
    response_model=LoginResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Verify a recovery code and complete login",
)
def mfa_recovery(
    body: MfaRecoveryRequest,
    auth: Authenticator = Depends(get_authenticator),
) -> LoginResponse:
    try:
        session, raw_token = auth.verify_recovery_and_create_session(
            body.pending_mfa_token, body.recovery_code
        )
    except ValueError as e:
        raise Unauthorized(str(e))
    user = auth.get_user_by_id(session.user_id)
    return LoginResponse(
        token=raw_token,
        token_type="bearer",
        user_id=session.user_id,
        username=user.username if user else "",
        role=user.role if user else "USER",
        expires_at=session.expires_at,
    )


@router.post(
    "/mfa/disable",
    response_model=MfaDisableResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Disable MFA for the current user",
)
def mfa_disable(
    current_user: User = Depends(get_current_user),
    auth: Authenticator = Depends(get_authenticator),
) -> MfaDisableResponse:
    auth.disable_mfa(current_user.id)
    return MfaDisableResponse()


@router.post(
    "/mfa/recovery-codes/regenerate",
    response_model=MfaRecoveryCodesResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Regenerate recovery codes",
)
def mfa_regenerate_codes(
    current_user: User = Depends(get_current_user),
    auth: Authenticator = Depends(get_authenticator),
) -> MfaRecoveryCodesResponse:
    _, raw_codes = auth.regenerate_recovery_codes(current_user.id)
    return MfaRecoveryCodesResponse(codes=raw_codes)
