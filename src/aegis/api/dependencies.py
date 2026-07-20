from __future__ import annotations

from typing import AsyncIterator

from fastapi import Depends, Header, Request

from aegis.ai import AICopilot
from aegis.api.exceptions import Unauthorized
from aegis.api.rate_limiter import RateLimiter
from aegis.auth import Authenticator, User
from aegis.entitlement import EntitlementService
from aegis.fs import Filesystem
from aegis.gateway import Gateway
from aegis.payment import PaymentService
from aegis.rbac import AuthorizationService
from aegis.settings import get_data_dir


def get_authenticator(data_dir: str = Depends(get_data_dir)) -> Authenticator:
    return Authenticator(data_dir)


def get_authz(data_dir: str = Depends(get_data_dir)) -> AuthorizationService:
    return AuthorizationService(data_dir)


def get_entitlement(data_dir: str = Depends(get_data_dir)) -> EntitlementService:
    return EntitlementService(data_dir)


def get_gateway(data_dir: str = Depends(get_data_dir)) -> Gateway:
    return Gateway(data_dir)


def get_payment_service(data_dir: str = Depends(get_data_dir)) -> PaymentService:
    return PaymentService(data_dir)


def get_filesystem(data_dir: str = Depends(get_data_dir)) -> Filesystem:
    return Filesystem(data_dir)


def get_ai_copilot(data_dir: str = Depends(get_data_dir)) -> AICopilot:
    return AICopilot(data_dir)


def get_rate_limiter(data_dir: str = Depends(get_data_dir)) -> RateLimiter:
    return RateLimiter(data_dir)


async def get_current_user(
    request: Request,
    auth: Authenticator = Depends(get_authenticator),
) -> User:
    """Extract and validate the bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise Unauthorized("Missing or invalid Authorization header")
    raw_token = auth_header[len("Bearer "):].strip()
    if not raw_token:
        raise Unauthorized("Missing or invalid Authorization header")
    user = auth.validate_session(raw_token)
    if user is None:
        raise Unauthorized("Invalid or expired session token")
    return user


async def require_rate_limit(
    request: Request,
    limiter: RateLimiter = Depends(get_rate_limiter),
) -> None:
    """Apply rate limiting based on client IP."""
    from aegis.api.exceptions import RateLimited

    client_ip = request.client.host if request.client else "unknown"
    if not limiter.check(client_ip):
        raise RateLimited("Too many requests. Try again later.")
