from __future__ import annotations

import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


_SENSITIVE_HEADERS = frozenset({
    "authorization", "cookie", "x-api-key", "proxy-authorization",
})

_SENSITIVE_PARAMS = frozenset({
    "password", "token", "secret", "api_key", "api-key", "apikey",
    "passwd", "credential", "auth",
})


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Log requests without sensitive data."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        start = time.monotonic()

        response = await call_next(request)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        safe_path = str(request.url.path)
        method = request.method
        status = response.status_code
        print(
            f"[{request_id}] {method} {safe_path} -> {status} ({elapsed_ms}ms)",
            flush=True,
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def configure_cors(app: FastAPI, origins: list[str] | None = None) -> None:
    """Configure CORS. Defaults to no cross-origin access."""
    from fastapi.middleware.cors import CORSMiddleware

    allowed = origins or []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_credentials=bool(allowed),
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


def configure_middleware(app: FastAPI, cors_origins: list[str] | None = None) -> None:
    configure_cors(app, cors_origins)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLogMiddleware)
