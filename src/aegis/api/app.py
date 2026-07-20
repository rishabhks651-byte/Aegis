from __future__ import annotations

import os

from fastapi import FastAPI

from aegis import __version__
from aegis.api.exceptions import register_exception_handlers
from aegis.api.middleware import configure_middleware
from aegis.api.routes import (
    actions,
    agents,
    auth,
    copilot,
    execution,
    filesystem,
    network,
    payments,
    policies,
    subscriptions,
    users,
)


def create_app(cors_origins: list[str] | None = None) -> FastAPI:
    """Create and configure the Aegis API application.

    Args:
        cors_origins: Allowed CORS origins. Defaults to
                      ``AEGIS_CORS_ORIGINS`` env var (comma-separated)
                      or empty (no cross-origin).
    """
    if cors_origins is None:
        raw = os.environ.get("AEGIS_CORS_ORIGINS", "").strip()
        cors_origins = [o.strip() for o in raw.split(",") if o.strip()] if raw else []

    app = FastAPI(
        title="Aegis API",
        description="Security gateway for AI and software agents",
        version=__version__,
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
        redoc_url=None,
    )

    configure_middleware(app, cors_origins)
    register_exception_handlers(app)

    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(agents.router)
    app.include_router(policies.router)
    app.include_router(actions.router)
    app.include_router(filesystem.router)
    app.include_router(execution.router)
    app.include_router(network.router)
    app.include_router(copilot.router)
    app.include_router(payments.router)
    app.include_router(subscriptions.router)

    @app.get("/api/v1/health", tags=["Health"])
    def health():
        from aegis.api.schemas import HealthResponse
        return HealthResponse(version=__version__)

    return app
