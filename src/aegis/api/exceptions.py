from __future__ import annotations

from fastapi import Request, status
from fastapi.responses import JSONResponse

from aegis.api.schemas import ErrorResponse


class AppException(Exception):
    """Base application exception with HTTP status code and detail."""

    def __init__(self, status_code: int, detail: str, code: str = "error") -> None:
        self.status_code = status_code
        self.detail = detail
        self.code = code


class NotFound(AppException):
    def __init__(self, detail: str = "Not found") -> None:
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail, code="not_found")


class Unauthorized(AppException):
    def __init__(self, detail: str = "Unauthorized") -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, code="unauthorized")


class Forbidden(AppException):
    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail, code="forbidden")


class Conflict(AppException):
    def __init__(self, detail: str = "Conflict") -> None:
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=detail, code="conflict")


class RateLimited(AppException):
    def __init__(self, detail: str = "Rate limit exceeded") -> None:
        super().__init__(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail, code="rate_limited")


_EXCEPTION_HANDLERS: dict[type[Exception], int] = {
    ValueError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    TypeError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    KeyError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    LookupError: status.HTTP_404_NOT_FOUND,
    PermissionError: status.HTTP_403_FORBIDDEN,
}


def _safe_detail(exc: Exception) -> str:
    """Return a safe generic error message for unexpected exceptions."""
    if isinstance(exc, AppException):
        return exc.detail
    return "Internal server error"


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(detail=exc.detail, code=exc.code).model_dump(),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    status_code = _EXCEPTION_HANDLERS.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)
    detail = _safe_detail(exc)
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(detail=detail).model_dump(),
    )


def register_exception_handlers(app: "FastAPI") -> None:
    from fastapi import FastAPI

    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)
