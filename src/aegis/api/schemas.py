from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=1)

class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str
    expires_at: datetime

class LogoutResponse(BaseModel):
    message: str = "Logged out"

class MeResponse(BaseModel):
    user_id: str
    username: str
    role: str
    active: bool
    created_at: datetime

# ---------------------------------------------------------------------------
# Users / RBAC
# ---------------------------------------------------------------------------

class PermissionsResponse(BaseModel):
    user_id: str
    username: str
    role: str
    permissions: list[str]

class UserListEntry(BaseModel):
    user_id: str
    username: str
    role: str
    active: bool
    created_at: datetime

class SetRoleRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    role: str = Field(..., min_length=1)

# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

class AgentCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")

class AgentResponse(BaseModel):
    agent_id: str
    name: str
    user_id: str
    created_at: datetime
    revoked: bool = False
    revoked_at: datetime | None = None

class AgentListResponse(BaseModel):
    agents: list[AgentResponse]

class AgentRevokeResponse(BaseModel):
    agent_id: str
    revoked: bool

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class PolicyApplyRequest(BaseModel):
    yaml_content: str = Field(..., min_length=10)

class PolicyResponse(BaseModel):
    policy_id: str
    name: str
    description: str
    priority: int
    enabled: bool
    rules: list[dict[str, Any]]
    created_at: datetime

class PolicyListEntry(BaseModel):
    policy_id: str
    name: str
    priority: int
    enabled: bool
    rules_count: int

class PolicyListResponse(BaseModel):
    policies: list[PolicyListEntry]

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

class ActionEvaluateRequest(BaseModel):
    agent_id: str
    policy_id: str
    action_type: str = Field(..., min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] | None = None

class ActionEvaluateResponse(BaseModel):
    action_id: str
    decision_id: str
    result: str
    matched: bool
    policy_id: str | None
    policy_name: str | None
    rule_id: str | None
    rule_effect: str | None
    reason: str
    evaluated_at: str

# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------

class FileReadRequest(BaseModel):
    agent_id: str
    policy_id: str
    path: str = Field(..., min_length=1)

class FileReadResponse(BaseModel):
    content: str

# ---------------------------------------------------------------------------
# Process Execution
# ---------------------------------------------------------------------------

class ProcessExecuteRequest(BaseModel):
    agent_id: str
    policy_id: str
    executable_name: str = Field(..., min_length=1)
    args: list[str] = Field(default_factory=list)
    timeout: int = Field(default=30, ge=1, le=300)
    output_limit: int = Field(default=1_048_576, ge=1024, le=104_857_600)

class ProcessExecuteResponse(BaseModel):
    action_id: str
    decision_id: str
    result: str
    reason: str
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    execution_time_ms: int | None = None
    timed_out: bool = False
    output_truncated: bool = False

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

class NetworkRequest(BaseModel):
    agent_id: str
    policy_id: str
    url: str = Field(..., min_length=1)
    method: str = Field(default="GET")
    timeout: int = Field(default=30, ge=1, le=120)
    max_response_size: int = Field(default=10_485_760, ge=1024, le=104_857_600)

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        v = v.upper()
        if v not in ("GET", "HEAD"):
            raise ValueError("method must be GET or HEAD")
        return v

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("URL must have a hostname")
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL scheme must be http or https")
        return v

class NetworkResponse(BaseModel):
    action_id: str
    decision_id: str
    result: str
    reason: str
    status_code: int | None = None
    body: str | None = None
    elapsed_ms: int | None = None
    timed_out: bool = False
    body_truncated: bool = False

# ---------------------------------------------------------------------------
# AI Copilot
# ---------------------------------------------------------------------------

class AIExplainRequest(BaseModel):
    decision_id: str = Field(..., min_length=1)

class AIPolicyReviewRequest(BaseModel):
    policy_id: str = Field(..., min_length=1)

class AIPolicyDraftRequest(BaseModel):
    description: str = Field(..., min_length=10)

class AIResponse(BaseModel):
    content: str

# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------

class PaymentSubmitRequest(BaseModel):
    plan_id: str = Field(..., min_length=1)
    utr: str = Field(..., min_length=1)

class PaymentResponse(BaseModel):
    payment_id: str
    plan_id: str
    amount_minor: int
    currency: str
    destination_upi: str
    submitted_utr: str
    submitted_at: datetime
    status: str
    verification_method: str | None = None
    verified_at: datetime | None = None
    rejection_reason: str | None = None

class PaymentListResponse(BaseModel):
    payments: list[PaymentResponse]

class PaymentVerifyRequest(BaseModel):
    payment_id: str = Field(..., min_length=1)

class PaymentRejectRequest(BaseModel):
    payment_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)

# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------

class SubscriptionResponse(BaseModel):
    subscription_id: str
    user_id: str
    plan_id: str
    plan_name: str = ""
    status: str
    start_time: datetime
    end_time: datetime | None = None
    renewal: bool = True
    payment_id: str | None = None

class EntitlementsResponse(BaseModel):
    user_id: str
    plan_id: str | None
    plan_name: str | None
    status: str | None
    entitlements: dict[str, Any]

# ---------------------------------------------------------------------------
# Standard error
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------

class MfaStatusResponse(BaseModel):
    mfa_enabled: bool
    totp_confirmed_at: datetime | None = None
    recovery_codes_count: int = 0
    recovery_codes_generated_at: datetime | None = None

class MfaGenerateResponse(BaseModel):
    secret: str
    provisioning_uri: str

class MfaConfirmRequest(BaseModel):
    code: str = Field(..., min_length=1)

class MfaSetupConfirmRequest(BaseModel):
    code: str = Field(..., min_length=1)

class MfaVerifyRequest(BaseModel):
    pending_mfa_token: str = Field(..., min_length=1)
    code: str = Field(..., min_length=1)

class MfaRecoveryRequest(BaseModel):
    pending_mfa_token: str = Field(..., min_length=1)
    recovery_code: str = Field(..., min_length=1)

class MfaRecoveryCodesResponse(BaseModel):
    codes: list[str]
    message: str = "Store these codes securely. They will not be shown again."

class MfaLoginResponse(BaseModel):
    mfa_required: bool = True
    pending_mfa_token: str
    message: str = "MFA code required"

class MfaDisableResponse(BaseModel):
    mfa_enabled: bool = False
    message: str = "MFA disabled"

# ---------------------------------------------------------------------------
# Standard error
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    detail: str
    code: str = "error"

class ValidationErrorResponse(BaseModel):
    detail: str
    errors: list[dict[str, Any]] = []
    code: str = "validation_error"

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = ""
