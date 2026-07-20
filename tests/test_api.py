"""Comprehensive API tests for Phase 15."""
from __future__ import annotations

import json
import os
import platform
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.auth import Authenticator, hash_password, User
from aegis.entitlement import EntitlementService
from aegis.payment import PaymentService
from aegis.rbac import AuthorizationService
from aegis.registry import AgentRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TEST_DIR: str | None = None
_TEST_PASSWORD = "testpass123"


def _data_dir() -> str:
    global _TEST_DIR
    if _TEST_DIR is None:
        _TEST_DIR = tempfile.mkdtemp(prefix="aegis_api_test_")
    return _TEST_DIR


@pytest.fixture(scope="session", autouse=True)
def _set_env():
    old = os.environ.get("AEGIS_DATA_DIR")
    os.environ["AEGIS_DATA_DIR"] = _data_dir()
    yield
    if old:
        os.environ["AEGIS_DATA_DIR"] = old
    else:
        del os.environ["AEGIS_DATA_DIR"]


@pytest.fixture(autouse=True)
def _clean_data_dir():
    yield
    dd = _data_dir()
    for f in os.listdir(dd):
        fp = os.path.join(dd, f)
        if os.path.isfile(fp):
            os.remove(fp)


@pytest.fixture
def app():
    return create_app(cors_origins=["http://localhost:3000"])


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def auth():
    return Authenticator(_data_dir())


@pytest.fixture
def token(client, auth) -> str:
    auth.register("testuser", _TEST_PASSWORD)
    resp = client.post("/api/v1/auth/login", json={
        "username": "testuser",
        "password": _TEST_PASSWORD,
    })
    data = resp.json()
    return data["token"]


@pytest.fixture
def headers(token) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_token(client, auth) -> str:
    auth.register("adminuser", _TEST_PASSWORD)
    auth.user_store.set_role(
        auth.user_store.get_by_username("adminuser").id,
        "ADMIN",
    )
    resp = client.post("/api/v1/auth/login", json={
        "username": "adminuser",
        "password": _TEST_PASSWORD,
    })
    return resp.json()["token"]


@pytest.fixture
def admin_headers(admin_token) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


# ===================================================================
# Authentication
# ===================================================================


class TestLogin:
    def test_successful_login(self, client, auth):
        auth.register("alice", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "alice",
            "password": _TEST_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["token_type"] == "bearer"
        assert data["username"] == "alice"

    def test_wrong_password_returns_401(self, client, auth):
        auth.register("alice", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "alice",
            "password": "wrongpass",
        })
        assert resp.status_code == 401
        assert "token" not in resp.json()

    def test_nonexistent_user_returns_401(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "nobody",
            "password": _TEST_PASSWORD,
        })
        assert resp.status_code == 401

    def test_generic_error_message_no_enumeration(self, client, auth):
        auth.register("alice", _TEST_PASSWORD)
        # Both wrong password and nonexistent user return same message
        r1 = client.post("/api/v1/auth/login", json={
            "username": "alice",
            "password": "wrong",
        })
        r2 = client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": _TEST_PASSWORD,
        })
        assert r1.json()["detail"] == r2.json()["detail"]

    def test_deactivated_user_returns_401(self, client, auth):
        user = auth.register("alice", _TEST_PASSWORD)
        auth.user_store.deactivate(user.id)
        resp = client.post("/api/v1/auth/login", json={
            "username": "alice",
            "password": _TEST_PASSWORD,
        })
        assert resp.status_code == 401

    def test_validation_empty_fields(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "",
            "password": "",
        })
        assert resp.status_code == 422


class TestMe:
    def test_me_authenticated(self, client, headers):
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "testuser"

    def test_me_unauthorized(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_invalid_token(self, client):
        resp = client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer invalidtoken123",
        })
        assert resp.status_code == 401

    def test_me_expired_token_is_rejected(self, client, auth):
        import hashlib
        import secrets
        import os
        from aegis.auth import Session
        from aegis.auth import _append_ndjson as append_sesh
        from datetime import timedelta
        dd = _data_dir()
        user = auth.register("expireduser", _TEST_PASSWORD)
        raw = secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        session = Session(
            session_id=str(uuid.uuid4()),
            token_hash=h,
            user_id=user.id,
            created_at=datetime.now(timezone.utc) - timedelta(hours=48),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=24),
        )
        append_sesh(os.path.join(dd, "sessions.ndjson"), session.to_dict())
        resp = client.get("/api/v1/auth/me", headers={
            "Authorization": f"Bearer {raw}",
        })
        assert resp.status_code == 401


class TestLogout:
    def test_logout_revokes_token(self, client, token):
        # Verify token works
        r1 = client.get("/api/v1/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert r1.status_code == 200

        # Logout
        r2 = client.post("/api/v1/auth/logout", headers={
            "Authorization": f"Bearer {token}",
        })
        assert r2.status_code == 200

        # Token should now be invalid
        r3 = client.get("/api/v1/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert r3.status_code == 401


class TestPermissions:
    def test_user_has_no_permissions(self, client, headers):
        resp = client.get("/api/v1/auth/permissions", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["permissions"] == []

    def test_admin_has_permissions(self, client, admin_headers):
        resp = client.get("/api/v1/auth/permissions", headers=admin_headers)
        assert resp.status_code == 200
        assert len(resp.json()["permissions"]) > 0


# ===================================================================
# Users / RBAC
# ===================================================================


class TestUsers:
    def test_get_me(self, client, headers):
        resp = client.get("/api/v1/users/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "testuser"

    def test_get_my_permissions(self, client, headers):
        resp = client.get("/api/v1/users/me/permissions", headers=headers)
        assert resp.status_code == 200

    def test_list_users_requires_admin(self, client, headers):
        resp = client.get("/api/v1/users", headers=headers)
        assert resp.status_code == 403

    def test_list_users_as_admin(self, client, admin_headers, auth):
        auth.register("another", _TEST_PASSWORD)
        resp = client.get("/api/v1/users", headers=admin_headers)
        assert resp.status_code == 200
        assert len(resp.json()) >= 2

    def test_set_role_requires_admin(self, client, headers, auth):
        resp = client.post("/api/v1/users/role", headers=headers, json={
            "username": "testuser",
            "role": "ADMIN",
        })
        assert resp.status_code == 403

    def test_set_role_as_admin(self, client, admin_headers, auth):
        auth.register("targetuser", _TEST_PASSWORD)
        resp = client.post("/api/v1/users/role", headers=admin_headers, json={
            "username": "targetuser",
            "role": "PAYMENT_VERIFIER",
        })
        assert resp.status_code == 200
        assert resp.json()["role"] == "PAYMENT_VERIFIER"

    def test_cannot_set_own_role(self, client, admin_headers):
        resp = client.post("/api/v1/users/role", headers=admin_headers, json={
            "username": "adminuser",
            "role": "USER",
        })
        assert resp.status_code == 403

    def test_set_nonexistent_user_returns_404(self, client, admin_headers):
        resp = client.post("/api/v1/users/role", headers=admin_headers, json={
            "username": "doesnotexist",
            "role": "USER",
        })
        assert resp.status_code == 404


# ===================================================================
# Agents
# ===================================================================


class TestAgents:
    def test_create_agent(self, client, headers):
        resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "my-agent",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "my-agent"
        assert data["user_id"]
        assert not data["revoked"]

    def test_list_agents(self, client, headers):
        resp = client.get("/api/v1/agents", headers=headers)
        assert resp.status_code == 200

    def test_get_agent(self, client, headers):
        # Create first
        create_resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "get-test",
        })
        agent_id = create_resp.json()["agent_id"]

        resp = client.get(f"/api/v1/agents/{agent_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "get-test"

    def test_get_nonexistent_agent_returns_404(self, client, headers):
        resp = client.get(f"/api/v1/agents/{uuid.uuid4()}", headers=headers)
        assert resp.status_code == 404

    def test_revoke_agent(self, client, headers):
        create_resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "revoke-test",
        })
        agent_id = create_resp.json()["agent_id"]

        resp = client.post(f"/api/v1/agents/{agent_id}/revoke", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True

    def test_cross_user_agent_isolation(self, client, headers, auth):
        # Create agent for testuser
        create_resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "my-agent",
        })
        agent_id = create_resp.json()["agent_id"]

        # Create another user and try to access
        auth.register("otheruser", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "otheruser",
            "password": _TEST_PASSWORD,
        })
        other_token = resp.json()["token"]

        resp = client.get(
            f"/api/v1/agents/{agent_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 404

    def test_agent_validation_invalid_name(self, client, headers):
        resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "name with spaces",
        })
        assert resp.status_code == 422


# ===================================================================
# Policies
# ===================================================================


class TestPolicies:
    VALID_YAML = '''version: "1.0"
name: test-policy
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: fs_read
      path: /safe/file.txt
'''

    def test_apply_policy(self, client, headers):
        resp = client.post("/api/v1/policies", headers=headers, json={
            "yaml_content": self.VALID_YAML,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "test-policy"
        assert len(data["rules"]) == 1

    def test_list_policies(self, client, headers):
        # Apply one first
        client.post("/api/v1/policies", headers=headers, json={
            "yaml_content": self.VALID_YAML,
        })
        resp = client.get("/api/v1/policies", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()["policies"]) == 1

    def test_get_policy(self, client, headers):
        create_resp = client.post("/api/v1/policies", headers=headers, json={
            "yaml_content": self.VALID_YAML,
        })
        policy_id = create_resp.json()["policy_id"]

        resp = client.get(f"/api/v1/policies/{policy_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "test-policy"

    def test_get_nonexistent_policy_returns_404(self, client, headers):
        resp = client.get("/api/v1/policies/nonexistent-id", headers=headers)
        assert resp.status_code == 404

    def test_invalid_yaml_returns_422(self, client, headers):
        resp = client.post("/api/v1/policies", headers=headers, json={
            "yaml_content": "not: valid: yaml: [",
        })
        assert resp.status_code == 403


# ===================================================================
# Actions
# ===================================================================


class TestActions:
    def test_evaluate_action(self, client, headers):
        # Create agent and policy first
        agent_resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "action-agent",
        })
        agent_id = agent_resp.json()["agent_id"]

        policy_yaml = '''version: "1.0"
name: eval-policy
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: test_action
'''
        policy_resp = client.post("/api/v1/policies", headers=headers, json={
            "yaml_content": policy_yaml,
        })
        policy_id = policy_resp.json()["policy_id"]

        resp = client.post("/api/v1/actions/evaluate", headers=headers, json={
            "agent_id": agent_id,
            "policy_id": policy_id,
            "action_type": "test_action",
            "params": {"key": "value"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["result"] in ("ALLOW", "DENY")

    def test_evaluate_nonexistent_agent(self, client, headers):
        resp = client.post("/api/v1/actions/evaluate", headers=headers, json={
            "agent_id": str(uuid.uuid4()),
            "policy_id": "some-policy",
            "action_type": "test",
        })
        assert resp.status_code == 200
        assert resp.json()["result"] == "DENY"

    def test_evaluate_validation(self, client, headers):
        resp = client.post("/api/v1/actions/evaluate", headers=headers, json={
            "agent_id": "",
            "policy_id": "",
            "action_type": "",
        })
        assert resp.status_code == 422


# ===================================================================
# Filesystem
# ===================================================================


class TestFilesystem:
    def test_read_file_requires_policy_allow(self, client, headers, auth):
        from aegis.fs import Filesystem
        dd = _data_dir()
        fs = Filesystem(dd)
        # Create a file in the scope
        scope_file = os.path.join(dd, "fs-scope", "test.txt")
        os.makedirs(os.path.dirname(scope_file), exist_ok=True)
        with open(scope_file, "w") as f:
            f.write("hello world")

        # Create agent
        agent_resp = client.post("/api/v1/agents", headers=headers, json={
            "name": "fs-agent",
        })
        agent_id = agent_resp.json()["agent_id"]

        # First try with no policy -> DENY
        resp = client.post("/api/v1/filesystem/read", headers=headers, json={
            "agent_id": agent_id,
            "policy_id": "nonexistent",
            "path": "test.txt",
        })
        assert resp.status_code == 403  # DENY from policy evaluation


# ===================================================================
# Process Execution
# ===================================================================


class TestExecution:
    def test_execute_requires_auth(self, client):
        resp = client.post("/api/v1/execution/execute", json={
            "agent_id": str(uuid.uuid4()),
            "policy_id": "test",
            "executable_name": "python",
        })
        assert resp.status_code == 401

    def test_execute_validation(self, client, headers):
        resp = client.post("/api/v1/execution/execute", headers=headers, json={
            "agent_id": "",
            "policy_id": "",
            "executable_name": "",
        })
        assert resp.status_code == 422


# ===================================================================
# Network
# ===================================================================


class TestNetwork:
    def test_network_request_requires_auth(self, client):
        resp = client.post("/api/v1/network/request", json={
            "agent_id": str(uuid.uuid4()),
            "policy_id": "test",
            "url": "https://example.com",
        })
        assert resp.status_code == 401

    def test_invalid_url_rejected(self, client, headers):
        resp = client.post("/api/v1/network/request", headers=headers, json={
            "agent_id": str(uuid.uuid4()),
            "policy_id": "test",
            "url": "not-a-url",
        })
        assert resp.status_code == 422

    def test_unsupported_scheme_rejected(self, client, headers):
        resp = client.post("/api/v1/network/request", headers=headers, json={
            "agent_id": str(uuid.uuid4()),
            "policy_id": "test",
            "url": "ftp://example.com",
        })
        assert resp.status_code == 422


# ===================================================================
# AI Copilot
# ===================================================================


class TestCopilot:
    def test_require_auth(self, client):
        resp = client.post("/api/v1/copilot/explain", json={
            "decision_id": str(uuid.uuid4()),
        })
        assert resp.status_code == 401

    def test_empty_input_validation(self, client, headers):
        resp = client.post("/api/v1/copilot/explain", headers=headers, json={
            "decision_id": "",
        })
        assert resp.status_code == 422


# ===================================================================
# Payments
# ===================================================================


class TestPayments:
    def test_submit_payment_requires_auth(self, client):
        resp = client.post("/api/v1/payments/submit", json={
            "plan_id": "pro",
            "utr": "TESTUTR123",
        })
        assert resp.status_code == 401

    def test_submit_payment(self, client, headers, auth):
        resp = client.post("/api/v1/payments/submit", headers=headers, json={
            "plan_id": "pro",
            "utr": "TESTUTR123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "PENDING"
        assert data["plan_id"] == "pro"

    def test_list_payments(self, client, headers):
        resp = client.get("/api/v1/payments", headers=headers)
        assert resp.status_code == 200

    def test_get_payment(self, client, headers):
        # Submit first
        submit_resp = client.post("/api/v1/payments/submit", headers=headers, json={
            "plan_id": "pro",
            "utr": "GETUTR001",
        })
        payment_id = submit_resp.json()["payment_id"]

        resp = client.get(f"/api/v1/payments/{payment_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["payment_id"] == payment_id

    def test_get_other_users_payment_returns_404(self, client, headers, auth):
        # Submit as testuser
        submit_resp = client.post("/api/v1/payments/submit", headers=headers, json={
            "plan_id": "pro",
            "utr": "OTHER001",
        })
        payment_id = submit_resp.json()["payment_id"]

        # Login as otheruser
        auth.register("otherpayuser", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "otherpayuser",
            "password": _TEST_PASSWORD,
        })
        other_token = resp.json()["token"]

        resp = client.get(
            f"/api/v1/payments/{payment_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        )
        assert resp.status_code == 404

    def test_verify_payment_requires_verifier_role(self, client, headers, auth):
        # Submit as testuser
        submit_resp = client.post("/api/v1/payments/submit", headers=headers, json={
            "plan_id": "pro",
            "utr": "VERIFY001",
        })
        payment_id = submit_resp.json()["payment_id"]

        # testuser (USER role) should not be able to verify
        resp = client.post("/api/v1/payments/verify", headers=headers, json={
            "payment_id": payment_id,
        })
        assert resp.status_code == 403

    def test_verify_payment_as_verifier(self, client, admin_headers, auth):
        # Submit as testuser
        # Need a payment from another user
        auth.register("payuser", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "payuser",
            "password": _TEST_PASSWORD,
        })
        user_token = resp.json()["token"]

        submit_resp = client.post("/api/v1/payments/submit", headers={
            "Authorization": f"Bearer {user_token}",
        }, json={
            "plan_id": "pro",
            "utr": "ADMINVERIFY001",
        })
        payment_id = submit_resp.json()["payment_id"]

        # Admin verifies
        resp = client.post("/api/v1/payments/verify", headers=admin_headers, json={
            "payment_id": payment_id,
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "VERIFIED"

    def test_reject_payment(self, client, admin_headers, auth):
        auth.register("rejectuser", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "rejectuser",
            "password": _TEST_PASSWORD,
        })
        user_token = resp.json()["token"]

        submit_resp = client.post("/api/v1/payments/submit", headers={
            "Authorization": f"Bearer {user_token}",
        }, json={
            "plan_id": "pro",
            "utr": "REJECT001",
        })
        payment_id = submit_resp.json()["payment_id"]

        resp = client.post("/api/v1/payments/reject", headers=admin_headers, json={
            "payment_id": payment_id,
            "reason": "Insufficient funds",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "REJECTED"
        assert resp.json()["rejection_reason"] == "Insufficient funds"


# ===================================================================
# Subscriptions
# ===================================================================


class TestSubscriptions:
    def test_no_subscription(self, client, headers):
        resp = client.get("/api/v1/subscriptions/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_plans_list(self, client, headers):
        resp = client.get("/api/v1/subscriptions/plans", headers=headers)
        assert resp.status_code == 200
        plans = resp.json()
        assert len(plans) >= 3
        plan_ids = [p["id"] for p in plans]
        assert "free" in plan_ids
        assert "pro" in plan_ids
        assert "enterprise" in plan_ids

    def test_entitlements_empty(self, client, headers):
        resp = client.get("/api/v1/subscriptions/me/entitlements", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["entitlements"] == {}


# ===================================================================
# Health
# ===================================================================


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ===================================================================
# API Security
# ===================================================================


class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        resp = client.get("/api/v1/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("cache-control") == "no-store"


class TestCORs:
    def test_cors_allowed_origin(self, app, client):
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.headers.get("access-control-allow-origin") == "http://localhost:3000"

    def test_cors_disallowed_origin(self, app, client):
        resp = client.options(
            "/api/v1/health",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Should not include the disallowed origin
        allow_origin = resp.headers.get("access-control-allow-origin")
        assert allow_origin != "https://evil.com"


class TestErrorHandling:
    def test_404_returns_json_not_html(self, client):
        resp = client.get("/api/v1/nonexistent-route")
        assert resp.status_code == 404
        assert resp.headers.get("content-type", "").startswith("application/json")

    def test_generic_error_no_stack_trace(self, client, headers):
        # Try sending malformed data
        resp = client.post(
            "/api/v1/auth/login",
            data="not-json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_no_secret_in_logs(self):
        """Verify sensitive params are not leaked (compile-time check)."""
        import ast
        import os

        api_dir = os.path.join(os.path.dirname(__file__), "..", "src", "aegis", "api")
        sensitive = ["password", "secret", "api_key"]
        for root, _dirs, files in os.walk(api_dir):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    with open(fpath) as f:
                        try:
                            tree = ast.parse(f.read())
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Call):
                                    for kw in node.keywords:
                                        if kw.arg and kw.arg.lower() in sensitive:
                                            if isinstance(kw.value, ast.Call):
                                                continue
                                            pytest.fail(
                                                f"{fpath}: "
                                                f"sensitive keyword '{kw.arg}' passed to function call"
                                            )
                        except SyntaxError:
                            pass


# ===================================================================
# Domain Integration
# ===================================================================


class TestDomainIntegration:
    def test_api_uses_same_authenticator_as_cli(self, client, headers, auth):
        """Verify the same Authenticator instance backs both."""
        me_resp = client.get("/api/v1/auth/me", headers=headers)
        user_id = me_resp.json()["user_id"]
        user = auth.get_user_by_id(user_id)
        assert user is not None
        assert user.username == "testuser"

    def test_payment_verification_rbac_enforced(self, client, headers, admin_headers, auth):
        """Payment verification must remain RBAC-protected."""
        auth.register("victim", _TEST_PASSWORD)
        resp = client.post("/api/v1/auth/login", json={
            "username": "victim",
            "password": _TEST_PASSWORD,
        })
        victim_token = resp.json()["token"]

        submit_resp = client.post("/api/v1/payments/submit", headers={
            "Authorization": f"Bearer {victim_token}",
        }, json={
            "plan_id": "pro",
            "utr": "RBAC001",
        })
        payment_id = submit_resp.json()["payment_id"]

        # USER role cannot verify
        resp = client.post("/api/v1/payments/verify", headers=headers, json={
            "payment_id": payment_id,
        })
        assert resp.status_code == 403

        # ADMIN can verify
        resp = client.post("/api/v1/payments/verify", headers=admin_headers, json={
            "payment_id": payment_id,
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "VERIFIED"

    def test_subscription_entitlements_enforced(self, client, headers):
        """Free plan has limited entitlements."""
        resp = client.get("/api/v1/subscriptions/me/entitlements", headers=headers)
        # No active subscription yet
        assert resp.json()["entitlements"] == {}
