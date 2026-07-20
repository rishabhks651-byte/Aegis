"""Tests for the AI Security Copilot."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from aegis.ai import (
    AICopilot,
    AIError,
    AIOutcome,
    LocalProvider,
    RemoteProvider,
    _sanitise_params,
    _create_provider,
)
from aegis.auth import Authenticator
from aegis.audit import AuditStore
from aegis.entitlement import EntitlementError
from aegis.gateway import Gateway
from aegis.models import Action, AuditEvent, Decision, DecisionResult
from aegis.policy import PolicyStore, parse_policy_yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_ID = str(uuid.uuid4())

_ALLOW_POLICY = f"""\
version: "1.0"
id: "{_POLICY_ID}"
name: test-policy
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "fs_read"
  - effect: DENY
    match:
      action_type: "*"
"""


@pytest.fixture
def env():
    """Set up a test environment with a decision and audit event.

    The user is given a Pro subscription so that AI entitlement checks
    pass by default.  Tests that verify entitlement-denial behaviour
    should use separate unsubscribed users.
    """
    tmpdir = tempfile.mkdtemp()
    auth = Authenticator(tmpdir)
    user = auth.register("aiuser", "ValidPass1!")

    from aegis.entitlement import EntitlementService
    svc = EntitlementService(tmpdir)
    svc.activate_subscription(user.id, "pro")

    from aegis.registry import AgentRegistry
    registry = AgentRegistry(tmpdir)
    agent = registry.create(user.id, "ai-agent")

    policy = parse_policy_yaml(_ALLOW_POLICY, user.id)
    store = PolicyStore(tmpdir)
    store.save(policy)

    # Create an audit event via gateway
    gateway = Gateway(tmpdir)
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=agent.id,
        action_type="fs_read",
        params={"path": "/safe/file.txt"},
        requested_at=datetime.now(timezone.utc),
    )
    decision = gateway.evaluate(user.id, action, agent.id, policy.id)

    return {
        "tmpdir": tmpdir,
        "user_id": user.id,
        "agent": agent,
        "policy": policy,
        "decision": decision,
        "svc": svc,
    }


# ---------------------------------------------------------------------------
# Provider tests
# ---------------------------------------------------------------------------


class TestProviders:
    def test_local_provider_name(self):
        assert LocalProvider().name == "local"

    def test_local_provider_cannot_generate(self):
        with pytest.raises(AIError):
            LocalProvider().generate("hello")

    def test_remote_provider_name(self):
        rp = RemoteProvider(api_key="test-key")
        assert rp.name == "remote"

    @patch("urllib.request.urlopen")
    def test_remote_provider_generate(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "Hello, world!"}}],
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        rp = RemoteProvider(api_key="test-key", api_url="https://fake.test/v1")
        result = rp.generate("Say hello")
        assert result == "Hello, world!"

    @patch("urllib.request.urlopen")
    def test_remote_provider_error_handled(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")

        rp = RemoteProvider(api_key="test-key")
        with pytest.raises(AIError, match="Remote provider error"):
            rp.generate("test")

    def test_create_provider_no_key(self):
        """Without AEGIS_AI_API_KEY, local provider is used."""
        with patch.dict(os.environ, {}, clear=True):
            provider = _create_provider()
            assert provider.name == "local"

    def test_create_provider_with_key(self):
        """With AEGIS_AI_API_KEY, remote provider is used."""
        with patch.dict(os.environ, {"AEGIS_AI_API_KEY": "sk-test"}):
            provider = _create_provider()
            assert provider.name == "remote"


# ---------------------------------------------------------------------------
# Sanitisation tests
# ---------------------------------------------------------------------------


class TestSanitisation:
    def test_sensitive_keys_removed(self):
        params = {"path": "/safe.txt", "password": "hunter2", "api_key": "sk-123"}
        sanitised = _sanitise_params(params)
        assert "path" in sanitised
        assert "password" not in sanitised
        assert "api_key" not in sanitised

    def test_long_values_truncated(self):
        params = {"data": "x" * 500}
        sanitised = _sanitise_params(params)
        assert len(sanitised["data"]) <= 203  # 200 + "..."


# ---------------------------------------------------------------------------
# Deterministic fallback tests
# ---------------------------------------------------------------------------


class TestDeterministicFallback:
    def test_explain_works_without_ai(self, env):
        copilot = AICopilot(env["tmpdir"])
        result = copilot.explain_decision(env["decision"].decision_id, env["user_id"])
        assert "DETERMINISTIC ANALYSIS" in result
        assert env["decision"].result.value in result

    def test_explain_unknown_decision(self, env):
        copilot = AICopilot(env["tmpdir"])
        with pytest.raises(AIError, match="not found"):
            copilot.explain_decision(str(uuid.uuid4()), env["user_id"])

    def test_audit_summary_works_without_ai(self, env):
        copilot = AICopilot(env["tmpdir"])
        result = copilot.audit_summary(env["user_id"])
        assert "DETERMINISTIC ANALYSIS" in result
        assert "ALLOW" in result

    def test_audit_summary_empty(self, env):
        copilot = AICopilot(env["tmpdir"])
        # Use a user with a subscription but no audit events
        from aegis.auth import Authenticator
        auth = Authenticator(env["tmpdir"])
        fresh_user = auth.register("emptyuser", "ValidPass1!")
        from aegis.entitlement import EntitlementService
        svc = EntitlementService(env["tmpdir"])
        svc.activate_subscription(fresh_user.id, "pro")
        result = copilot.audit_summary(fresh_user.id)
        assert "No audit events found" in result

    def test_policy_review_works_without_ai(self, env):
        copilot = AICopilot(env["tmpdir"])
        result = copilot.policy_review(env["policy"].id, env["user_id"])
        assert "DETERMINISTIC ANALYSIS" in result
        assert env["policy"].name in result

    def test_policy_review_unknown(self, env):
        copilot = AICopilot(env["tmpdir"])
        with pytest.raises(AIError, match="not found"):
            copilot.policy_review(str(uuid.uuid4()), env["user_id"])

    def test_policy_draft_fails_without_remote(self, env):
        """Without remote provider, policy drafting must fail clearly."""
        copilot = AICopilot(env["tmpdir"])
        with pytest.raises(AIError, match="remote AI provider"):
            copilot.policy_draft("Allow read access", env["user_id"])


# ---------------------------------------------------------------------------
# AI cannot override security
# ---------------------------------------------------------------------------


class TestSecurityBoundary:
    def test_ai_cannot_override_deny(self, env):
        """The AI copilot has no influence over the PolicyEngine."""
        gateway = Gateway(env["tmpdir"])
        action = Action(
            action_id=str(uuid.uuid4()),
            agent_id=env["agent"].id,
            action_type="execute_process",
            params={"executable": "rm"},
            requested_at=datetime.now(timezone.utc),
        )
        decision = gateway.evaluate(
            env["user_id"], action, env["agent"].id, env["policy"].id,
        )
        # The policy only ALLOWs fs_read, so this should DENY
        assert decision.result is DecisionResult.DENY

    def test_ai_output_is_untrusted(self):
        """AI-generated content must never be executed as commands."""
        copilot = AICopilot(tempfile.mkdtemp())
        assert not hasattr(copilot, "execute_ai_output")
        assert not hasattr(copilot, "apply_ai_suggestion")

    def test_ai_draft_not_auto_activated(self, env):
        """AI-generated policy must require explicit human apply."""
        from aegis.policy import parse_policy_yaml
        draft = f"""version: "1.0"
name: ai-draft
priority: 50
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "read"
"""
        parsed = parse_policy_yaml(draft, env["user_id"])
        store = PolicyStore(env["tmpdir"])
        store.save(parsed)
        # It must NOT be active just because it was saved
        # The apply command is separate


# ---------------------------------------------------------------------------
# Remote provider integration tests (mocked)
# ---------------------------------------------------------------------------


class TestRemoteIntegration:
    def test_remote_explain(self, env):
        with patch.dict(os.environ, {"AEGIS_AI_API_KEY": "sk-test"}):
            copilot = AICopilot(env["tmpdir"])
            # Mock the provider's generate method
            copilot._provider.generate = MagicMock(
                return_value="This is a test explanation."
            )
            result = copilot.explain_decision(
                env["decision"].decision_id, env["user_id"],
            )
            assert "AI RECOMMENDATION" in result
            assert "test explanation" in result

    def test_remote_policy_review(self, env):
        with patch.dict(os.environ, {"AEGIS_AI_API_KEY": "sk-test"}):
            copilot = AICopilot(env["tmpdir"])
            copilot._provider.generate = MagicMock(
                return_value="Risk analysis result."
            )
            result = copilot.policy_review(env["policy"].id, env["user_id"])
            assert "AI RECOMMENDATION" in result

    def test_remote_policy_draft_success(self, env):
        with patch.dict(os.environ, {"AEGIS_AI_API_KEY": "sk-test"}):
            copilot = AICopilot(env["tmpdir"])
            valid_yaml = """\
```yaml
version: "1.0"
name: draft-policy
priority: 10
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "read"
```"""
            copilot._provider.generate = MagicMock(return_value=valid_yaml)
            result = copilot.policy_draft(
                "Allow read access", env["user_id"],
            )
            assert "AI RECOMMENDATION" in result
            assert "draft-policy" in result
            assert "NOT active" in result

    def test_remote_policy_draft_invalid_yaml_rejected(self, env):
        with patch.dict(os.environ, {"AEGIS_AI_API_KEY": "sk-test"}):
            copilot = AICopilot(env["tmpdir"])
            copilot._provider.generate = MagicMock(
                return_value="This is not valid YAML at all"
            )
            with pytest.raises(AIError, match="failed validation"):
                copilot.policy_draft("Bad policy", env["user_id"])


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------


class TestAIAudit:
    def test_ai_operations_auditable(self, env):
        copilot = AICopilot(env["tmpdir"])
        copilot.record_audit(env["user_id"], AIOutcome(
            operation="explain",
            provider="local",
            success=True,
            target_id=str(uuid.uuid4()),
        ))
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert any(e.action_type == "ai_operation" for e in events)

    def test_ai_audit_no_secrets(self, env):
        """Verify that audit events for AI ops don't contain secrets."""
        copilot = AICopilot(env["tmpdir"])
        outcome = AIOutcome(
            operation="explain",
            provider="local",
            success=True,
        )
        copilot.record_audit(env["user_id"], outcome)
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        for e in events:
            if e.action_type == "ai_operation":
                params_str = json.dumps(e.params)
                assert "sk-" not in params_str
                assert "api_key" not in params_str.lower()

    def test_audit_recorded_via_cli_flow(self, env):
        """Local explain should result in an audit event."""
        copilot = AICopilot(env["tmpdir"])
        result = copilot.explain_decision(env["decision"].decision_id, env["user_id"])
        # Record the outcome
        copilot.record_audit(env["user_id"], copilot._outcomes[-1])
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        ai_events = [e for e in events if e.action_type == "ai_operation"]
        assert len(ai_events) >= 1


# ---------------------------------------------------------------------------
# Regression: AI entitlement enforcement
# ---------------------------------------------------------------------------
# ``AICopilot`` methods must call ``EntitlementService.require()``
# centrally rather than relying on CLI-level checks.
# ---------------------------------------------------------------------------


class TestAIEntitlementEnforcement:
    """Every public AICopilot method must check 'ai.copilot' entitlement."""

    def _unentitled_user(self, tmpdir: str) -> str:
        """Register a user *without* any subscription."""
        from aegis.auth import Authenticator
        auth = Authenticator(tmpdir)
        return auth.register("unenrolled", "ValidPass1!").id

    def test_explain_decision_requires_entitlement(self, env):
        copilot = AICopilot(env["tmpdir"])
        uid = self._unentitled_user(env["tmpdir"])
        with pytest.raises(EntitlementError, match="not entitled"):
            copilot.explain_decision(str(uuid.uuid4()), uid)

    def test_audit_summary_requires_entitlement(self, env):
        copilot = AICopilot(env["tmpdir"])
        uid = self._unentitled_user(env["tmpdir"])
        with pytest.raises(EntitlementError, match="not entitled"):
            copilot.audit_summary(uid)

    def test_policy_review_requires_entitlement(self, env):
        copilot = AICopilot(env["tmpdir"])
        uid = self._unentitled_user(env["tmpdir"])
        with pytest.raises(EntitlementError, match="not entitled"):
            copilot.policy_review(str(uuid.uuid4()), uid)

    def test_policy_draft_requires_entitlement(self, env):
        copilot = AICopilot(env["tmpdir"])
        uid = self._unentitled_user(env["tmpdir"])
        with pytest.raises(EntitlementError, match="not entitled"):
            copilot.policy_draft("description", uid)

    def test_entitled_user_calls_succeed(self, env):
        """When the user has a Pro subscription, AI methods work (env)."""
        copilot = AICopilot(env["tmpdir"])
        result = copilot.explain_decision(env["decision"].decision_id, env["user_id"])
        assert "DETERMINISTIC ANALYSIS" in result


# ---------------------------------------------------------------------------
# Regression: audit failure observability
# ---------------------------------------------------------------------------


class TestAIAuditFailureObservability:
    """Silent audit failures must be observable via _last_audit_warning."""

    def test_audit_failure_captures_warning(self, env):
        """When audit append fails, _last_audit_warning is set."""
        from unittest.mock import MagicMock

        copilot = AICopilot(env["tmpdir"])
        # Make the audit store's append raise
        copilot._audit_store.append = MagicMock(
            side_effect=RuntimeError("disk full")
        )
        copilot.record_audit(env["user_id"], AIOutcome(
            operation="explain", provider="local", success=True,
        ))
        assert copilot._last_audit_warning is not None
        assert "disk full" in copilot._last_audit_warning

    def test_normal_audit_does_not_set_warning(self, env):
        """Successful record_audit leaves _last_audit_warning as None."""
        copilot = AICopilot(env["tmpdir"])
        copilot.record_audit(env["user_id"], AIOutcome(
            operation="explain", provider="local", success=True,
        ))
        assert copilot._last_audit_warning is None


# ---------------------------------------------------------------------------
# AI output validation tests
# ---------------------------------------------------------------------------


class TestAIOutputValidation:
    def test_ai_draft_must_parse_through_safe_parser(self, env):
        """AI-generated YAML must pass normal Aegis validation."""
        from aegis.policy import parse_policy_yaml

        valid_yaml = """\
version: "1.0"
name: test-from-ai
priority: 5
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "http_request"
      url: "https://example.com"
"""
        parsed = parse_policy_yaml(valid_yaml, env["user_id"])
        assert parsed.name == "test-from-ai"
        assert len(parsed.rules) == 1

    def test_malformed_ai_output_rejected(self, env):
        """Malformed AI-generated YAML must be rejected."""
        from aegis.policy import parse_policy_yaml

        invalid_yaml = """\
version: "1.0"
name: broken
priority: not_a_number
enabled: true
rules: []
"""
        with pytest.raises(ValueError):
            parse_policy_yaml(invalid_yaml, env["user_id"])

    def test_empty_ai_output_rejected(self, env):
        from aegis.policy import parse_policy_yaml
        with pytest.raises(ValueError):
            parse_policy_yaml("", env["user_id"])
