"""AI Security Copilot — assistance layer for Aegis.

Core principle
--------------
The AI must **never** become the final security decision-maker.
All recommendations are advisory only.  The PolicyEngine is the sole
authority for ALLOW/DENY decisions.

Architecture
------------
AIProvider (abstract)
    ├── LocalProvider   — deterministic template-based (always available)
    └── RemoteProvider  — calls an external AI API (OpenAI-compatible)

Provider selection
------------------
If the environment variable ``AEGIS_AI_API_KEY`` is set, the system uses
the remote provider.  Otherwise the local deterministic provider is used.

Aegis must remain fully functional without any AI provider configured.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aegis.audit import AuditStore
from aegis.entitlement import EntitlementError, EntitlementService
from aegis.models import AuditEvent
from aegis.policy import PolicyStore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_API_URL = "https://api.openai.com/v1/chat/completions"
_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_TIMEOUT = 30

_SENSITIVE_PARAM_KEYS = frozenset({
    "password", "secret", "token", "api_key", "api-key", "apikey",
    "authorization", "cookie", "auth", "credential", "passwd",
})

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AIError(Exception):
    """Raised when an AI operation fails."""


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------


class AIProvider(ABC):
    """Abstract base for an AI text-generation provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name (e.g. ``"remote"``, ``"local"``)."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send *prompt* and return the generated text."""


class LocalProvider(AIProvider):
    """Deterministic template-based provider — always available, no AI.

    This provider cannot generate novel text; it returns structured
    templates populated from available Aegis data.
    """

    @property
    def name(self) -> str:
        return "local"

    def generate(self, prompt: str) -> str:
        raise AIError("Local provider has no generative capability")


class RemoteProvider(AIProvider):
    """Calls an OpenAI-compatible chat-completion API."""

    def __init__(
        self,
        api_key: str,
        api_url: str = _DEFAULT_API_URL,
        model: str = _DEFAULT_MODEL,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._api_url = api_url
        self._model = model
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "remote"

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the remote API and return the response."""
        import urllib.error
        import urllib.request

        data = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": "You are an AI security copilot for Aegis, a security gateway for AI agents. Respond concisely and accurately."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 2000,
        }

        req = urllib.request.Request(
            self._api_url,
            data=json.dumps(data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["choices"][0]["message"]["content"]
        except Exception as exc:
            raise AIError(f"Remote provider error: {exc}") from exc


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def _create_provider() -> AIProvider:
    """Create a provider based on environment configuration.

    Selection (first match wins):
      1. ``AEGIS_AI_API_KEY`` → remote provider (OpenAI-compatible)
      2. otherwise → local deterministic provider
    """
    api_key = os.environ.get("AEGIS_AI_API_KEY", "").strip()
    if api_key:
        api_url = os.environ.get("AEGIS_AI_API_URL", _DEFAULT_API_URL).strip()
        model = os.environ.get("AEGIS_AI_MODEL", _DEFAULT_MODEL).strip()
        return RemoteProvider(api_key=api_key, api_url=api_url, model=model)
    return LocalProvider()


# ---------------------------------------------------------------------------
# Data sanitisation
# ---------------------------------------------------------------------------


def _sanitise_params(params: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive values from a params dict before external sharing."""
    sanitised: dict[str, Any] = {}
    for k, v in params.items():
        if k.lower() in _SENSITIVE_PARAM_KEYS:
            continue
        if isinstance(v, str) and len(v) > 200:
            sanitised[k] = v[:200] + "..."
        elif isinstance(v, dict):
            sanitised[k] = _sanitise_params(v)
        else:
            sanitised[k] = v
    return sanitised


def _sanitise_event(event: AuditEvent) -> dict[str, Any]:
    """Return a sanitised dict suitable for an external AI provider."""
    safe = {
        "result": event.result,
        "action_type": event.action_type,
        "policy_name": event.policy_name,
        "policy_id": event.policy_id,
        "rule_id": event.rule_id,
        "rule_effect": event.rule_effect,
        "reason": event.reason,
        "matched": event.matched,
    }
    if event.params:
        safe["params"] = _sanitise_params(event.params)
    return safe


# ---------------------------------------------------------------------------
# Outcome tracking
# ---------------------------------------------------------------------------


@dataclass
class AIOutcome:
    """Result of an AI operation, suitable for audit logging."""

    operation: str
    provider: str
    success: bool
    target_id: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# AICopilot
# ---------------------------------------------------------------------------


class AICopilot:
    """AI Security Copilot — provides analysis, explanation, and drafting.

    Every method is available regardless of provider configuration; when
    only the local provider is available, deterministic templates are
    used instead of generative AI.
    """

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        self._audit_store = AuditStore(data_dir)
        self._policy_store = PolicyStore(data_dir)
        self._provider = _create_provider()
        self._outcomes: list[AIOutcome] = []
        self._entitlement = EntitlementService(data_dir)
        self._last_audit_warning: str | None = None

    @property
    def provider_name(self) -> str:
        return self._provider.name

    # -- 1. Decision explanation --------------------------------------------

    def explain_decision(self, decision_id: str, user_id: str) -> str:
        """Generate a structured explanation for a past decision.

        Works with both local (template) and remote (AI) providers.
        """
        self._entitlement.require(user_id, "ai.copilot")
        try:
            event = self._audit_store.get(decision_id, user_id)
        except ValueError:
            raise AIError(f"Decision {decision_id!r} not found")

        if isinstance(self._provider, RemoteProvider):
            result = self._remote_explain(event)
        else:
            result = self._local_explain(event)

        self._outcomes.append(AIOutcome(
            operation="explain",
            provider=self._provider.name,
            success=True,
            target_id=decision_id,
        ))
        return result

    def _local_explain(self, event: AuditEvent) -> str:
        """Deterministic template-based explanation."""
        lines = [
            "DETERMINISTIC ANALYSIS",
            "",
            f"Decision:        {event.result}",
            f"Action Type:     {event.action_type}",
        ]
        if event.policy_name:
            lines.append(f"Policy:          {event.policy_name}")
        if event.rule_id:
            lines.append(f"Matched Rule:    {event.rule_id} ({event.rule_effect})")
        lines.append(f"Reason:          {event.reason}")
        lines.append("")

        if event.result == "ALLOW":
            lines.append("Security Implications:")
            lines.append("  The action was permitted by the policy.")
            lines.append("  This is the expected behaviour when rules match.")
            lines.append("")
            lines.append("Recommended Next Step:")
            lines.append("  Verify that the access granted aligns with the")
            lines.append("  intended security posture for this agent.")
        else:
            lines.append("Security Implications:")
            lines.append("  The action was blocked by policy.")
            lines.append("  No unauthorised access was granted.")
            lines.append("")
            lines.append("Recommended Next Step:")
            lines.append("  If the action should be permitted, update the policy")
            lines.append("  with an explicit ALLOW rule for this action type.")
        return "\n".join(lines)

    def _remote_explain(self, event: AuditEvent) -> str:
        """AI-generated explanation using sanitised event data."""
        safe = _sanitise_event(event)
        prompt = (
            "You are an AI security copilot for Aegis. "
            "Given the following security decision, provide a concise "
            "structured explanation.\n\n"
            f"Decision: {safe['result']}\n"
            f"Action Type: {safe['action_type']}\n"
            f"Policy: {safe.get('policy_name', 'N/A')}\n"
            f"Matched Rule: {safe.get('rule_id', 'N/A')} ({safe.get('rule_effect', 'N/A')})\n"
            f"Reason: {safe.get('reason', 'N/A')}\n\n"
            "Provide:\n"
            "1. What happened\n"
            "2. Why this decision was made\n"
            "3. Security implications\n"
            "4. Recommended next steps"
        )
        ai_text = self._provider.generate(prompt)
        return "AI RECOMMENDATION\n\n" + ai_text

    # -- 2. Audit log summarisation -----------------------------------------

    def audit_summary(self, user_id: str) -> str:
        """Generate a summary of audit events.

        This is always deterministic (no AI needed).
        """
        self._entitlement.require(user_id, "ai.copilot")
        events = self._audit_store.list(user_id)
        if not events:
            return "DETERMINISTIC ANALYSIS\n\nNo audit events found."

        total = len(events)
        allow_count = sum(1 for e in events if e.result == "ALLOW")
        deny_count = sum(1 for e in events if e.result == "DENY")

        action_types = Counter(e.action_type for e in events)
        denied_action_types = Counter(
            e.action_type for e in events if e.result == "DENY"
        )

        most_common = action_types.most_common(5)
        most_denied = denied_action_types.most_common(5)

        lines = [
            "DETERMINISTIC ANALYSIS",
            "",
            f"Total Audit Events:  {total}",
            f"ALLOW:               {allow_count}",
            f"DENY:                {deny_count}",
            "",
            "Most Common Action Types:",
        ]
        for action, count in most_common:
            lines.append(f"  {action:<30} {count}")

        if most_denied:
            lines.append("")
            lines.append("Most Frequently Denied Actions:")
            for action, count in most_denied:
                lines.append(f"  {action:<30} {count}")

        self._outcomes.append(AIOutcome(
            operation="audit_summary",
            provider="local",
            success=True,
        ))
        return "\n".join(lines)

    # -- 3. Policy risk analysis --------------------------------------------

    def policy_review(self, policy_id: str, user_id: str) -> str:
        """Analyse a policy for potential security risks.

        When a remote provider is available, the full policy YAML is
        sent for AI analysis.  Otherwise a deterministic rule scan is
        performed.
        """
        self._entitlement.require(user_id, "ai.copilot")
        try:
            policy = self._policy_store.get_by_id(policy_id, user_id)
        except ValueError:
            raise AIError(f"Policy {policy_id!r} not found")

        if isinstance(self._provider, RemoteProvider):
            result = self._remote_policy_review(policy)
        else:
            result = self._local_policy_review(policy)

        self._outcomes.append(AIOutcome(
            operation="policy_review",
            provider=self._provider.name,
            success=True,
            target_id=policy_id,
        ))
        return result

    def _local_policy_review(self, policy: Any) -> str:
        """Deterministic policy risk analysis based on rule patterns."""
        lines = [
            "DETERMINISTIC ANALYSIS",
            f"Policy: {policy.name} (id={policy.id})",
            f"Rules:  {len(policy.rules)}",
            "",
        ]

        risks_found = False
        for i, rule in enumerate(policy.rules, 1):
            rule_risks: list[str] = []
            match = rule.match if hasattr(rule, "match") else {}

            for field, pattern in match.items():
                if isinstance(pattern, str) and pattern == "*":
                    rule_risks.append(
                        f"  - Field '{field}' uses wildcard '*' — may be too broad"
                    )
                elif isinstance(pattern, str) and "/" in pattern:
                    rule_risks.append(
                        f"  - Field '{field}' matches path '{pattern}' — "
                        "verify scope is necessary"
                    )

            if rule_risks:
                risks_found = True
                lines.append(f"Rule #{i} [{rule.effect.value}]:")
                lines.extend(rule_risks)
                lines.append("")

        if not risks_found:
            lines.append("No significant risks detected in this policy.")

        if not policy.enabled:
            lines.append("Note: This policy is currently disabled.")

        return "\n".join(lines)

    def _remote_policy_review(self, policy: Any) -> str:
        """AI-generated policy risk analysis."""
        policy_dict = policy.to_dict()
        policy_yaml_lines = [f"{k}: {v}" for k, v in policy_dict.items() if k != "rules"]
        for r in policy_dict.get("rules", []):
            policy_yaml_lines.append(f"  - effect: {r['effect']}")
            policy_yaml_lines.append(f"    match: {json.dumps(r.get('match', {}))}")

        policy_text = "\n".join(policy_yaml_lines)

        prompt = (
            "You are an AI security copilot for Aegis. "
            "Analyse this security policy for potential risks.\n\n"
            f"{policy_text}\n\n"
            "Identify:\n"
            "1. Overly broad wildcard matches\n"
            "2. Unrestricted filesystem or process access\n"
            "3. Wide network scope\n"
            "4. Excessive permissions\n"
            "5. Specific recommendations to minimise access"
        )
        ai_text = self._provider.generate(prompt)
        return "AI RECOMMENDATION\n\n" + ai_text

    # -- 4. Natural-language policy drafting --------------------------------

    def policy_draft(self, description: str, user_id: str) -> str:
        """Generate a policy YAML draft from a natural-language description.

        The generated YAML is parsed through normal Aegis validation
        before being returned.  It is **never** automatically activated.
        """
        self._entitlement.require(user_id, "ai.copilot")
        if isinstance(self._provider, RemoteProvider):
            result = self._remote_policy_draft(description, user_id)
        else:
            raise AIError(
                "Policy drafting requires a remote AI provider. "
                "Set AEGIS_AI_API_KEY in your environment."
            )

        self._outcomes.append(AIOutcome(
            operation="policy_draft",
            provider=self._provider.name,
            success=True,
        ))
        return result

    def _remote_policy_draft(self, description: str, user_id: str) -> str:
        """Generate a policy draft via remote AI and validate it."""
        prompt = (
            "You are an AI security copilot for Aegis. "
            "Generate a valid Aegis YAML security policy for the following request.\n\n"
            f"Request: {description}\n\n"
            "The policy must:\n"
            "- Use version \"1.0\"\n"
            "- Include name, priority (integer), enabled (true/false)\n"
            "- Include at least one rule with effect (ALLOW or DENY) and match conditions\n"
            "- Be valid YAML\n\n"
            "Output ONLY the YAML policy, surrounded by ```yaml ... ``` markers."
        )

        ai_text = self._provider.generate(prompt)

        # Extract YAML from potential markdown fences
        yaml_match = re.search(
            r"```(?:yaml)?\s*\n?(.*?)\n?```", ai_text, re.DOTALL
        )
        yaml_str = yaml_match.group(1) if yaml_match else ai_text.strip()

        # Validate through the safe YAML parser
        try:
            from aegis.policy import parse_policy_yaml
            parsed = parse_policy_yaml(yaml_str, user_id)
        except Exception as exc:
            raise AIError(
                f"AI-generated policy failed validation: {exc}\n\n"
                f"Raw AI output:\n{ai_text}"
            ) from exc

        validated_yaml = self._policy_to_yaml(parsed)
        return (
            "AI RECOMMENDATION\n\n"
            "The following policy was generated by AI. "
            "It is NOT active. Review carefully before applying.\n\n"
            f"{validated_yaml}\n\n"
            "To activate: aegis policy apply <file>"
        )

    @staticmethod
    def _policy_to_yaml(policy: Any) -> str:
        """Render a Policy model as YAML-like string for display."""
        lines = [
            f'version: "1.0"',
            f"id: {policy.id}",
            f"name: {policy.name}",
            f"priority: {policy.priority}",
            f"enabled: {str(policy.enabled).lower()}",
            "rules:",
        ]
        for r in policy.rules:
            lines.append(f"  - effect: {r.effect.value}")
            lines.append(f"    match: {json.dumps(r.match, sort_keys=True)}")
            if r.comment:
                lines.append(f"    comment: {r.comment}")
        return "\n".join(lines)

    # -- Audit helpers ------------------------------------------------------

    def record_audit(self, user_id: str, outcome: AIOutcome) -> None:
        """Persist an AI operation audit event.

        Never stores API keys, tokens, or secrets.
        Audit failures are silent (logged to ``_last_audit_warning``)
        so they never break the user-facing operation.
        """
        try:
            d = {
                "operation": outcome.operation,
                "provider": outcome.provider,
                "success": outcome.success,
            }
            if outcome.target_id:
                d["target_id"] = outcome.target_id
            if outcome.error:
                d["error"] = outcome.error

            event = AuditEvent(
                decision_id=str(uuid.uuid4()),
                action_id=str(uuid.uuid4()),
                action_type="ai_operation",
                params=d,
                result="",
                matched=False,
                evaluated_at=datetime.now(timezone.utc).isoformat(),
                reason=f"AI {outcome.operation} via {outcome.provider} provider",
                user_id=user_id,
            )
            self._audit_store.append(event)
        except Exception as exc:
            self._last_audit_warning = f"Audit append failed: {exc}"
            # audit failures must not break the user-facing operation
