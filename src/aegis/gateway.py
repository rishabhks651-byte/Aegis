"""Central action evaluation gateway.

Orchestrates the full request lifecycle:

    Authenticated User → Agent → Action → Policy Evaluation → Decision → Audit

Failure semantics (all produce DENY — fail-closed):
  - unknown or revoked agent
  - agent owned by another user
  - policy evaluation raises an exception
  - audit event creation or persistence fails
  - storage is corrupted

The policy engine is always the final decision authority for matching
rules; the gateway only validates preconditions and fails closed on
infrastructure errors.

If audit persistence fails the principal decision is **overridden to
DENY** because the system cannot guarantee a complete audit trail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.audit import AuditStore
from aegis.engine import PolicyEngine
from aegis.entitlement import EntitlementService
from aegis.execution import Allowlist, AllowlistError, ProcessExecutor
from aegis.models import Action, AuditEvent, Decision, DecisionResult, HttpResponse, ProcessResult
from aegis.network import HttpClient, NetworkAllowlist, NetworkError, SSRFValidator
from aegis.policy import PolicyStore
from aegis.registry import AgentRegistry


class GatewayError(Exception):
    """Raised when a non-recoverable gateway error occurs."""
    pass


class Gateway:
    """Single entry point for evaluating agent actions."""

    def __init__(
        self,
        data_dir: str,
        engine: PolicyEngine | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._registry = AgentRegistry(data_dir)
        self._policy_store = PolicyStore(data_dir)
        self._audit_store = AuditStore(data_dir)
        self._engine = engine or PolicyEngine()

    # -- public API ----------------------------------------------------------

    def evaluate(
        self,
        user_id: str,
        action: Action,
        agent_id: str,
        policy_id: str,
    ) -> Decision:
        """Evaluate *action* under the policy owned by *user_id*.

        Returns a ``Decision`` — ``ALLOW`` only if every precondition
        passes, the engine matches a ``ALLOW`` rule, *and* audit
        persistence succeeds.  All failures produce ``DENY``.
        """
        # 1. Agent lookup & ownership
        try:
            agent = self._registry.get_for_user(agent_id, user_id)
        except ValueError:
            return self._deny(
                action, f"Agent {agent_id!r} not found or not owned",
            )

        if agent.revoked:
            return self._deny(
                action, f"Agent {agent_id!r} has been revoked",
            )

        # 2. Policy lookup
        try:
            policy = self._policy_store.get_by_id(policy_id, user_id)
        except ValueError:
            policies: list = []
        else:
            policies = [policy]

        # 3. Policy evaluation
        try:
            decision = self._engine.evaluate(action, policies)
        except Exception:
            return self._deny(action, "Policy evaluation error")

        # 4. Audit creation & persistence
        #    Fail-closed: if the audit trail cannot be written the
        #    decision is converted to DENY.
        try:
            event = AuditEvent.from_decision(decision, action, agent.name, user_id)
            self._audit_store.append(event)
        except Exception as exc:
            return self._deny(
                action, f"Audit persistence failed: {exc}",
            )

        return decision

    def execute_process(
        self,
        user_id: str,
        action: Action,
        agent_id: str,
        policy_id: str,
        *,
        executable_name: str,
        process_args: list[str] | None = None,
        timeout: int = 30,
        output_limit: int = 1_048_576,
        cwd: str | None = None,
    ) -> tuple[Decision, ProcessResult | None]:
        """Evaluate *action* then, if ALLOW, execute a controlled process.

        Returns ``(decision, process_result)`` where *process_result* is
        ``None`` when the decision is ``DENY``.

        The audit event captures both the policy decision and (on success)
        the execution outcome (exit code, timing, truncation flag).
        """
        # 0. Entitlement check
        if not self._entitlements.has(user_id, "process.execute"):
            return (
                self._deny(action, "User not entitled to process execution"),
                None,
            )

        # 1. Agent lookup & ownership
        try:
            agent = self._registry.get_for_user(agent_id, user_id)
        except ValueError:
            return (
                self._deny(action, f"Agent {agent_id!r} not found or not owned"),
                None,
            )

        if agent.revoked:
            return (
                self._deny(action, f"Agent {agent_id!r} has been revoked"),
                None,
            )

        # 2. Policy lookup
        try:
            policy = self._policy_store.get_by_id(policy_id, user_id)
        except ValueError:
            return (
                self._deny(action, f"Policy {policy_id!r} not found"),
                None,
            )

        # 3. Policy evaluation
        try:
            decision = self._engine.evaluate(action, [policy])
        except Exception:
            return (
                self._deny(action, "Policy evaluation error"),
                None,
            )

        # 4. If DENY — audit and return
        if decision.result is DecisionResult.DENY:
            self._try_audit(decision, action, agent.name, user_id)
            return (decision, None)

        # 5. Execute process (only reached when policy says ALLOW)
        allowlist = Allowlist(self._data_dir)
        executor = ProcessExecutor(allowlist)

        try:
            process_result = executor.execute(
                executable_name=executable_name,
                args=process_args,
                timeout=timeout,
                output_limit=output_limit,
                cwd=cwd,
            )
        except AllowlistError as exc:
            deny = self._deny(action, str(exc))
            self._try_audit(deny, action, agent.name, user_id)
            return (deny, None)
        except Exception as exc:
            deny = self._deny(action, f"Process execution failed: {exc}")
            self._try_audit(deny, action, agent.name, user_id)
            return (deny, None)

        # 6. Audit — include execution metadata in params
        try:
            exec_params = dict(action.params)
            exec_params.update({
                "executable": process_result.executable,
                "exit_code": process_result.exit_code,
                "execution_time_ms": process_result.execution_time_ms,
                "timed_out": process_result.timed_out,
                "output_truncated": process_result.output_truncated,
            })
            event = AuditEvent.from_decision(
                decision, action, agent.name, user_id,
            )
            augmented = AuditEvent.from_dict({
                **event.to_dict(),
                "params": exec_params,
            })
            self._audit_store.append(augmented)
        except Exception:
            # Fail-closed: audit failure → DENY
            deny = self._deny(action, "Audit persistence failed")
            return (deny, None)

        return (decision, process_result)

    def http_request(
        self,
        user_id: str,
        action: Action,
        agent_id: str,
        policy_id: str,
        *,
        url: str,
        method: str = "GET",
        timeout: int = 30,
        max_response_size: int = 10_485_760,
        follow_redirects: bool = False,
    ) -> tuple[Decision, HttpResponse | None]:
        """Evaluate *action* then, if ALLOW, perform a controlled HTTP request.

        Returns ``(decision, http_response)`` where *http_response* is
        ``None`` when the decision is ``DENY``.

        The audit event captures both the policy decision and (on success)
        the HTTP outcome (status code, timing, truncation flag).  Response
        body and headers are **not** included in the audit trail.
        """
        # 0. Entitlement check
        if not self._entitlements.has(user_id, "network.http"):
            return (
                self._deny(action, "User not entitled to network access"),
                None,
            )

        # 1. Agent lookup & ownership
        try:
            agent = self._registry.get_for_user(agent_id, user_id)
        except ValueError:
            return (
                self._deny(action, f"Agent {agent_id!r} not found or not owned"),
                None,
            )

        if agent.revoked:
            return (
                self._deny(action, f"Agent {agent_id!r} has been revoked"),
                None,
            )

        # 2. Policy lookup
        try:
            policy = self._policy_store.get_by_id(policy_id, user_id)
        except ValueError:
            return (
                self._deny(action, f"Policy {policy_id!r} not found"),
                None,
            )

        # 3. Policy evaluation
        try:
            decision = self._engine.evaluate(action, [policy])
        except Exception:
            return (
                self._deny(action, "Policy evaluation error"),
                None,
            )

        # 4. If DENY — audit and return
        if decision.result is DecisionResult.DENY:
            self._try_audit(decision, action, agent.name, user_id)
            return (decision, None)

        # 5. HTTP request (only reached when policy says ALLOW)
        allowlist = NetworkAllowlist(self._data_dir)
        ssrf = SSRFValidator()
        client = HttpClient(allowlist=allowlist, ssrf_validator=ssrf)

        try:
            http_response = client.request(
                url,
                method=method,
                timeout=timeout,
                max_response_size=max_response_size,
                follow_redirects=follow_redirects,
                allowlist=allowlist,
            )
        except NetworkError as exc:
            deny = self._deny(action, str(exc))
            self._try_audit(deny, action, agent.name, user_id)
            return (deny, None)
        except Exception as exc:
            deny = self._deny(action, f"HTTP request failed: {exc}")
            self._try_audit(deny, action, agent.name, user_id)
            return (deny, None)

        # 6. Audit — include HTTP metadata, NOT body or sensitive headers
        try:
            exec_params = dict(action.params)
            exec_params.update({
                "status_code": http_response.status_code,
                "elapsed_ms": http_response.elapsed_ms,
                "timed_out": http_response.timed_out,
                "body_truncated": http_response.body_truncated,
            })
            event = AuditEvent.from_decision(
                decision, action, agent.name, user_id,
            )
            augmented = AuditEvent.from_dict({
                **event.to_dict(),
                "params": exec_params,
            })
            self._audit_store.append(augmented)
        except Exception:
            deny = self._deny(action, "Audit persistence failed")
            return (deny, None)

        return (decision, http_response)

    # -- internal helpers ----------------------------------------------------

    @property
    def _entitlements(self) -> EntitlementService:
        """Lazy entitlement service."""
        if not hasattr(self, "_entitlement_svc"):
            object.__setattr__(self, "_entitlement_svc", EntitlementService(self._data_dir))
        return self._entitlement_svc  # type: ignore[has-type]

    def _try_audit(
        self, decision: Decision, action: Action,
        agent_name: str, user_id: str,
    ) -> None:
        """Attempt to persist an audit event; swallow exceptions on DENY paths."""
        try:
            event = AuditEvent.from_decision(decision, action, agent_name, user_id)
            self._audit_store.append(event)
        except Exception:
            pass

    def _deny(self, action: Action, reason: str) -> Decision:
        return Decision(
            decision_id=str(uuid.uuid4()),
            action_id=action.action_id,
            agent_id=action.agent_id,
            result=DecisionResult.DENY,
            policy_id=None,
            policy_name=None,
            rule_id=None,
            rule_effect=None,
            matched=False,
            evaluated_at=datetime.now(timezone.utc),
            reason=reason,
        )
