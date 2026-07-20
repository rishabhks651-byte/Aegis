"""Agent registry — persistent storage and ownership enforcement."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.models import Agent


# ---------------------------------------------------------------------------
# NDJSON helpers
# ---------------------------------------------------------------------------

def _read_ndjson(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _append_ndjson(path: str, record: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _dedup_by_field(
    records: list[dict[str, Any]], field: str = "id"
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for r in records:
        result[r[field]] = r
    return result


# ---------------------------------------------------------------------------
# AgentRegistry
# ---------------------------------------------------------------------------

class AgentRegistry:
    """Persistent registry of agent identities with user-ownership enforcement.

    Every agent is owned by a user. Operations that act on a specific agent
    (*get*, *revoke*) require a ``user_id`` and verify ownership.  If the
    agent does not exist *or* belongs to a different user, a single generic
    ``ValueError("Agent '<id>' not found")`` is raised — indistinguishable
    to the caller.
    """

    def __init__(self, storage_dir: str) -> None:
        self._path = os.path.join(storage_dir, "agents.ndjson")

    # -- public API ----------------------------------------------------------

    def create(self, user_id: str, name: str) -> Agent:
        """Register a new agent owned by *user_id*."""
        agent = Agent(
            id=str(uuid.uuid4()),
            name=name,
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
        )
        _append_ndjson(self._path, agent.to_dict())
        return agent

    def list_for_user(self, user_id: str) -> list[Agent]:
        """Return all agents owned by *user_id* (including revoked ones)."""
        return [a for a in self._all() if a.user_id == user_id]

    def get_by_id(self, agent_id: str) -> Agent | None:
        """Look up an agent by ID without ownership check.

        Used by the policy engine during evaluation — returns ``None``
        if the agent does not exist or has been revoked.
        """
        agent = self._by_id(agent_id)
        if agent is None or agent.revoked:
            return None
        return agent

    def get_for_user(self, agent_id: str, user_id: str) -> Agent:
        """Return agent by ID, verifying ownership.

        Raises:
            ValueError: agent not found or not owned by *user_id*
                        (same message in both cases).
        """
        agent = self._by_id(agent_id)
        if agent is None or agent.user_id != user_id:
            raise ValueError(f"Agent {agent_id!r} not found")
        return agent

    def revoke(self, agent_id: str, user_id: str) -> Agent:
        """Revoke an agent, verifying ownership.

        Idempotent — revoking an already-revoked agent returns the current
        state without error.  Raise ``ValueError`` (generic message) when
        the agent does not exist or is not owned by *user_id*.
        """
        agent = self.get_for_user(agent_id, user_id)
        if agent.revoked:
            return agent
        revoked = Agent(
            id=agent.id,
            name=agent.name,
            user_id=agent.user_id,
            created_at=agent.created_at,
            metadata=agent.metadata,
            revoked=True,
            revoked_at=datetime.now(timezone.utc),
        )
        _append_ndjson(self._path, revoked.to_dict())
        return revoked

    # -- internal helpers ----------------------------------------------------

    def _all(self) -> list[Agent]:
        records = _read_ndjson(self._path)
        deduped = _dedup_by_field(records, "id")
        return [Agent.from_dict(r) for r in deduped.values()]

    def _by_id(self, agent_id: str) -> Agent | None:
        for a in self._all():
            if a.id == agent_id:
                return a
        return None
