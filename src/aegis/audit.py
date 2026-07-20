"""Persistent tamper-evident audit logging."""

from __future__ import annotations

import hashlib
import json
import os
import os.path
from typing import Any

from aegis.models import AuditEvent


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HASH_ALGORITHM = "sha256"
_INTEGRITY_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Canonical serialization & hashing
# ---------------------------------------------------------------------------

def _integrity_fields(event: AuditEvent, previous_hash: str | None) -> dict[str, Any]:
    """Build the ordered dict that feeds the hash — *without* the ``hash`` field.

    The serialization is deterministic: sorted keys, no extra whitespace.
    The ``hash`` field is excluded (it is the output of this computation).
    """
    raw = event.to_dict()
    raw.pop("hash", None)
    raw["previous_hash"] = previous_hash
    raw["integrity_version"] = _INTEGRITY_VERSION
    return raw


def canonical_json(event: AuditEvent, previous_hash: str | None) -> str:
    """Deterministic JSON string that represents the integrity payload."""
    return json.dumps(_integrity_fields(event, previous_hash), sort_keys=True)


def compute_hash(event: AuditEvent, previous_hash: str | None) -> str:
    """SHA-256 hex digest of the canonical representation."""
    raw = canonical_json(event, previous_hash)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# AuditStore
# ---------------------------------------------------------------------------

class AuditStore:
    """Append-only, user-isolated, tamper-evident audit log.

    Storage: one NDJSON file per user under ``<data_dir>/audit/<user_id>.ndjson``.

    Integrity: each event carries a SHA-256 hash that chains to the previous
    event, forming a hash chain.  Verification detects:
      - modified event content
      - reordered events
      - deleted events
      - inserted events (unless inserted at the end with knowledge of the
        previous hash, which requires access to the chain state)
    """

    def __init__(self, data_dir: str) -> None:
        self._audit_dir = os.path.join(data_dir, "audit")
        os.makedirs(self._audit_dir, exist_ok=True)

    # -- public API ----------------------------------------------------------

    def append(self, event: AuditEvent) -> AuditEvent:
        """Persist *event*, computing its place in the hash chain.

        Returns a new ``AuditEvent`` with ``previous_hash`` and ``hash`` set.
        The original is not modified (the model is frozen).
        """
        previous_hash = self._last_hash(event.user_id)
        event_hash = compute_hash(event, previous_hash)

        chained = AuditEvent.from_dict({
            **event.to_dict(),
            "previous_hash": previous_hash,
            "hash": event_hash,
        })

        line = json.dumps(chained.to_dict(), sort_keys=True)
        filepath = self._filepath(event.user_id)
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        return chained

    def list(self, user_id: str) -> list[AuditEvent]:
        """Return all audit events for *user_id*, in chronological order."""
        filepath = self._filepath(user_id)
        if not os.path.exists(filepath):
            return []
        events: list[AuditEvent] = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(AuditEvent.from_dict(json.loads(line)))
        return events

    def get(self, event_id: str, user_id: str) -> AuditEvent:
        """Return a single event by its ``decision_id``.

        Raises ``ValueError`` (indistinguishable) if not found or not owned.
        """
        for event in self.list(user_id):
            if event.decision_id == event_id:
                return event
        raise ValueError(f"Audit event {event_id!r} not found")

    def verify(self, user_id: str) -> list[dict[str, Any]]:
        """Walk the hash chain and return a list of integrity check results.

        Each result dict has keys:
          - ``index`` (0-based position)
          - ``decision_id``
          - ``valid`` (bool)
          - ``error`` (str, only present when *valid* is False)

        Fail-closed: if the file is unreadable or malformed a single result
        with ``valid=False`` is returned.
        """
        try:
            events = self.list(user_id)
        except Exception as exc:
            return [{"index": 0, "decision_id": "", "valid": False, "error": str(exc)}]

        if not events:
            return [{"index": 0, "decision_id": "", "valid": True, "error": "Empty log — no integrity data to verify"}]

        results: list[dict[str, Any]] = []
        for i, event in enumerate(events):
            expected_prev = events[i - 1].hash if i > 0 else None
            expected_hash = compute_hash(event, expected_prev)

            if event.previous_hash != expected_prev:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": False,
                    "error": (
                        f"previous_hash mismatch: "
                        f"got {event.previous_hash!r}, expected {expected_prev!r}"
                    ),
                })
            elif event.hash != expected_hash:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": False,
                    "error": (
                        f"hash mismatch: "
                        f"got {event.hash!r}, expected {expected_hash!r}"
                    ),
                })
            else:
                results.append({
                    "index": i,
                    "decision_id": event.decision_id,
                    "valid": True,
                    "error": None,
                })

        return results

    # -- internals -----------------------------------------------------------

    def _filepath(self, user_id: str) -> str:
        return os.path.join(self._audit_dir, f"{user_id}.ndjson")

    def _last_hash(self, user_id: str) -> str | None:
        """Return the hash of the most recent event, or ``None``."""
        events = self.list(user_id)
        if not events:
            return None
        return events[-1].hash
