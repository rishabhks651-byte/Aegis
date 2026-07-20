"""Policy file parsing, validation, and storage."""

from __future__ import annotations

import hashlib
import json
import os
import os.path
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml

from aegis.models import Policy, Rule, RuleEffect


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPORTED_VERSION = "1.0"
_ALLOWED_EFFECTS = {"ALLOW", "DENY"}
_POLICY_NAME_RE_PATTERN = r"^.{1,128}$"  # validated during parse


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------

def parse_policy_yaml(content: str, user_id: str) -> Policy:
    """Parse a YAML string into a validated Policy model.

    Raises:
        ValueError: if the YAML is invalid, the schema is wrong, or
                    required fields are missing.
    """
    raw = yaml.safe_load(content)
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping (dictionary)")

    _validate_top_level(raw)
    rules = _parse_rules(raw.get("rules", []))

    policy_id = _resolve_policy_id(raw, content)
    name = str(raw["name"]).strip()
    description = str(raw.get("description", "")).strip()

    return Policy(
        id=policy_id,
        name=name,
        user_id=user_id,
        description=description,
        rules=rules,
        priority=int(raw["priority"]),
        enabled=raw.get("enabled", True),
        created_at=datetime.now(timezone.utc),
    )


def load_policy_file(filepath: str, user_id: str) -> Policy:
    """Read a YAML file and return a validated Policy."""
    if not os.path.exists(filepath):
        raise ValueError(f"Policy file not found: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        return parse_policy_yaml(f.read(), user_id)


def _validate_top_level(raw: dict[str, Any]) -> None:
    unknown = [k for k in raw if k not in (
        "version", "id", "name", "description", "priority",
        "enabled", "rules",
    )]
    if unknown:
        raise ValueError(f"Unknown policy keys: {', '.join(unknown)}")

    if raw.get("version") != _SUPPORTED_VERSION:
        raise ValueError(
            f"Unsupported policy version {raw.get('version')!r}; "
            f"expected {_SUPPORTED_VERSION!r}"
        )
    if "name" not in raw or not isinstance(raw["name"], str) or not raw["name"].strip():
        raise ValueError("Policy 'name' is required and must be a non-empty string")
    if len(raw["name"]) > 128:
        raise ValueError("Policy 'name' must be at most 128 characters")
    if "priority" not in raw:
        raise ValueError("Policy 'priority' is required")
    if "rules" not in raw or not isinstance(raw["rules"], list) or not raw["rules"]:
        raise ValueError("Policy must contain at least one rule")


def _parse_rules(raw_rules: list[dict[str, Any]]) -> tuple[Rule, ...]:
    rules = []
    for i, r in enumerate(raw_rules):
        unknown = [k for k in r if k not in ("id", "effect", "match", "comment")]
        if unknown:
            raise ValueError(f"Rule #{i + 1} has unknown keys: {', '.join(unknown)}")

        effect = r.get("effect")
        if effect not in _ALLOWED_EFFECTS:
            raise ValueError(
                f"Rule #{i + 1} effect must be ALLOW or DENY, got {effect!r}"
            )
        match = r.get("match")
        if not isinstance(match, dict) or not match:
            raise ValueError(f"Rule #{i + 1} must have a non-empty 'match' dict")

        rule_id = r.get("id") or f"r{i + 1}"
        rules.append(Rule(
            id=rule_id,
            effect=RuleEffect(effect),
            match=match,
            comment=str(r.get("comment", "")),
        ))
    return tuple(rules)


def _resolve_policy_id(raw: dict[str, Any], content: str) -> str:
    """Return the explicit UUID or derive one from the content hash."""
    if "id" in raw:
        uid = str(raw["id"])
        uuid.UUID(uid)  # validate format
        return uid
    # deterministic content-based ID
    normalized = yaml.safe_dump(raw, sort_keys=True)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"gen-{digest}"


# ---------------------------------------------------------------------------
# PolicyStore
# ---------------------------------------------------------------------------

class PolicyStore:
    """Append-only NDJSON-backed policy storage with user isolation."""

    def __init__(self, storage_dir: str) -> None:
        self._path = os.path.join(storage_dir, "policies.ndjson")

    def save(self, policy: Policy) -> None:
        """Persist a policy (appends to the NDJSON log)."""
        _append_ndjson(self._path, policy.to_dict())

    def get_by_id(self, policy_id: str, user_id: str) -> Policy:
        """Return a policy by ID, verifying ownership.

        Raises ValueError (generic) if not found or not owned.
        """
        for p in self._all():
            if p.id == policy_id:
                if p.user_id != user_id:
                    raise ValueError(f"Policy {policy_id!r} not found")
                return p
        raise ValueError(f"Policy {policy_id!r} not found")

    def list_for_user(self, user_id: str) -> list[Policy]:
        """Return all policies owned by *user_id*."""
        return [p for p in self._all() if p.user_id == user_id]

    def _all(self) -> list[Policy]:
        records = _read_ndjson(self._path)
        deduped = _dedup_by_field(records, "id")
        return [Policy.from_dict(r) for r in deduped.values()]


# ---------------------------------------------------------------------------
# NDJSON helpers (local copies to avoid cross-module coupling)
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
    records: list[dict[str, Any]], field: str = "id",
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for r in records:
        result[r[field]] = r
    return result
