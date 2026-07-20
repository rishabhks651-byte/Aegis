"""Tests for policy parsing and storage."""

import json
import os
import tempfile
import uuid

import pytest
import yaml

from aegis.models import Policy, Rule, RuleEffect
from aegis.policy import PolicyStore, parse_policy_yaml, load_policy_file

_U1 = str(uuid.uuid4())
_U2 = str(uuid.uuid4())
_U3 = str(uuid.uuid4())

_VALID_YAML = """\
version: "1.0"
name: test-policy
description: A test policy
priority: 100
enabled: true
rules:
  - effect: DENY
    match:
      action_type: read
  - effect: ALLOW
    match:
      action_type: "*"
      params.path: /safe/*
"""


class TestParsePolicyYaml:
    def test_basic_parse(self):
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        assert policy.name == "test-policy"
        assert policy.user_id == _U1
        assert len(policy.rules) == 2
        assert isinstance(policy.rules[0].id, str)
        assert policy.rules[0].effect is RuleEffect.DENY
        assert policy.rules[1].effect is RuleEffect.ALLOW

    def test_missing_version(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw.pop("version")
        with pytest.raises(ValueError, match="version"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_wrong_version(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["version"] = "0.9"
        with pytest.raises(ValueError, match="version"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_missing_name(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw.pop("name")
        with pytest.raises(ValueError, match="name"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_missing_priority(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw.pop("priority")
        with pytest.raises(ValueError, match="priority"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_missing_rules(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw.pop("rules")
        with pytest.raises(ValueError, match="rule"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_empty_rules_list(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["rules"] = []
        with pytest.raises(ValueError, match="rule"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_invalid_effect(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["rules"][0]["effect"] = "PERMIT"
        with pytest.raises(ValueError, match="effect"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_empty_match(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["rules"][0]["match"] = {}
        with pytest.raises(ValueError, match="match"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_unknown_top_level_key(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["foo"] = "bar"
        with pytest.raises(ValueError, match="Unknown"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_unknown_rule_key(self):
        raw = yaml.safe_load(_VALID_YAML)
        raw["rules"][0]["unknown"] = True
        with pytest.raises(ValueError, match="unknown"):
            parse_policy_yaml(yaml.dump(raw), _U1)

    def test_auto_generated_id(self):
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        assert policy.id.startswith("gen-")

    def test_content_based_id_is_deterministic(self):
        p1 = parse_policy_yaml(_VALID_YAML, _U1)
        p2 = parse_policy_yaml(_VALID_YAML, _U1)
        assert p1.id == p2.id

    def test_explicit_uuid(self):
        yaml_str = _VALID_YAML.replace('name:', 'id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"\nname:')
        policy = parse_policy_yaml(yaml_str, _U1)
        assert policy.id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class TestLoadPolicyFile:
    def test_file_not_found(self):
        with pytest.raises(ValueError, match="not found"):
            load_policy_file("/nonexistent/policy.yaml", _U1)

    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(_VALID_YAML)
            path = f.name
        try:
            policy = load_policy_file(path, _U1)
            assert policy.name == "test-policy"
        finally:
            os.unlink(path)


class TestPolicyStore:
    def _store(self):
        tmp = tempfile.mkdtemp()
        return PolicyStore(tmp), tmp

    def test_save_and_list(self):
        store, _ = self._store()
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        store.save(policy)
        policies = store.list_for_user(_U1)
        assert len(policies) == 1
        assert policies[0].name == "test-policy"

    def test_user_isolation(self):
        store, _ = self._store()
        p1 = parse_policy_yaml(_VALID_YAML, _U1)
        p2 = parse_policy_yaml(
            _VALID_YAML.replace("test-policy", "other-policy"), _U2
        )
        store.save(p1)
        store.save(p2)
        assert len(store.list_for_user(_U1)) == 1
        assert len(store.list_for_user(_U2)) == 1
        assert len(store.list_for_user(_U3)) == 0

    def test_get_by_id(self):
        store, _ = self._store()
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        store.save(policy)
        loaded = store.get_by_id(policy.id, _U1)
        assert loaded.name == policy.name

    def test_get_by_id_wrong_user(self):
        store, _ = self._store()
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        store.save(policy)
        with pytest.raises(ValueError, match="not found"):
            store.get_by_id(policy.id, _U2)

    def test_get_by_id_nonexistent(self):
        store, _ = self._store()
        with pytest.raises(ValueError, match="not found"):
            store.get_by_id("nonexistent", _U1)

    def test_persistence(self):
        store, tmp = self._store()
        policy = parse_policy_yaml(_VALID_YAML, _U1)
        store.save(policy)
        ndjson_path = os.path.join(tmp, "policies.ndjson")
        assert os.path.exists(ndjson_path)
        with open(ndjson_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 1

    def test_append_dedup(self):
        store, _ = self._store()
        p1 = parse_policy_yaml(_VALID_YAML, _U1)
        store.save(p1)
        store.save(p1)  # same content → same gen- id → dedup
        policies = store.list_for_user(_U1)
        assert len(policies) == 1

    def test_description_defaults_to_empty(self):
        yaml_str = _VALID_YAML.replace("description: A test policy\n", "")
        policy = parse_policy_yaml(yaml_str, _U1)
        assert policy.description == ""

    def test_enabled_defaults_to_true(self):
        yaml_str = _VALID_YAML.replace("enabled: true\n", "")
        policy = parse_policy_yaml(yaml_str, _U1)
        assert policy.enabled is True
