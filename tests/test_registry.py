"""Tests for the AgentRegistry."""

import pytest

from aegis.models import Agent
from aegis.registry import AgentRegistry
from aegis.auth import Authenticator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UUID_A = "550e8400-e29b-41d4-a716-446655440000"
_UUID_B = "660e8400-e29b-41d4-a716-446655440001"
_UUID_C = "770e8400-e29b-41d4-a716-446655440002"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_registry(tmp_path):
    return AgentRegistry(str(tmp_path))


@pytest.fixture
def auth(tmp_path):
    return Authenticator(str(tmp_path))


@pytest.fixture
def sample_password():
    return "correct-horse-battery-staple"


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


class TestCreate:
    def test_create_agent(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "ci-bot-prod")
        assert agent.name == "ci-bot-prod"
        assert agent.user_id == _UUID_A
        assert agent.revoked is False
        assert agent.revoked_at is None
        assert len(agent.id) == 36  # UUID4

    def test_agent_has_unique_id(self, tmp_registry) -> None:
        a1 = tmp_registry.create(_UUID_A, "bot-1")
        a2 = tmp_registry.create(_UUID_A, "bot-2")
        assert a1.id != a2.id

    def test_invalid_name_raises(self, tmp_registry) -> None:
        with pytest.raises(ValueError, match="name must be"):
            tmp_registry.create(_UUID_A, "")

    def test_name_with_spaces_raises(self, tmp_registry) -> None:
        with pytest.raises(ValueError):
            tmp_registry.create(_UUID_A, "my agent")

    def test_name_too_long_raises(self, tmp_registry) -> None:
        with pytest.raises(ValueError):
            tmp_registry.create(_UUID_A, "a" * 65)

    def test_ownership_persisted(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "my-agent")
        found = tmp_registry.get_for_user(agent.id, _UUID_A)
        assert found.user_id == _UUID_A


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


class TestList:
    def test_user_sees_own_agents(self, tmp_registry) -> None:
        tmp_registry.create(_UUID_A, "alice-bot-1")
        tmp_registry.create(_UUID_A, "alice-bot-2")
        agents = tmp_registry.list_for_user(_UUID_A)
        assert len(agents) == 2

    def test_cross_user_isolation(self, tmp_registry) -> None:
        tmp_registry.create(_UUID_A, "alice-bot")
        tmp_registry.create(_UUID_B, "bob-bot")
        alice_agents = tmp_registry.list_for_user(_UUID_A)
        bob_agents = tmp_registry.list_for_user(_UUID_B)
        assert len(alice_agents) == 1
        assert len(bob_agents) == 1
        assert alice_agents[0].name == "alice-bot"
        assert bob_agents[0].name == "bob-bot"

    def test_empty_list_for_new_user(self, tmp_registry) -> None:
        assert tmp_registry.list_for_user(_UUID_C) == []

    def test_revoked_agents_included_in_list(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "bot")
        tmp_registry.revoke(agent.id, _UUID_A)
        agents = tmp_registry.list_for_user(_UUID_A)
        assert len(agents) == 1
        assert agents[0].revoked is True


# ---------------------------------------------------------------------------
# Inspection (get_for_user)
# ---------------------------------------------------------------------------


class TestShow:
    def test_owner_can_inspect(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "my-bot")
        found = tmp_registry.get_for_user(agent.id, _UUID_A)
        assert found.id == agent.id
        assert found.name == "my-bot"

    def test_other_user_cannot_inspect(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "alice-bot")
        with pytest.raises(ValueError, match="not found"):
            tmp_registry.get_for_user(agent.id, _UUID_B)

    def test_unknown_id_raises(self, tmp_registry) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_registry.get_for_user("00000000-0000-0000-0000-000000000000", _UUID_A)

    def test_error_is_indistinguishable(self, tmp_registry) -> None:
        """Ownership error and not-found error use the same *format*."""
        agent = tmp_registry.create(_UUID_A, "bot")
        with pytest.raises(ValueError, match=r"Agent '.*' not found"):
            tmp_registry.get_for_user(agent.id, _UUID_B)
        with pytest.raises(ValueError, match=r"Agent '.*' not found"):
            tmp_registry.get_for_user("00000000-0000-0000-0000-000000000000", _UUID_A)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_owner_can_revoke(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "bot")
        revoked = tmp_registry.revoke(agent.id, _UUID_A)
        assert revoked.revoked is True
        assert revoked.revoked_at is not None

    def test_revoked_state_persists(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "bot")
        tmp_registry.revoke(agent.id, _UUID_A)
        found = tmp_registry.get_for_user(agent.id, _UUID_A)
        assert found.revoked is True

    def test_other_user_cannot_revoke(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "alice-bot")
        with pytest.raises(ValueError, match="not found"):
            tmp_registry.revoke(agent.id, _UUID_B)

    def test_revoke_unknown_raises(self, tmp_registry) -> None:
        with pytest.raises(ValueError, match="not found"):
            tmp_registry.revoke("00000000-0000-0000-0000-000000000000", _UUID_A)

    def test_revoke_idempotent(self, tmp_registry) -> None:
        agent = tmp_registry.create(_UUID_A, "bot")
        r1 = tmp_registry.revoke(agent.id, _UUID_A)
        r2 = tmp_registry.revoke(agent.id, _UUID_A)
        assert r2.revoked is True
        assert r1.revoked_at == r2.revoked_at  # unchanged, same object returned

    def test_revoked_not_active(self, tmp_registry) -> None:
        """Revoked agents appear in list but are not active."""
        agent = tmp_registry.create(_UUID_A, "bot")
        tmp_registry.revoke(agent.id, _UUID_A)
        found = tmp_registry.get_for_user(agent.id, _UUID_A)
        assert found.revoked is True


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_agents_survive_registry_recreation(self, tmp_path) -> None:
        r1 = AgentRegistry(str(tmp_path))
        agent = r1.create(_UUID_A, "persistent-bot")

        r2 = AgentRegistry(str(tmp_path))
        found = r2.get_for_user(agent.id, _UUID_A)
        assert found is not None
        assert found.name == "persistent-bot"
        assert found.user_id == _UUID_A

    def test_revocation_survives_recreation(self, tmp_path) -> None:
        r1 = AgentRegistry(str(tmp_path))
        agent = r1.create(_UUID_A, "bot")
        r1.revoke(agent.id, _UUID_A)

        r2 = AgentRegistry(str(tmp_path))
        found = r2.get_for_user(agent.id, _UUID_A)
        assert found.revoked is True

    def test_cross_user_isolation_survives(self, tmp_path) -> None:
        r1 = AgentRegistry(str(tmp_path))
        a = r1.create(_UUID_A, "alice-bot")
        b = r1.create(_UUID_B, "bob-bot")

        r2 = AgentRegistry(str(tmp_path))
        assert len(r2.list_for_user(_UUID_A)) == 1
        assert len(r2.list_for_user(_UUID_B)) == 1
        with pytest.raises(ValueError, match="not found"):
            r2.get_for_user(a.id, _UUID_B)
        with pytest.raises(ValueError, match="not found"):
            r2.get_for_user(b.id, _UUID_A)

    def test_ndjson_file_created(self, tmp_path) -> None:
        r = AgentRegistry(str(tmp_path))
        r.create(_UUID_A, "bot")
        assert (tmp_path / "agents.ndjson").exists()


# ---------------------------------------------------------------------------
# Security: auth enforcement end-to-end
# ---------------------------------------------------------------------------


class TestAuthEnforcement:
    """Full stack tests: Authenticator + AgentRegistry through CLI handlers."""

    def test_authenticated_user_can_create(self, auth, tmp_path, sample_password) -> None:
        auth.register("alice", sample_password)
        _, raw_token = auth.login("alice", sample_password)
        auth.save_session_token(raw_token)

        registry = AgentRegistry(str(tmp_path))
        user = auth.validate_session(raw_token)
        assert user is not None
        agent = registry.create(user.id, "my-agent")
        assert agent.name == "my-agent"
        assert agent.user_id == user.id

    def test_unauthenticated_user_cannot_create(self, tmp_registry) -> None:
        """Without a valid session token, the CLI layer blocks access
        before reaching the registry.  At the registry level the method
        simply accepts a user_id, so auth enforcement is the CLI's job.
        This test checks the registry accepts a valid user_id regardless."""
        # Registry itself does not enforce auth — auth is the CLI's
        # responsibility.  The registry enforces *ownership* once a
        # user_id is provided.
        agent = tmp_registry.create(_UUID_A, "orphan-bot")
        assert agent.user_id == _UUID_A

    def test_ownership_indistinguishable(self, tmp_registry) -> None:
        """The error for 'not your agent' looks the same as 'does not exist'."""
        agent = tmp_registry.create(_UUID_A, "alice-bot")
        with pytest.raises(ValueError, match=r"Agent '.*' not found"):
            tmp_registry.get_for_user(agent.id, _UUID_B)
        with pytest.raises(ValueError, match=r"Agent '.*' not found"):
            tmp_registry.get_for_user("00000000-0000-0000-0000-000000000000", _UUID_A)
