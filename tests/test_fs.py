"""Tests for the controlled read-only filesystem capability."""

import os
import os.path
import sys
import tempfile
import uuid
from datetime import datetime, timezone

import pytest

from aegis.auth import Authenticator
from aegis.fs import Filesystem, FsError
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_ID = str(uuid.uuid4())

_ALLOW_FS_POLICY = f"""\
version: "1.0"
id: "{_POLICY_ID}"
name: allow-fs-read
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
    """Set up a fully provisioned test environment with an fs-scope dir."""
    tmpdir = tempfile.mkdtemp()
    auth = Authenticator(tmpdir)
    user = auth.register("fstest", "ValidPass1!")

    from aegis.registry import AgentRegistry
    registry = AgentRegistry(tmpdir)
    agent = registry.create(user.id, "fs-agent")

    from aegis.policy import parse_policy_yaml, PolicyStore
    policy = parse_policy_yaml(_ALLOW_FS_POLICY, user.id)
    store = PolicyStore(tmpdir)
    store.save(policy)

    # Create fs scope dir and a test file inside it
    fs_scope = os.path.join(tmpdir, "fs-scope")
    os.makedirs(fs_scope, exist_ok=True)
    test_file = os.path.join(fs_scope, "hello.txt")
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("Hello, Aegis!\n")

    return {
        "tmpdir": tmpdir,
        "gateway": Gateway(tmpdir),
        "user_id": user.id,
        "agent": agent,
        "policy_id": policy.id,
        "test_file": test_file,
    }


def _make_action(agent_id: str, path: str) -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_type="fs_read",
        params={"path": path},
        requested_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Authorization (Gateway + Filesystem end-to-end)
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_valid_authorized_read(self, env):
        action = _make_action(env["agent"].id, env["test_file"])
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.ALLOW

        fs = Filesystem(env["tmpdir"])
        content = fs.read_file(env["test_file"])
        assert content == "Hello, Aegis!\n"

    def test_policy_deny_prevents_read(self, env):
        action = _make_action(env["agent"].id, env["test_file"])
        # Use a non-existent policy ID → no matching policy → default DENY
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, str(uuid.uuid4()),
        )
        assert decision.result is DecisionResult.DENY

    def test_unauthorized_user_denied(self, env):
        action = _make_action(env["agent"].id, env["test_file"])
        decision = env["gateway"].evaluate(
            "", action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY

    def test_unknown_agent_denied(self, env):
        action = _make_action(str(uuid.uuid4()), env["test_file"])
        decision = env["gateway"].evaluate(
            env["user_id"], action, str(uuid.uuid4()), env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY

    def test_revoked_agent_denied(self, env):
        from aegis.registry import AgentRegistry
        registry = AgentRegistry(env["tmpdir"])
        registry.revoke(env["agent"].id, env["user_id"])
        action = _make_action(env["agent"].id, env["test_file"])
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        assert decision.result is DecisionResult.DENY

    def test_audit_event_created_on_success(self, env):
        action = _make_action(env["agent"].id, env["test_file"])
        env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, env["policy_id"],
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert len(events) == 1
        assert events[0].result == "ALLOW"
        assert events[0].action_type == "fs_read"


# ---------------------------------------------------------------------------
# Path security (Filesystem unit tests)
# ---------------------------------------------------------------------------


class TestPathSecurity:
    def test_normal_allowed_file(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            test_file = os.path.join(td, "fs-scope", "test.txt")
            os.makedirs(os.path.dirname(test_file), exist_ok=True)
            with open(test_file, "w") as f:
                f.write("data")
            assert fs.read_file(test_file) == "data"

    def test_relative_path(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            scope = os.path.join(td, "fs-scope")
            os.makedirs(scope, exist_ok=True)
            test_file = os.path.join(scope, "data.txt")
            with open(test_file, "w") as f:
                f.write("rel")
            cwd = os.getcwd()
            try:
                os.chdir(scope)
                content = fs.read_file("data.txt")
                assert content == "rel"
            finally:
                os.chdir(cwd)

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            # Create a file outside the scope
            secret = os.path.join(td, "secret.txt")
            with open(secret, "w") as f:
                f.write("SECRET")
            # Try to read it via traversal
            with pytest.raises(FsError, match="outside the allowed scope"):
                fs.read_file(os.path.join("..", "secret.txt"))

    def test_absolute_path_outside_scope_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            outside = os.path.join(td, "outside.txt")
            with open(outside, "w") as f:
                f.write("outside")
            with pytest.raises(FsError, match="outside the allowed scope"):
                fs.read_file(outside)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            with pytest.raises(FsError, match="not found"):
                fs.read_file(os.path.join(td, "fs-scope", "nope.txt"))

    def test_directory_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            scope = os.path.join(td, "fs-scope")
            os.makedirs(scope, exist_ok=True)
            with pytest.raises(FsError, match="regular file"):
                fs.read_file(scope)

    def test_empty_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            with pytest.raises(FsError, match="empty"):
                fs.read_file("")

    def test_whitespace_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            with pytest.raises(FsError, match="empty"):
                fs.read_file("   ")

    @pytest.mark.skipif(
        sys.platform == "win32" and not os.environ.get("AEGIS_TEST_SYMLINK"),
        reason="Symlink creation requires admin/developer mode on Windows",
    )
    def test_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            scope = os.path.join(td, "fs-scope")
            os.makedirs(scope, exist_ok=True)
            # Create a file outside the scope
            secret = os.path.join(td, "secret.txt")
            with open(secret, "w") as f:
                f.write("secret")
            # Create a symlink inside the scope pointing outside
            link = os.path.join(scope, "escape.lnk")
            os.symlink(secret, link)
            with pytest.raises(FsError, match="outside the allowed scope"):
                fs.read_file(link)


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------


class TestSafety:
    def test_no_write_method(self):
        assert not hasattr(Filesystem, "write_file")
        assert not hasattr(Filesystem, "delete_file")
        assert not hasattr(Filesystem, "execute")
        assert not hasattr(Filesystem, "run")
        assert not hasattr(Filesystem, "read_file_unsafe")

    def test_no_subprocess_import(self):
        """Filesystem should not import subprocess or shutil."""
        import inspect
        import aegis.fs
        source = inspect.getsource(aegis.fs)
        assert "import subprocess" not in source
        assert "from subprocess" not in source
        assert "import shutil" not in source
        assert "from shutil" not in source


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class TestFailureHandling:
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="os.chmod does not restrict owner reads on Windows",
    )
    def test_permission_denied(self):
        with tempfile.TemporaryDirectory() as td:
            fs = Filesystem(td)
            scope = os.path.join(td, "fs-scope")
            test_file = os.path.join(scope, "noaccess.txt")
            with open(test_file, "w") as f:
                f.write("protected")
            os.chmod(test_file, 0o000)
            try:
                with pytest.raises(FsError, match="permission"):
                    fs.read_file(test_file)
            finally:
                os.chmod(test_file, 0o644)

    def test_read_error_from_gateway_integration(self, env):
        """Even if the path is valid for FS, Gateway DENY prevents the read."""
        action = _make_action(env["agent"].id, env["test_file"])
        # Use bad policy → DENY
        decision = env["gateway"].evaluate(
            env["user_id"], action, env["agent"].id, str(uuid.uuid4()),
        )
        assert decision.result is DecisionResult.DENY
