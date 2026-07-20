"""Tests for controlled outbound network access."""

import io
import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest

from aegis.auth import Authenticator
from aegis.gateway import Gateway
from aegis.models import Action, DecisionResult
from aegis.network import (
    HttpClient,
    NetworkAllowlist,
    NetworkAllowlistEntry,
    NetworkError,
    SSRFValidator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_POLICY_ID = str(uuid.uuid4())

_ALLOW_NET_POLICY = f"""\
version: "1.0"
id: "{_POLICY_ID}"
name: allow-net
priority: 100
enabled: true
rules:
  - effect: ALLOW
    match:
      action_type: "http_request"
  - effect: DENY
    match:
      action_type: "*"
"""


@pytest.fixture
def env():
    """Set up a fully provisioned test environment."""
    tmpdir = tempfile.mkdtemp()
    auth = Authenticator(tmpdir)
    user = auth.register("netuser", "ValidPass1!")

    from aegis.registry import AgentRegistry
    registry = AgentRegistry(tmpdir)
    agent = registry.create(user.id, "net-agent")

    from aegis.policy import parse_policy_yaml, PolicyStore
    policy = parse_policy_yaml(_ALLOW_NET_POLICY, user.id)
    store = PolicyStore(tmpdir)
    store.save(policy)

    # Activate Pro subscription for entitlement
    from aegis.entitlement import EntitlementService
    svc = EntitlementService(tmpdir)
    svc.activate_subscription(user.id, "pro")

    # Add a network allowlist entry for testing
    al = NetworkAllowlist(tmpdir)
    al.add("example", "https", "example.com", path_prefix="/")
    al.add("httpbin", "https", "httpbin.org", path_prefix="/")
    al.add("http-example", "http", "example.com", port=8080, path_prefix="/")

    return {
        "tmpdir": tmpdir,
        "gateway": Gateway(tmpdir),
        "user_id": user.id,
        "agent": agent,
        "policy_id": policy.id,
        "allowlist": al,
    }


def _make_http_action(agent_id: str, url: str, method: str = "GET") -> Action:
    return Action(
        action_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action_type="http_request",
        params={"url": url, "method": method},
        requested_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Monkey-patch helpers
# ---------------------------------------------------------------------------

_MOCK_DNS = {}


def _set_dns(hostname: str, *ips: str) -> None:
    """Configure mock DNS for a hostname."""
    _MOCK_DNS[hostname.lower()] = list(ips)


def _mock_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Mock socket.getaddrinfo."""
    import socket as _socket
    ips = _MOCK_DNS.get(host.lower(), [])
    if not ips:
        raise _socket.gaierror(11001, "getaddrinfo failed")
    results = []
    for ip in ips:
        family = _socket.AF_INET if "." in ip else _socket.AF_INET6
        results.append((family, _socket.SOCK_STREAM, 6, "", (ip, port or 0)))
    return results


# ---------------------------------------------------------------------------
# NetworkAllowlistEntry unit tests
# ---------------------------------------------------------------------------


class TestNetworkAllowlistEntry:
    def test_exact_match(self):
        entry = NetworkAllowlistEntry("t", "https", "api.example.com")
        assert entry.allows("https://api.example.com/v1/users")

    def test_scheme_mismatch(self):
        entry = NetworkAllowlistEntry("t", "https", "example.com")
        assert not entry.allows("http://example.com/")

    def test_hostname_case_insensitive(self):
        entry = NetworkAllowlistEntry("t", "https", "Api.Example.COM")
        assert entry.allows("https://api.example.com/")

    def test_port_mismatch(self):
        entry = NetworkAllowlistEntry("t", "https", "example.com", port=443)
        assert not entry.allows("https://example.com:8443/")

    def test_port_default_443_for_https(self):
        entry = NetworkAllowlistEntry("t", "https", "example.com")
        assert entry.allows("https://example.com/")  # default 443

    def test_port_default_80_for_http(self):
        entry = NetworkAllowlistEntry("t", "http", "example.com")
        assert entry.allows("http://example.com/")

    def test_path_prefix(self):
        entry = NetworkAllowlistEntry("t", "https", "example.com", path_prefix="/api/")
        assert entry.allows("https://example.com/api/v1/users")
        assert not entry.allows("https://example.com/other")

    def test_different_hostname(self):
        entry = NetworkAllowlistEntry("t", "https", "allowed.com")
        assert not entry.allows("https://evil.com/")


# ---------------------------------------------------------------------------
# NetworkAllowlist unit tests
# ---------------------------------------------------------------------------


class TestNetworkAllowlist:
    def test_add_and_allows(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            al.add("test", "https", "example.com")
            assert al.allows("https://example.com/")
            assert not al.allows("http://evil.com/")

    def test_add_with_port_and_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            al.add("test", "http", "example.com", port=8080, path_prefix="/api")
            assert al.allows("http://example.com:8080/api/v1")
            assert not al.allows("http://example.com:8080/other")
            assert not al.allows("http://example.com:9090/api/v1")

    def test_empty_allowlist_denies_all(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            assert not al.allows("https://example.com/")

    def test_list_entries(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            al.add("a", "https", "a.com")
            al.add("b", "http", "b.com")
            entries = al.list()
            assert len(entries) == 2

    def test_invalid_name_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            with pytest.raises(NetworkError, match="Name"):
                al.add("", "https", "example.com")

    def test_invalid_hostname_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            al = NetworkAllowlist(td)
            with pytest.raises(NetworkError, match="hostname"):
                al.add("x", "https", "...")


# ---------------------------------------------------------------------------
# SSRFValidator unit tests
# ---------------------------------------------------------------------------


class TestSSRFValidator:
    def setup_method(self):
        _MOCK_DNS.clear()

    def test_loopback_ipv4_rejected(self):
        assert SSRFValidator.is_restricted("127.0.0.1")
        assert SSRFValidator.is_restricted("127.0.0.0")
        assert SSRFValidator.is_restricted("127.255.255.255")

    def test_private_ipv4_rejected(self):
        assert SSRFValidator.is_restricted("10.0.0.1")
        assert SSRFValidator.is_restricted("172.16.0.1")
        assert SSRFValidator.is_restricted("192.168.1.1")

    def test_link_local_rejected(self):
        assert SSRFValidator.is_restricted("169.254.1.1")

    def test_multicast_rejected(self):
        assert SSRFValidator.is_restricted("224.0.0.1")

    def test_reserved_rejected(self):
        assert SSRFValidator.is_restricted("240.0.0.1")

    def test_public_ip_allowed(self):
        assert not SSRFValidator.is_restricted("93.184.216.34")  # example.com

    def test_ipv6_loopback_rejected(self):
        assert SSRFValidator.is_restricted("::1")

    def test_ipv6_link_local_rejected(self):
        assert SSRFValidator.is_restricted("fe80::1")

    def test_ipv6_unique_local_rejected(self):
        assert SSRFValidator.is_restricted("fc00::1")
        assert SSRFValidator.is_restricted("fd00::1")

    @patch("socket.getaddrinfo")
    def test_hostname_resolves_to_private(self, mock_gai):
        mock_gai.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 80)),
        ]
        assert SSRFValidator.is_restricted("internal.example.com")

    @patch("socket.getaddrinfo")
    def test_hostname_resolves_to_public(self, mock_gai):
        mock_gai.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
        ]
        assert not SSRFValidator.is_restricted("example.com")

    @patch("socket.getaddrinfo")
    def test_dns_failure_treated_as_restricted(self, mock_gai):
        import socket
        mock_gai.side_effect = socket.gaierror("DNS failure")
        assert SSRFValidator.is_restricted("unknown.example.com")

    @patch("socket.getaddrinfo")
    def test_hostname_resolves_to_mixed_private_and_public(self, mock_gai):
        """If any resolved IP is restricted, the destination is restricted."""
        mock_gai.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)),
            (2, 1, 6, "", ("10.0.0.1", 80)),
        ]
        assert SSRFValidator.is_restricted("split-horizon.example.com")


# ---------------------------------------------------------------------------
# HttpClient unit tests (mocked)
# ---------------------------------------------------------------------------


class _MockHTTPResponse:
    """Simulates an http.client.HTTPResponse for testing."""

    def __init__(self, status=200, headers=None, body=b"OK"):
        self.status = status
        self.headers = headers or {}
        self._body = body
        self._pos = 0

    def read(self, amt=None):
        if self._pos >= len(self._body):
            return b""
        if amt is None:
            chunk = self._body[self._pos:]
            self._pos = len(self._body)
        else:
            chunk = self._body[self._pos:self._pos + amt]
            self._pos += amt
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TestHttpClient:
    def setup_method(self):
        _MOCK_DNS.clear()
        _MOCK_DNS["example.com"] = ["93.184.216.34"]

    def _make_client(self, allowlist=None):
        td = tempfile.mkdtemp()
        al = allowlist or NetworkAllowlist(td)
        al.add("example", "https", "example.com")
        return HttpClient(allowlist=al, ssrf_validator=SSRFValidator())

    @patch("urllib.request.build_opener")
    def test_get_success(self, mock_builder):
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener
        mock_opener.open.return_value = _MockHTTPResponse(
            status=200, body=b'{"ok": true}'
        )

        client = self._make_client()
        result = client.request("https://example.com/api", method="GET")
        assert result.status_code == 200
        assert '{"ok": true}' in result.body
        assert not result.timed_out
        assert not result.body_truncated

    @patch("urllib.request.build_opener")
    def test_head_method(self, mock_builder):
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener
        mock_opener.open.return_value = _MockHTTPResponse(
            status=200, body=b""
        )

        client = self._make_client()
        result = client.request("https://example.com/", method="HEAD")
        assert result.status_code == 200
        assert result.body == ""

    def test_unsupported_method_rejected(self):
        client = self._make_client()
        with pytest.raises(NetworkError, match="Unsupported method"):
            client.request("https://example.com/", method="POST")

    def test_invalid_url_rejected(self):
        client = self._make_client()
        with pytest.raises(NetworkError, match="no hostname"):
            client.request("not-a-url")

    def test_unsupported_scheme_rejected(self):
        client = self._make_client()
        with pytest.raises(NetworkError, match="Unsupported scheme"):
            client.request("ftp://example.com/")

    def test_url_credentials_rejected(self):
        client = self._make_client()
        with pytest.raises(NetworkError, match="credentials"):
            client.request("https://user:pass@example.com/")

    def test_not_allowlisted_denied(self):
        td = tempfile.mkdtemp()
        al = NetworkAllowlist(td)
        client = HttpClient(allowlist=al, ssrf_validator=SSRFValidator())
        with pytest.raises(NetworkError, match="not allowed"):
            client.request("https://evil.com/")

    @patch("urllib.request.build_opener")
    def test_response_size_limit(self, mock_builder):
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener
        # Return a response larger than limit
        big_body = b"x" * 2000
        mock_opener.open.return_value = _MockHTTPResponse(
            status=200, body=big_body
        )

        client = self._make_client()
        result = client.request(
            "https://example.com/", method="GET", max_response_size=100,
        )
        assert result.body_truncated
        assert len(result.body) <= 100

    @patch("urllib.request.build_opener")
    def test_timeout_handled(self, mock_builder):
        import socket
        import urllib.error

        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener
        mock_opener.open.side_effect = urllib.error.URLError(
            socket.timeout("timed out")
        )

        client = self._make_client()
        result = client.request("https://example.com/", method="GET")
        assert result.timed_out
        assert result.status_code == 0

    @patch("urllib.request.build_opener")
    def test_http_error_handled(self, mock_builder):
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener

        import urllib.error
        mock_opener.open.side_effect = urllib.error.HTTPError(
            "https://example.com/", 404, "Not Found", {}, None,
        )

        client = self._make_client()
        result = client.request("https://example.com/", method="GET")
        assert result.status_code == 404

    @patch("urllib.request.build_opener")
    def test_localhost_rejected_by_ssrf(self, mock_builder):
        """Even if allowlisted, SSRF blocks private destinations."""
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener
        mock_opener.open.return_value = _MockHTTPResponse(status=200, body=b"x")

        td = tempfile.mkdtemp()
        al = NetworkAllowlist(td)
        al.add("local", "http", "127.0.0.1")
        client = HttpClient(allowlist=al, ssrf_validator=SSRFValidator())
        with pytest.raises(NetworkError, match="restricted"):
            client.request("http://127.0.0.1/")

    @patch("urllib.request.build_opener")
    def test_ssrf_check_before_request(self, mock_builder):
        """SSRF check must happen before any HTTP request."""
        mock_opener = MagicMock()
        mock_builder.return_value = mock_opener

        td = tempfile.mkdtemp()
        al = NetworkAllowlist(td)
        al.add("local", "http", "localhost")
        client = HttpClient(allowlist=al, ssrf_validator=SSRFValidator())
        with pytest.raises(NetworkError, match="restricted"):
            client.request("http://localhost/")
        # The opener should never have been called
        mock_opener.open.assert_not_called()


# ---------------------------------------------------------------------------
# Security tests (Gateway integration)
# ---------------------------------------------------------------------------


class TestNetworkSecurity:
    def test_authorized_user_allowed(self, env):
        action = _make_http_action(env["agent"].id, "https://example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://example.com/",
        )
        # Decision should be ALLOW (HTTP request is not actually made
        # because SSRF will fail to resolve, but the gateway flow
        # reaches step 5 — the DENY comes from the network layer)
        # Actually, with the mocked DNS this will fail at SSRF.
        # But the DECISION from policy evaluation is what matters here.
        assert decision.result is DecisionResult.ALLOW

    def test_policy_deny_prevents_request(self, env):
        action = _make_http_action(env["agent"].id, "https://example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, str(uuid.uuid4()),
            url="https://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_unauthorized_user_denied(self, env):
        action = _make_http_action(env["agent"].id, "https://example.com/")
        decision, result = env["gateway"].http_request(
            "", action, env["agent"].id, env["policy_id"],
            url="https://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_unknown_agent_denied(self, env):
        action = _make_http_action(str(uuid.uuid4()), "https://example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, str(uuid.uuid4()), env["policy_id"],
            url="https://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_revoked_agent_denied(self, env):
        from aegis.registry import AgentRegistry
        registry = AgentRegistry(env["tmpdir"])
        registry.revoke(env["agent"].id, env["user_id"])
        action = _make_http_action(env["agent"].id, "https://example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_url_credentials_rejected_in_gateway(self, env):
        action = _make_http_action(
            env["agent"].id, "https://user:pass@example.com/",
        )
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://user:pass@example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_unsupported_scheme_rejected(self, env):
        action = _make_http_action(env["agent"].id, "ftp://example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="ftp://example.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    def test_not_allowlisted_denied(self, env):
        action = _make_http_action(env["agent"].id, "https://evil.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://evil.com/",
        )
        assert decision.result is DecisionResult.DENY
        assert result is None

    @patch("socket.getaddrinfo")
    def test_private_destination_blocked_by_ssrf(self, mock_gai, env):
        mock_gai.return_value = [
            (2, 1, 6, "", ("10.0.0.1", 80)),
        ]
        action = _make_http_action(env["agent"].id, "http://internal.example.com/")
        decision, result = env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="http://internal.example.com/",
        )
        assert decision.result is DecisionResult.DENY

    def test_no_raw_socket_capability(self):
        """Verify no raw socket usage in network module."""
        import inspect
        import aegis.network
        source = inspect.getsource(aegis.network)
        assert "socket.SOCK_RAW" not in source
        assert "SOCK_RAW" not in source


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------


class TestNetworkAudit:
    def test_allowed_request_auditable(self, env):
        action = _make_http_action(env["agent"].id, "https://example.com/")
        env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://example.com/",
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert any(e.result == "ALLOW" for e in events)

    def test_denied_request_auditable(self, env):
        """Policy ALLOWs but network allowlist rejects — must still audit."""
        action = _make_http_action(env["agent"].id, "https://evil.com/")
        env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://evil.com/",
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        assert any(e.result == "DENY" for e in events)

    def test_audit_contains_http_metadata(self, env):
        action = _make_http_action(env["agent"].id, "https://example.com/")
        env["gateway"].http_request(
            env["user_id"], action, env["agent"].id, env["policy_id"],
            url="https://example.com/",
        )
        from aegis.audit import AuditStore
        store = AuditStore(env["tmpdir"])
        events = store.list(env["user_id"])
        # Find the ALLOW event which should have HTTP metadata in params
        for e in reversed(events):
            if e.result == "ALLOW":
                params = e.params
                assert "url" in params or "status_code" in params
                break
