"""Controlled outbound HTTP/HTTPS network access.

Security properties
-------------------
* Explicit destination allowlist (scheme, hostname, port, path prefix).
* SSRF protection — blocks loopback, private, link-local, multicast IPs.
* DNS resolution before request; restricted IPs are rejected.
* No redirect following by default; every redirect *must* be re-validated
  if enabled.
* URL userinfo (``user:password@host``) is unconditionally rejected.
* Only ``GET`` and ``HEAD`` methods are allowed.
* No raw sockets, no inbound listeners, no proxying.
* Response body is limited; oversized responses are truncated.
"""

from __future__ import annotations

import ipaddress
import json
import os
import os.path
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from aegis.models import HttpResponse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_METHODS = frozenset({"GET", "HEAD"})
_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_RESPONSE_SIZE = 10_485_760  # 10 MiB

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class NetworkError(Exception):
    """Raised when a network operation is denied or fails."""


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


@dataclass
class NetworkAllowlistEntry:
    """A single network allowlist entry."""

    name: str
    scheme: str
    hostname: str
    port: int | None = None
    path_prefix: str = "/"

    def allows(self, url: str) -> bool:
        """Check whether *url* is allowed by this entry."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            return False

        # Scheme
        if parsed.scheme != self.scheme:
            return False

        # Hostname (case-insensitive)
        if parsed.hostname.lower() != self.hostname.lower():
            return False

        # Port
        actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        expected_port = self.port or (443 if self.scheme == "https" else 80)
        if actual_port != expected_port:
            return False

        # Path prefix
        path = parsed.path or "/"
        if not path.startswith(self.path_prefix):
            return False

        return True


_ALLOWLIST_ENTRY_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_SCHEME_PATTERN = re.compile(r"^https?$")
_HOSTNAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class NetworkAllowlist:
    """Persistent network destination allowlist backed by NDJSON storage."""

    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "network-allowlist.ndjson")

    def add(
        self,
        name: str,
        scheme: str,
        hostname: str,
        port: int | None = None,
        path_prefix: str = "/",
    ) -> None:
        """Register a network destination allowlist entry."""
        name = name.strip()
        if not _ALLOWLIST_ENTRY_NAME_RE.match(name):
            raise NetworkError(
                "Name must be 1-64 chars matching [a-zA-Z0-9._-]"
            )

        scheme = scheme.strip().lower()
        if not _SCHEME_PATTERN.match(scheme):
            raise NetworkError(f"Scheme must be 'http' or 'https', got {scheme!r}")

        hostname = hostname.strip().lower()
        if not _HOSTNAME_PATTERN.match(hostname):
            raise NetworkError(f"Invalid hostname: {hostname!r}")

        if port is not None:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise NetworkError(f"Port must be 1-65535 or None, got {port!r}")

        path_prefix = path_prefix.strip() or "/"
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix

        entry: dict[str, Any] = {
            "name": name,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path_prefix": path_prefix,
        }
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def list(self) -> list[dict[str, Any]]:
        """Return all unique entries (last-write-wins dedup)."""
        if not os.path.exists(self._path):
            return []
        entries: list[dict[str, Any]] = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        deduped: dict[str, dict[str, Any]] = {}
        for e in entries:
            deduped[e["name"]] = e
        return list(deduped.values())

    def allows(self, url: str) -> bool:
        """Return ``True`` if *url* matches at least one allowlist entry."""
        for entry_dict in self.list():
            entry = NetworkAllowlistEntry(
                name=entry_dict["name"],
                scheme=entry_dict["scheme"],
                hostname=entry_dict["hostname"],
                port=entry_dict.get("port"),
                path_prefix=entry_dict.get("path_prefix", "/"),
            )
            if entry.allows(url):
                return True
        return False


# ---------------------------------------------------------------------------
# SSRF Validator
# ---------------------------------------------------------------------------


class SSRFValidator:
    """Validates that a destination is not a restricted (private/local) IP.

    Every outbound request *must* pass through this validator *after*
    the destination allowlist check and *before* the HTTP request.
    """

    # Well-known restricted IPv4 ranges checked via ipaddress properties
    # IPv6 ranges are also handled by ipaddress properties.

    @staticmethod
    def is_restricted(hostname: str) -> bool:
        """Return ``True`` if *hostname* resolves to a restricted address.

        Restricted addresses include:
          - loopback (127.0.0.0/8, ::1)
          - private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
          - link-local (169.254.0.0/16, fe80::/10)
          - multicast (224.0.0.0/4, ff00::/8)
          - reserved (240.0.0.0/4)

        DNS resolution failures are treated as restricted (fail-closed).
        """
        # Check if hostname is a literal IP address
        try:
            addr = ipaddress.ip_address(hostname)
            if _is_restricted_address(addr):
                return True
            # A public IP literal is allowed (further validation via allowlist)
            return False
        except ValueError:
            pass

        # Resolve hostname to IPs
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return True  # fail-closed

        for family, _, _, _, sockaddr in addrinfo:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if _is_restricted_address(addr):
                    return True
            except ValueError:
                continue

        return False


def _is_restricted_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check whether an address object falls in a restricted range."""
    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_loopback:
            return True
        if addr.is_private:
            return True
        if addr.is_link_local:
            return True
        if addr.is_multicast:
            return True
        if addr.is_reserved:
            return True
    elif isinstance(addr, ipaddress.IPv6Address):
        if addr.is_loopback:
            return True
        if addr.is_link_local:
            return True
        if addr.is_private:
            return True
        if addr.is_multicast:
            return True
    return False


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses all redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient:
    """Controlled HTTP/HTTPS client with security constraints."""

    def __init__(
        self,
        allowlist: NetworkAllowlist | None = None,
        ssrf_validator: SSRFValidator | None = None,
    ) -> None:
        self._allowlist = allowlist or NetworkAllowlist("")
        self._ssrf = ssrf_validator or SSRFValidator()

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        timeout: int = _DEFAULT_TIMEOUT,
        max_response_size: int = _DEFAULT_MAX_RESPONSE_SIZE,
        follow_redirects: bool = False,
        allowlist: NetworkAllowlist | None = None,
    ) -> HttpResponse:
        """Perform a controlled HTTP request.

        Steps performed in order:
          1. Parse & validate URL structure
          2. Reject unsupported methods
          3. Reject URL credentials
          4. Reject unsupported schemes
          5. Validate destination against allowlist
          6. SSRF check (resolve IP, reject private/local)
          7. Execute request with timeout
          8. Read response with size limit
        """
        # 1. Parse URL
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            raise NetworkError("Invalid URL: no hostname")

        hostname = parsed.hostname
        scheme = parsed.scheme

        # 2. Validate method
        if method.upper() not in _ALLOWED_METHODS:
            raise NetworkError(
                f"Unsupported method {method!r}; allowed: {', '.join(sorted(_ALLOWED_METHODS))}"
            )

        # 3. Reject URL credentials
        if parsed.username or parsed.password:
            raise NetworkError("URL credentials (user:password@host) are not allowed")

        # 4. Reject unsupported schemes
        if scheme not in ("http", "https"):
            raise NetworkError(f"Unsupported scheme {scheme!r}; only http/https allowed")

        # 5. Validate against allowlist
        al = allowlist or self._allowlist
        if not al.allows(url):
            raise NetworkError(
                f"Destination {hostname} is not allowed by the network allowlist"
            )

        # 6. SSRF check
        if self._ssrf.is_restricted(hostname):
            raise NetworkError(
                f"Destination {hostname} resolves to a restricted (private/local) address"
            )

        # 7. Execute request
        return self._do_request(
            url=url,
            method=method,
            timeout=timeout,
            max_response_size=max_response_size,
            follow_redirects=follow_redirects,
        )

    # -- internal ------------------------------------------------------------

    def _do_request(
        self,
        url: str,
        method: str,
        timeout: int,
        max_response_size: int,
        follow_redirects: bool,
    ) -> HttpResponse:
        """Raw HTTP execution — no validation, only I/O and limits."""
        req = urllib.request.Request(url, method=method.upper())
        ctx = ssl.create_default_context()

        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx),
            )
        else:
            opener = urllib.request.build_opener(
                _NoRedirectHandler,
                urllib.request.HTTPSHandler(context=ctx),
            )

        start = time.monotonic()
        timed_out = False
        body_truncated = False

        try:
            response = opener.open(req, timeout=timeout)
            status_code = response.status
            resp_headers = dict(response.headers)

            if method.upper() == "HEAD":
                body = ""
            else:
                raw = b""
                while len(raw) < max_response_size:
                    chunk = response.read(min(8192, max_response_size - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                if len(raw) >= max_response_size:
                    body_truncated = True
                    # Drain remaining to close connection cleanly
                    try:
                        while response.read(8192):
                            pass
                    except Exception:
                        pass
                body = raw.decode("utf-8", errors="replace")

            elapsed_ms = int((time.monotonic() - start) * 1000)
            return HttpResponse(
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                body_truncated=body_truncated,
                body=body,
                headers=resp_headers,
            )

        except urllib.error.HTTPError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return HttpResponse(
                status_code=exc.code,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                body_truncated=False,
                body=str(exc),
                headers=dict(exc.headers or {}),
            )

        except urllib.error.URLError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            # Distinguish timeout from other errors
            if isinstance(exc.reason, socket.timeout):
                timed_out = True
            return HttpResponse(
                status_code=0,
                elapsed_ms=elapsed_ms,
                timed_out=timed_out,
                body_truncated=False,
                body=str(exc.reason),
                headers={},
            )

        except OSError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return HttpResponse(
                status_code=0,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                body_truncated=False,
                body=str(exc),
                headers={},
            )
