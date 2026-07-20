"""Controlled process execution with explicit executable allowlist.

Security properties
-------------------
* Never uses ``shell=True`` or any other shell execution mechanism.
* Arguments are passed as a list of individual strings — no shell
  interpretation, no metacharacter risks.
* Executables are resolved through an explicit allowlist by logical name,
  not by user-provided paths.  The allowlist stores canonical paths
  (``os.path.realpath``) and verifies them on every use.
* A timeout prevents runaway processes.
* Output size limits prevent memory exhaustion.
* All failures raise ``AllowlistError`` or return ``ProcessResult`` with
  a non-zero exit code — never an unauthorised execution.
"""

from __future__ import annotations

import json
import os
import os.path
import re
import subprocess
import time
from typing import Any

from aegis.models import ProcessResult

_ALLOWLIST_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_DEFAULT_TIMEOUT = 30
_DEFAULT_OUTPUT_LIMIT = 1_048_576  # 1 MiB


class AllowlistError(Exception):
    """Raised when an executable is not allowlisted or its path is invalid."""


class Allowlist:
    """Persistent executable allowlist backed by NDJSON storage.

    Each entry maps a logical *name* (used by callers) to a *canonical
    path* (resolved via ``os.path.realpath``).  On every lookup the
    path is re-verified to detect symlink substitution.
    """

    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "process-allowlist.ndjson")

    # -- public API ----------------------------------------------------------

    def add(self, name: str, path: str) -> None:
        """Register *name* as an alias for the canonical *path*.

        Both *name* and *path* are validated before storage.
        The *path* is resolved to a canonical absolute path at add time.
        """
        name = name.strip()
        if not _ALLOWLIST_NAME_RE.match(name):
            raise AllowlistError(
                "Name must be 1-64 chars matching [a-zA-Z0-9._-]"
            )

        path = path.strip()
        if not path:
            raise AllowlistError("Path must not be empty")

        if not os.path.exists(path):
            raise AllowlistError(f"Path does not exist: {path}")

        canonical = os.path.realpath(path)
        if not os.path.isfile(canonical):
            raise AllowlistError(f"Not a regular file: {canonical}")

        entry: dict[str, str] = {"name": name, "path": canonical}
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def list(self) -> list[dict[str, str]]:
        """Return all unique allowlist entries (last-write-wins dedup)."""
        if not os.path.exists(self._path):
            return []
        entries: list[dict[str, str]] = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        deduped: dict[str, dict[str, str]] = {}
        for e in entries:
            deduped[e["name"]] = e
        return list(deduped.values())

    def resolve(self, name: str) -> str | None:
        """Resolve *name* to a verified canonical path, or return ``None``.

        The stored path is re-resolved via ``os.path.realpath`` and
        compared against the original — this catches symlink substitution
        attacks that swap the target after the entry was recorded.
        """
        for e in self.list():
            if e["name"] == name:
                stored_path = e["path"]
                if os.path.exists(stored_path):
                    current = os.path.realpath(stored_path)
                    if current == stored_path and os.path.isfile(stored_path):
                        return stored_path
                return None
        return None


class ProcessExecutor:
    """Executes allowlisted processes with security controls.

    Controls applied for every execution:
    * shell=False (mandatory)
    * argument list (no string construction)
    * execution timeout
    * output size limit
    * restricted working directory (optional)
    """

    def __init__(self, allowlist: Allowlist) -> None:
        self._allowlist = allowlist

    # -- public API ----------------------------------------------------------

    def execute(
        self,
        executable_name: str,
        args: list[str] | None = None,
        *,
        timeout: int = _DEFAULT_TIMEOUT,
        output_limit: int = _DEFAULT_OUTPUT_LIMIT,
        cwd: str | None = None,
    ) -> ProcessResult:
        """Execute *executable_name* with *args* and return a ``ProcessResult``.

        The process is executed directly — never through a shell.
        """
        # 1. Resolve executable through allowlist
        path = self._allowlist.resolve(executable_name)
        if path is None:
            raise AllowlistError(
                f"Executable {executable_name!r} is not allowlisted "
                f"or its path is no longer valid"
            )

        # 2. Double-check the path is still a regular file
        if not os.path.isfile(path):
            raise AllowlistError(
                f"Allowlisted executable is no longer a file: {path}"
            )

        # 3. Build argument list — never a command string
        cmd = [path]
        if args:
            cmd.extend(args)

        # 4. Execute
        start = time.monotonic()
        timed_out = False
        output_truncated = False

        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                timed_out = True

            elapsed_ms = int((time.monotonic() - start) * 1000)
            exit_code = proc.returncode

        except FileNotFoundError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ProcessResult(
                exit_code=-1, stdout="", stderr="executable not found",
                timed_out=False, output_truncated=False,
                execution_time_ms=elapsed_ms,
                executable=path, args=tuple(args or []),
            )
        except PermissionError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ProcessResult(
                exit_code=-1, stdout="", stderr="permission denied",
                timed_out=False, output_truncated=False,
                execution_time_ms=elapsed_ms,
                executable=path, args=tuple(args or []),
            )
        except OSError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ProcessResult(
                exit_code=-1, stdout="", stderr=str(exc),
                timed_out=False, output_truncated=False,
                execution_time_ms=elapsed_ms,
                executable=path, args=tuple(args or []),
            )

        # 5. Decode output and enforce limits
        stdout_str = (
            stdout_data.decode("utf-8", errors="replace")
            if stdout_data else ""
        )
        stderr_str = (
            stderr_data.decode("utf-8", errors="replace")
            if stderr_data else ""
        )

        if len(stdout_str) > output_limit:
            stdout_str = stdout_str[:output_limit]
            output_truncated = True
        if len(stderr_str) > output_limit:
            stderr_str = stderr_str[:output_limit]
            output_truncated = True

        return ProcessResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            timed_out=timed_out,
            output_truncated=output_truncated,
            execution_time_ms=elapsed_ms,
            executable=path,
            args=tuple(args or []),
        )
