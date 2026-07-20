"""Controlled read-only filesystem capability.

Scope model
-----------
All file reads are constrained to an *allowed scope* directory.
The scope defaults to ``<data_dir>/fs-scope/`` and is created on first
use.  Every path is resolved to its canonical form via
``os.path.realpath()`` and checked for containment within the scope.

Path canonicalisation & containment
------------------------------------
1. Relative paths are resolved against the scope root.
2. ``os.path.realpath()`` resolves symlinks, ``..``, junctions, and
   reparse points to an absolute canonical path.
3. Containment check: the canonical path must equal the scope directory
   or start with ``scope + os.sep``.
4. Case-insensitive comparison on Windows via ``os.path.normcase()``.

Security invariants
-------------------
- No write, delete, shell, or subprocess operations are exposed.
- Path traversal (``../``, symlink escape) is defeated by canonical
  resolution *before* the containment check.
- The scope is resolved once at initialisation so the anchor is stable.

Failure semantics
-----------------
All failures raise ``FsError`` — no unauthorised read is ever performed.
"""

from __future__ import annotations

import os
import os.path


class FsError(Exception):
    """Raised when a filesystem operation is rejected or fails."""


class Filesystem:
    """Read-only filesystem capability confined to an allowed scope."""

    def __init__(self, data_dir: str) -> None:
        scope = os.path.join(data_dir, "fs-scope")
        os.makedirs(scope, exist_ok=True)
        self._scope = os.path.realpath(scope)

    # -- public API ----------------------------------------------------------

    def read_file(self, path: str) -> str:
        """Read a text file within the allowed scope.

        Args:
            path: Absolute or relative path to the file.

        Returns:
            UTF-8 decoded contents of the file.

        Raises:
            FsError: if the path is invalid, outside the scope, not a
                     regular file, or unreadable.
        """
        resolved = self._resolve(path)
        self._assert_contained(resolved)
        self._assert_readable(resolved)

        try:
            with open(resolved, "r", encoding="utf-8") as f:
                return f.read()
        except PermissionError:
            raise FsError(f"Permission denied: {path}")
        except OSError as e:
            raise FsError(f"Read error for {path!r}: {e}")

    # -- internal helpers ----------------------------------------------------

    def _resolve(self, path: str) -> str:
        """Return the canonical absolute path for *path*."""
        if not path or not path.strip():
            raise FsError("Path must not be empty")
        if not os.path.isabs(path):
            path = os.path.join(self._scope, path)
        return os.path.realpath(path)

    def _assert_contained(self, resolved: str) -> None:
        scope_norm = os.path.normcase(self._scope)
        path_norm = os.path.normcase(resolved)
        if path_norm == scope_norm:
            return  # the scope directory itself — allow listing
        if not path_norm.startswith(scope_norm + os.sep):
            raise FsError(f"Path {resolved!r} is outside the allowed scope")

    def _assert_readable(self, resolved: str) -> None:
        if not os.path.exists(resolved):
            raise FsError(f"File not found: {resolved}")
        if not os.path.isfile(resolved):
            raise FsError(f"Not a regular file: {resolved}")
        if not os.access(resolved, os.R_OK):
            raise FsError(f"Permission denied: {resolved}")
