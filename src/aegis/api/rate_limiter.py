from __future__ import annotations

import json
import os
import os.path
import time
from threading import Lock


class RateLimiter:
    """File-backed rate limiter that works across multiple API workers.

    Uses a JSON file with WAL-style durability. Each worker holds a
    thread lock for local coordination; the file's append-and-rewrite
    pattern ensures cross-process consistency (last writer wins).

    Not intended for sub-second precision — granularity is ~1 second.
    """

    def __init__(self, data_dir: str, window_seconds: int = 60, max_requests: int = 30) -> None:
        self._path = os.path.join(data_dir, "rate-limits.json")
        self._window = window_seconds
        self._max = max_requests
        self._lock = Lock()

    def check(self, key: str) -> bool:
        """Return True if *key* is allowed, False if rate-limited."""
        now = time.time()
        window_start = now - self._window

        with self._lock:
            records = self._read()
            timestamps = records.get(key, [])
            timestamps = [t for t in timestamps if t > window_start]
            if len(timestamps) >= self._max:
                return False
            timestamps.append(now)
            records[key] = timestamps
            self._write(records)
            return True

    def remaining(self, key: str) -> int:
        """Return the number of remaining allowed requests in the window."""
        now = time.time()
        window_start = now - self._window

        with self._lock:
            records = self._read()
            timestamps = records.get(key, [])
            timestamps = [t for t in timestamps if t > window_start]
            remaining = self._max - len(timestamps)
            return max(0, remaining)

    def reset(self, key: str) -> None:
        """Clear rate-limit history for *key*."""
        with self._lock:
            records = self._read()
            records.pop(key, None)
            self._write(records)

    def _read(self) -> dict[str, list[float]]:
        if not os.path.exists(self._path):
            return {}
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, records: dict[str, list[float]]) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(records, f)
        os.replace(tmp, self._path)
