"""Signal handling for clean shutdown on Ctrl+C / SIGINT."""

from __future__ import annotations

import signal
import sys
from typing import Any


def _on_signal(signum: int, _frame: Any | None) -> None:
    """Handle SIGINT/SIGTERM with a clean message and exit."""
    names = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}
    name = names.get(signum, str(signum))
    print(f"\nReceived {name}. Exiting.", file=sys.stderr)
    sys.exit(80)


def install_signal_handlers() -> None:
    """Install signal handlers for SIGINT and SIGTERM."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass
