"""Date/time utility functions."""

from __future__ import annotations

from datetime import datetime


def to_epoch(ts: str) -> float:
    """Best-effort conversion of an ISO timestamp to epoch seconds.

    Args:
        ts: ISO-format timestamp string.

    Returns:
        Epoch seconds, or 0.0 on failure.
    """
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0
