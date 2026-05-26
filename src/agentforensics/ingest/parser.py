"""Log parsing utilities for AgentForensics ingestion."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def normalize_timestamp(ts: str | float | None) -> datetime:
    """Convert various timestamp formats to UTC datetime.

    Args:
        ts: Timestamp as ISO string, epoch float, or None.

    Returns:
        Normalized UTC datetime object.
    """
    if ts is None:
        return datetime.now(UTC)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=UTC)
    try:
        return datetime.fromisoformat(ts).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return datetime.now(UTC)


def safe_json_loads(line: str) -> dict[str, Any]:
    """Safely parse a JSON line, returning empty dict on failure.

    Args:
        line: JSON string to parse.

    Returns:
        Parsed dictionary or empty dict.
    """
    try:
        return json.loads(line)  # type: ignore[no-any-return]
    except (json.JSONDecodeError, TypeError):
        return {}
