"""Correlate events across multiple sources within configurable time windows."""

from __future__ import annotations

from typing import Any

from agentforensics.utils.dates import to_epoch as _to_epoch


def correlate_events(
    events: list[dict[str, Any]],
    window_seconds: int = 60,
) -> list[dict[str, Any]]:
    """Group events from multiple sources within sliding time windows.

    Events whose timestamps fall within *window_seconds* of each other are
    grouped into a single correlation group.

    Args:
        events: List of event dictionaries.
        window_seconds: Maximum gap (seconds) for two events to be correlated.

    Returns:
        List of correlation groups.  Each group has the shape::

            {
                "window_start": ISO timestamp,
                "window_end":   ISO timestamp,
                "event_count":  int,
                "sources":      [str, ...],
                "types":        [str, ...],
                "max_risk":     float,
                "events":       [dict, ...],
            }
    """
    if not events:
        return []

    # Sort by timestamp
    sorted_events = sorted(
        events,
        key=lambda e: _to_epoch(e.get("timestamp", "")),
    )

    groups: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = [sorted_events[0]]

    for ev in sorted_events[1:]:
        ts_cur = _to_epoch(current[0].get("timestamp", ""))
        ts_ev = _to_epoch(ev.get("timestamp", ""))
        if ts_ev - ts_cur <= window_seconds:
            current.append(ev)
        else:
            groups.append(_build_group(current))
            current = [ev]

    if current:
        groups.append(_build_group(current))

    return groups


def _build_group(events: list[dict[str, Any]]) -> dict[str, Any]:
    sources = sorted({e.get("source", "?") for e in events})
    types = sorted({e.get("event_type", "?") for e in events})
    max_risk = max((float(e.get("risk_score", 0)) for e in events), default=0.0)
    timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    timestamps.sort()

    return {
        "window_start": timestamps[0] if timestamps else "",
        "window_end": timestamps[-1] if timestamps else "",
        "event_count": len(events),
        "sources": sources,
        "types": types,
        "max_risk": max_risk,
        "events": events,
    }
