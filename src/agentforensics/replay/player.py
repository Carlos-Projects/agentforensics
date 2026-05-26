"""Replay agent behaviour from a forensic timeline at configurable speed."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any

from agentforensics.utils.dates import to_epoch as _to_epoch


def replay_events(
    events: list[dict[str, Any]],
    speed: float = 1.0,
    interactive: bool = False,
    on_event: Callable[[dict[str, Any]], Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Replay events in chronological order with optional real-time pacing.

    Args:
        events: Sorted list of forensic events.
        speed: Playback speed multiplier (``1.0`` = real-time).
        interactive: If True, pause after each event and wait for keypress.
        on_event: Optional callback ``fn(event)`` invoked per event.

    Yields:
        Events in playback order with a ``_replay_delay`` field added.
    """
    if not events:
        return

    sorted_events = sorted(
        events,
        key=lambda e: _to_epoch(e.get("timestamp", "")),
    )

    prev_ts = _to_epoch(sorted_events[0].get("timestamp", ""))

    for ev in sorted_events:
        ts = _to_epoch(ev.get("timestamp", ""))
        delta = (ts - prev_ts) / max(speed, 0.01)

        if delta > 0 and speed > 0:
            time.sleep(delta)

        ev = dict(ev)
        ev["_replay_delay"] = round(delta, 3)

        if on_event:
            on_event(ev)

        yield ev

        if interactive:
            try:
                input("  [Press Enter to continue, q to quit] ")
            except (EOFError, KeyboardInterrupt):
                return

        prev_ts = ts
