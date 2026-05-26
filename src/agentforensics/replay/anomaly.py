"""Detect anomalous patterns in replayed agent behaviour."""

from __future__ import annotations

from typing import Any

from agentforensics.utils.dates import to_epoch as _to_epoch


def detect_anomalies(
    events: list[dict[str, Any]],
    high_frequency_threshold: float = 0.5,
    rare_event_types: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect anomalies in a sequence of agent events.

    Detection strategies:

    - **High frequency**: more than *high_frequency_threshold* events per
      second (rolling two-event window).
    - **Rare event type**: events whose type appears in *rare_event_types*.
    - **High-risk event**: risk_score >= 8.0.
    - **Repetition**: same event_type repeated consecutively 5+ times.
    - **Blocked chain**: consecutive blocked events (a blocked agent retrying).

    Args:
        events: Chronological list of events.
        high_frequency_threshold: Max events/second before flagging.
        rare_event_types: Event types considered intrinsically anomalous.

    Returns:
        List of anomaly dicts::

            {
                "type": str,
                "severity": str,
                "description": str,
                "event": dict,
                "score": float,
            }
    """
    anomalies: list[dict[str, Any]] = []
    rare = set(rare_event_types or [])

    for _i, ev in enumerate(events):
        # Rare event type
        etype = ev.get("event_type", "")
        if etype in rare:
            anomalies.append(
                {
                    "type": "rare_event_type",
                    "severity": "high",
                    "description": f"Rare event type '{etype}' observed",
                    "event": ev,
                    "score": 8.0,
                }
            )

        # High risk
        risk = float(ev.get("risk_score", 0))
        if risk >= 8.0:
            anomalies.append(
                {
                    "type": "high_risk",
                    "severity": "critical" if risk >= 9.0 else "high",
                    "description": f"Risk score {risk:.1f} exceeds threshold",
                    "event": ev,
                    "score": risk,
                }
            )

    # --- High frequency (sustained burst) ---
    if len(events) >= 3:
        # sliding window of 3 events
        for i in range(len(events) - 2):
            window = events[i : i + 3]
            tss = [_to_epoch(e.get("timestamp", "")) for e in window]
            if tss[0] and tss[-1]:
                elapsed = tss[-1] - tss[0]
                if elapsed > 0 and (3.0 / elapsed) > high_frequency_threshold:
                    anomalies.append(
                        {
                            "type": "high_frequency",
                            "severity": "medium",
                            "description": f"Burst of {len(window)} events in {elapsed:.1f}s",
                            "event": window[-1],
                            "score": min(10.0, 3.0 / elapsed * 2),
                        }
                    )

    # --- Repetition ---
    if len(events) >= 5:
        for i in range(len(events) - 4):
            chunk = events[i : i + 5]
            types = [e.get("event_type", "") for e in chunk]
            if len(set(types)) == 1:
                anomalies.append(
                    {
                        "type": "repetition",
                        "severity": "medium",
                        "description": f"Same event repeated 5 times: '{types[0]}'",
                        "event": chunk[-1],
                        "score": 7.0,
                    }
                )
                break  # one repetition anomaly is enough

    # --- Blocked chain ---
    blocked_streak = 0
    for ev in events:
        if ev.get("blocked"):
            blocked_streak += 1
        else:
            if blocked_streak >= 3:
                anomalies.append(
                    {
                        "type": "blocked_chain",
                        "severity": "high",
                        "description": f"Agent had {blocked_streak} consecutive blocked actions",
                        "event": ev,
                        "score": min(10.0, blocked_streak * 2),
                    }
                )
            blocked_streak = 0
    if blocked_streak >= 3:
        anomalies.append(
            {
                "type": "blocked_chain",
                "severity": "high",
                "description": f"Agent had {blocked_streak} consecutive blocked actions at end",
                "event": events[-1],
                "score": min(10.0, blocked_streak * 2),
            }
        )

    return anomalies


