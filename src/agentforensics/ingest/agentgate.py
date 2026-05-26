"""Ingest signals from AgentGate firewall events."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_taxonomy import agentgate_signal_to_taxonomy


def parse_agentgate_signal(path: Path) -> Iterator[dict[str, Any]]:
    """Parse AgentGate firewall signal file.

    Each line is a JSON object representing a firewall signal with
    the shape ``{"signal_type": "...", "weight": N, "action": "...", ...}``.
    Normalises through ``mcp_taxonomy.agentgate_signal_to_taxonomy``.

    Args:
        path: Path to the signal file.

    Yields:
        Normalised signal dictionaries.
    """
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue

            # agentgate_signal_to_taxonomy expects keyword arguments
            tax = agentgate_signal_to_taxonomy(
                signal_type=raw.get("signal_type", raw.get("signal", "unknown")),
                weight=int(raw.get("weight", 0)),
                action=raw.get("action", ""),
                path=raw.get("path", ""),
                user_agent=raw.get("user_agent", ""),
                score=int(raw.get("score", 0)),
            )

            yield {
                "source": "agentgate",
                "event_type": tax.attack_category.value if tax.attack_category else "policy_violation",
                "severity": tax.severity.value if tax.severity else "info",
                "confidence": tax.confidence.value if tax.confidence else "low",
                "title": tax.title or "",
                "description": tax.description or "",
                "target": tax.target or "",
                "blocked": True,
                "timestamp": tax.timestamp or datetime.now(UTC).isoformat(),
                "risk_score": tax.risk_score or 0.0,
                "raw": raw,
            }
