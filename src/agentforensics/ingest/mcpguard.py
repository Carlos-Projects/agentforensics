"""Ingest logs from MCPGuard JSONL audit logs."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_taxonomy import mcpguard_event_to_taxonomy


def parse_mcpguard_log(path: Path) -> Iterator[dict[str, Any]]:
    """Parse MCPGuard JSONL audit log file.

    Each line is a JSON object.  The parser attempts to normalise the event
    via ``mcp_taxonomy.mcpguard_event_to_taxonomy`` so that downstream code
    works with a uniform schema.

    Args:
        path: Path to the JSONL log file.

    Yields:
        Normalised event dictionaries.
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

            # Normalize via mcp-taxonomy
            tax = mcpguard_event_to_taxonomy(raw)

            yield {
                "source": "mcpguard",
                "event_type": tax.attack_category.value if tax.attack_category else "unknown",
                "severity": tax.severity.value if tax.severity else "info",
                "confidence": tax.confidence.value if tax.confidence else "low",
                "title": tax.title or "",
                "description": tax.description or "",
                "target": tax.target or "",
                "blocked": tax.blocked if tax.blocked is not None else False,
                "timestamp": tax.timestamp or datetime.now(UTC).isoformat(),
                "risk_score": tax.risk_score or 0.0,
                "raw": raw,
            }
