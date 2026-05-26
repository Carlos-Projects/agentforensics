"""Ingest generic log formats (JSON, CSV, syslog, plain text)."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# A line is considered syslog only if it has the characteristic
# 3-letter month + day + HH:MM:SS prefix.
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S")


def _detect_format(path: Path) -> str:
    """Detect log format by inspecting the first lines."""
    with open(path, encoding="utf-8") as f:
        first = f.readline().strip()
        second = f.readline().strip()

    if _looks_like_json(first):
        return "jsonl"
    if "," in first and len(first.split(",")) >= 2:
        header = first.lower()
        if any(w in header for w in ("timestamp", "time", "date", "event", "level")):
            return "csv"
    if _looks_like_syslog(first):
        return "syslog"
    if second and _looks_like_syslog(second):
        return "syslog"
    return "plain"


def _looks_like_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _looks_like_syslog(text: str) -> bool:
    return bool(_SYSLOG_RE.match(text))


_SYSLOG_PARSE_RE = re.compile(
    r"^"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+)\[(?:\d+)\]:\s*"
    r"(.*)$"
)


def _parse_syslog_line(line: str, lineno: int) -> dict[str, Any]:
    m = _SYSLOG_PARSE_RE.match(line)
    if m:
        ts_str, host, app, rest = m.groups()
        return {
            "timestamp": str(ts_str or ""),
            "hostname": host or "",
            "application": app,
            "message": rest.strip(),
        }
    return {
        "timestamp": "",
        "hostname": "",
        "application": "",
        "message": line,
    }


def parse_generic_log(path: Path, fmt: str = "auto") -> Iterator[dict[str, Any]]:
    """Parse generic log files with auto-detection.

    Supported formats:

    - ``jsonl`` — one JSON object per line
    - ``csv`` — comma-separated values with header row
    - ``syslog`` — RFC 3164-style lines
    - ``plain`` — raw text lines

    Args:
        path: Path to the log file.
        fmt: Format hint (``auto``, ``jsonl``, ``csv``, ``syslog``, ``plain``).

    Yields:
        Parsed event dictionaries.
    """
    resolved = _detect_format(path) if fmt == "auto" else fmt

    with open(path, encoding="utf-8") as f:
        if resolved == "csv":
            reader = csv.DictReader(f)
            for row in reader:
                yield {
                    "source": "generic",
                    "format": "csv",
                    "timestamp": row.get("timestamp", row.get("time", datetime.now(UTC).isoformat())),
                    "raw": dict(row),
                }
            return

        if resolved == "jsonl":
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield {
                    "source": "generic",
                    "format": "jsonl",
                    "timestamp": obj.get(
                        "timestamp", obj.get("time", obj.get("@timestamp", datetime.now(UTC).isoformat()))
                    ),
                    "raw": obj,
                }
            return

        if resolved == "syslog":
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                parsed = _parse_syslog_line(line, lineno)
                yield {
                    "source": "generic",
                    "format": "syslog",
                    "timestamp": parsed["timestamp"] or datetime.now(UTC).isoformat(),
                    "raw": parsed,
                }
            return

        # plain text
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if line:
                yield {
                    "source": "generic",
                    "format": "plain",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "raw": {"line": line, "lineno": lineno},
                }
