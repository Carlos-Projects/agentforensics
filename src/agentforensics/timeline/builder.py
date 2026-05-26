"""Build forensic timelines from ingested events with SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TimelineBuilder:
    """Build and persist forensic timelines backed by SQLite.

    Can be used as a context manager::

        with TimelineBuilder("path.db") as tb:
            tb.insert(event)
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._db = sqlite3.connect(self._db_path)
        self._db.row_factory = sqlite3.Row
        self._init_schema()

    def __enter__(self) -> TimelineBuilder:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _init_schema(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                source      TEXT NOT NULL,
                event_type  TEXT NOT NULL DEFAULT 'unknown',
                severity    TEXT NOT NULL DEFAULT 'info',
                confidence  TEXT NOT NULL DEFAULT 'low',
                title       TEXT DEFAULT '',
                description TEXT DEFAULT '',
                target      TEXT DEFAULT '',
                blocked     INTEGER DEFAULT 0,
                timestamp   TEXT NOT NULL,
                risk_score  REAL DEFAULT 0.0,
                raw_json    TEXT DEFAULT '{}',
                ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_ts  ON timeline_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_timeline_src ON timeline_events(source);
            CREATE INDEX IF NOT EXISTS idx_timeline_type ON timeline_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_timeline_sev  ON timeline_events(severity);
        """)

    def insert(self, event: dict[str, Any]) -> int:
        """Insert a single event and return its row id."""
        cur = self._db.execute(
            """INSERT INTO timeline_events
               (source, event_type, severity, confidence, title, description,
                target, blocked, timestamp, risk_score, raw_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.get("source", "unknown"),
                event.get("event_type", "unknown"),
                event.get("severity", "info"),
                event.get("confidence", "low"),
                event.get("title", ""),
                event.get("description", ""),
                event.get("target", ""),
                1 if event.get("blocked") else 0,
                event.get("timestamp", datetime.now(UTC).isoformat()),
                float(event.get("risk_score", 0.0)),
                json.dumps(event.get("raw", {}), default=str),
            ),
        )
        self._db.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def insert_many(self, events: list[dict[str, Any]]) -> list[int]:
        """Insert multiple events and return their row ids."""
        ids: list[int] = []
        for ev in events:
            ids.append(self.insert(ev))
        return ids

    def count(self) -> int:
        """Total events in the timeline."""
        return self._db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]  # type: ignore[no-any-return]

    def query(
        self,
        source: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        min_risk: float | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query events with optional filters."""
        where: list[str] = []
        params: list[Any] = []

        if source:
            where.append("source = ?")
            params.append(source)
        if event_type:
            where.append("event_type = ?")
            params.append(event_type)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if min_risk is not None:
            where.append("risk_score >= ?")
            params.append(min_risk)

        # WARNING: `where` list must only contain hardcoded clauses with ?
        # placeholders for values. NEVER interpolate user-controlled strings
        # into `where` — always use parameterized queries via `self._db.execute()`.
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._db.execute(
            f"SELECT * FROM timeline_events {clause} ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

        return [dict(r) for r in rows]

    def get_timeline(self, limit: int = 5000) -> list[dict[str, Any]]:
        """Full chronological timeline."""
        return self.query(limit=limit)

    def sources(self) -> list[str]:
        """List distinct event sources."""
        rows = self._db.execute("SELECT DISTINCT source FROM timeline_events ORDER BY source").fetchall()
        return [r["source"] for r in rows]

    def event_types(self) -> list[str]:
        """List distinct event types."""
        rows = self._db.execute("SELECT DISTINCT event_type FROM timeline_events ORDER BY event_type").fetchall()
        return [r["event_type"] for r in rows]

    def severity_counts(self) -> dict[str, int]:
        """Count events per severity level."""
        rows = self._db.execute(
            "SELECT severity, COUNT(*) as cnt FROM timeline_events GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def close(self) -> None:
        self._db.close()
