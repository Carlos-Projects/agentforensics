"""Core forensics engine — orchestrates ingestion, persistence, and analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentforensics.ingest.agentgate import parse_agentgate_signal
from agentforensics.ingest.generic import parse_generic_log
from agentforensics.ingest.mcpguard import parse_mcpguard_log
from agentforensics.replay.anomaly import detect_anomalies
from agentforensics.replay.diff import diff_behavior
from agentforensics.reports.compliance import check_compliance
from agentforensics.reports.evidence import clear_chain, create_chain_entry, get_chain
from agentforensics.reports.generator import generate_report
from agentforensics.timeline.builder import TimelineBuilder


class ForensicsEngine:
    """Main forensics analysis engine with SQLite persistence."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = db_path
        self._timeline = TimelineBuilder(db_path)

    def ingest_mcpguard(self, path: Path) -> int:
        """Ingest MCPGuard logs.

        Args:
            path: Path to JSONL log file.

        Returns:
            Number of events ingested.
        """
        count = 0
        for event in parse_mcpguard_log(path):
            self._timeline.insert(event)
            count += 1
        return count

    def ingest_agentgate(self, path: Path) -> int:
        """Ingest AgentGate signals.

        Args:
            path: Path to signal file.

        Returns:
            Number of events ingested.
        """
        count = 0
        for event in parse_agentgate_signal(path):
            self._timeline.insert(event)
            count += 1
        return count

    def ingest_generic(self, path: Path, fmt: str = "auto") -> int:
        """Ingest generic log files.

        Args:
            path: Path to log file.
            fmt: Format hint.

        Returns:
            Number of events ingested.
        """
        count = 0
        for event in parse_generic_log(path, fmt=fmt):
            self._timeline.insert(event)
            count += 1
        return count

    def ingest_structured(self, event: dict[str, Any]) -> int:
        """Insert a single structured event directly.

        Args:
            event: Event dictionary.

        Returns:
            Row id of inserted event.
        """
        return self._timeline.insert(event)

    def build_timeline(self) -> list[dict[str, Any]]:
        """Build and return the full forensic timeline.

        Returns:
            Sorted list of all events.
        """
        return self._timeline.get_timeline()

    def get_sources(self) -> list[str]:
        """List unique event sources."""
        return self._timeline.sources()

    def get_event_types(self) -> list[str]:
        """List unique event types."""
        return self._timeline.event_types()

    def get_severity_counts(self) -> dict[str, int]:
        """Get counts per severity level."""
        return self._timeline.severity_counts()

    def query_events(
        self,
        source: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        min_risk: float | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query events with optional filters."""
        return self._timeline.query(
            source=source,
            event_type=event_type,
            severity=severity,
            min_risk=min_risk,
            limit=limit,
        )

    def analyze_anomalies(
        self,
        high_frequency_threshold: float = 0.5,
        rare_event_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run anomaly detection on the timeline.

        Args:
            high_frequency_threshold: Max events/second.
            rare_event_types: Event types considered anomalous.

        Returns:
            List of detected anomalies.
        """
        events = self.build_timeline()
        return detect_anomalies(events, high_frequency_threshold, rare_event_types)

    def analyze_deviations(self, policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run policy deviation analysis.

        Args:
            policy: Policy rules dict.

        Returns:
            List of deviations found.
        """
        events = self.build_timeline()
        return diff_behavior(events, policy=policy)

    def generate_report(
        self,
        fmt: str = "markdown",
        incident_id: str = "INC-UNKNOWN",
    ) -> str:
        """Generate a comprehensive forensic report.

        Args:
            fmt: Output format.
            incident_id: Incident identifier.

        Returns:
            Formatted report string.
        """
        events = self.build_timeline()
        anomalies = self.analyze_anomalies()
        deviations = self.analyze_deviations()
        evidence = get_chain()

        return generate_report(
            timeline=events,
            anomalies=anomalies,
            deviations=deviations,
            evidence_chain=evidence,
            fmt=fmt,
            incident_id=incident_id,
        )

    def check_compliance(self, framework: str = "nist_ai_rmf") -> dict[str, Any]:
        """Run compliance checks.

        Args:
            framework: Compliance framework.

        Returns:
            Compliance results dict.
        """
        events = self.build_timeline()
        return check_compliance(events, framework=framework)

    def add_evidence(self, evidence_id: str, data: bytes, collector: str = "agentforensics") -> dict[str, Any]:
        """Add an evidence entry with integrity hash.

        Args:
            evidence_id: Unique evidence identifier.
            data: Raw evidence data.
            collector: Collector identity.

        Returns:
            Chain of custody entry.
        """
        from agentforensics.reports.evidence import compute_evidence_hash

        h = compute_evidence_hash(data)
        return create_chain_entry(evidence_id, h, collector)

    def clear_evidence(self) -> None:
        """Clear the evidence chain."""
        clear_chain()

    def close(self) -> None:
        """Close the database connection."""
        self._timeline.close()

    @property
    def event_count(self) -> int:
        """Total ingested events."""
        return self._timeline.count()
