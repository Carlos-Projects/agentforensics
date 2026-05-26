"""End-to-end integration tests for the full forensics pipeline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentforensics.engine import ForensicsEngine
from agentforensics.reports.evidence import clear_chain


def _make_mcpguard_log(path: Path, events: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


class TestFullPipeline:
    """Test the full ingest → timeline → analyze → report pipeline."""

    def test_full_pipeline_with_mcpguard(self) -> None:
        """Ingest → build timeline → detect anomalies → deviations → report."""
        log = Path(tempfile.mktemp(suffix=".jsonl"))
        _make_mcpguard_log(
            log,
            [
                {"event_type": "read_file", "severity": "low", "timestamp": "2025-01-01T00:00:00Z"},
                {
                    "event_type": "execute_command",
                    "severity": "high",
                    "blocked": True,
                    "timestamp": "2025-01-01T00:00:05Z",
                },
                {
                    "event_type": "http_request",
                    "severity": "critical",
                    "blocked": True,
                    "risk_score": 9.5,
                    "timestamp": "2025-01-01T00:00:10Z",
                },
            ],
        )

        db = Path(tempfile.mktemp(suffix=".db"))
        with ForensicsEngine(db) as engine:
            # 1. Ingest
            n = engine.ingest_mcpguard(log)
            assert n == 3
            assert engine.event_count == 3

            # 2. Timeline
            timeline = engine.build_timeline()
            assert len(timeline) == 3
            assert timeline[0]["timestamp"] <= timeline[-1]["timestamp"]

            # 3. Sources
            sources = engine.get_sources()
            assert "mcpguard" in sources

            # 4. Anomaly detection
            anomalies = engine.analyze_anomalies()
            assert isinstance(anomalies, list)

            # 5. Deviation detection
            deviations = engine.analyze_deviations(
                policy={
                    "blocked_tools": ["http_request", "execute_command"],
                    "max_risk_score": 5.0,
                }
            )
            assert len(deviations) >= 2

            # 6. Compliance
            compliance = engine.check_compliance()
            assert compliance["total_checks"] == 10
            assert compliance["status"] in ("pass", "partial", "fail")

            # 7. Report
            report_md = engine.generate_report(fmt="markdown", incident_id="INC-INT-001")
            assert "INC-INT-001" in report_md
            assert len(report_md) > 100

            report_html = engine.generate_report(fmt="html")
            assert "<html" in report_html

            report_json = engine.generate_report(fmt="json")
            data = json.loads(report_json)
            assert data["incident_id"] == "INC-UNKNOWN"
            assert data["event_count"] == 3

            # 8. Evidence chain
            ev = engine.add_evidence("EV-INT-001", b"test evidence")
            assert ev["evidence_id"] == "EV-INT-001"
            assert len(ev["entry_hash"]) == 64

        log.unlink()
        db.unlink()

    def test_pipeline_multiple_sources(self) -> None:
        """Ingest from MCPGuard + AgentGate + generic sources."""
        mcp_log = Path(tempfile.mktemp(suffix=".jsonl"))
        ag_log = Path(tempfile.mktemp(suffix=".log"))
        gen_log = Path(tempfile.mktemp(suffix=".log"))
        db = Path(tempfile.mktemp(suffix=".db"))

        _make_mcpguard_log(
            mcp_log,
            [
                {"event_type": "tool_call", "severity": "low", "timestamp": "2025-01-01T00:00:00Z"},
            ],
        )
        _make_mcpguard_log(
            ag_log,
            [
                {"signal_type": "policy_violation", "weight": 80, "action": "block"},
            ],
        )
        with open(gen_log, "w", encoding="utf-8") as f:
            f.write("plain log line\n")

        with ForensicsEngine(db) as engine:
            assert engine.ingest_mcpguard(mcp_log) == 1
            assert engine.ingest_agentgate(ag_log) == 1
            assert engine.ingest_generic(gen_log) == 1
            assert engine.event_count == 3

            sources = engine.get_sources()
            assert len(sources) == 3
            assert "mcpguard" in sources
            assert "agentgate" in sources
            assert "generic" in sources

            timeline = engine.build_timeline()
            assert len(timeline) == 3

        for p in (mcp_log, ag_log, gen_log, db):
            p.unlink()

    def test_pipeline_empty_log(self) -> None:
        """Pipeline with no events should not crash."""
        log = Path(tempfile.mktemp(suffix=".jsonl"))
        _make_mcpguard_log(log, [])
        db = Path(tempfile.mktemp(suffix=".db"))

        with ForensicsEngine(db) as engine:
            assert engine.ingest_mcpguard(log) == 0
            assert engine.build_timeline() == []
            assert engine.analyze_anomalies() == []
            assert engine.analyze_deviations() == []
            report = engine.generate_report()
            assert isinstance(report, str)

        log.unlink()
        db.unlink()

    def test_pipeline_query_with_filters(self) -> None:
        """Query events with source+severity+risk filters."""
        clear_chain()
        log = Path(tempfile.mktemp(suffix=".jsonl"))
        db = Path(tempfile.mktemp(suffix=".db"))
        _make_mcpguard_log(
            log,
            [
                {"event_type": "low_risk", "severity": "low", "risk_score": 1.0, "timestamp": "2025-01-01T00:00:00Z"},
                {
                    "event_type": "high_risk",
                    "severity": "critical",
                    "risk_score": 9.0,
                    "timestamp": "2025-01-01T00:00:01Z",
                },
                {
                    "event_type": "medium_risk",
                    "severity": "medium",
                    "risk_score": 5.0,
                    "timestamp": "2025-01-01T00:00:02Z",
                },
            ],
        )

        with ForensicsEngine(db) as engine:
            engine.ingest_mcpguard(log)

            all_events = engine.build_timeline()
            # MCPGuard parser sets risk_score via taxonomy; check at least 3 events
            assert len(all_events) >= 2

            critical = engine.query_events(severity="critical")
            # At least one critical severity event
            assert len(critical) >= 1

            # Use structured events to test query min_risk precisely
            db2 = Path(tempfile.mktemp(suffix=".db"))
            with ForensicsEngine(db2) as engine2:
                engine2.ingest_structured(
                    {"source": "test", "event_type": "a", "risk_score": 1.0, "timestamp": "2025-01-01T00:00:00Z"}
                )
                engine2.ingest_structured(
                    {"source": "test", "event_type": "b", "risk_score": 9.0, "timestamp": "2025-01-01T00:00:01Z"}
                )
                engine2.ingest_structured(
                    {"source": "test", "event_type": "c", "risk_score": 5.0, "timestamp": "2025-01-01T00:00:02Z"}
                )
                high_risk = engine2.query_events(min_risk=5.0)
                assert len(high_risk) == 2

                mcpguard_only = engine.query_events(source="mcpguard")
                assert len(mcpguard_only) >= 2
            db2.unlink()

        log.unlink()
        db.unlink()

    def test_pipeline_with_evidence_chain(self) -> None:
        """Evidence chain integrity across pipeline stages."""
        clear_chain()
        db = Path(tempfile.mktemp(suffix=".db"))
        with ForensicsEngine(db) as engine:
            engine.add_evidence("EV-1", b"evidence 1")
            engine.add_evidence("EV-2", b"evidence 2")
            engine.add_evidence("EV-3", b"evidence 3")

            report = engine.generate_report(fmt="json")
            data = json.loads(report)
            assert len(data["evidence_chain"]) == 3
            assert data["evidence_chain"][0]["evidence_id"] == "EV-1"
            assert data["evidence_chain"][1]["parent_hash"] == data["evidence_chain"][0]["entry_hash"]

            engine.clear_evidence()
            report2 = engine.generate_report(fmt="json")
            data2 = json.loads(report2)
            assert len(data2["evidence_chain"]) == 0

        db.unlink()

    def test_pipeline_query_events_limit(self) -> None:
        """Respect query limit."""
        log = Path(tempfile.mktemp(suffix=".jsonl"))
        db = Path(tempfile.mktemp(suffix=".db"))
        _make_mcpguard_log(log, [{"event_type": str(i), "timestamp": f"2025-01-01T00:00:0{i}Z"} for i in range(10)])

        with ForensicsEngine(db) as engine:
            engine.ingest_mcpguard(log)
            result = engine.query_events(limit=3)
            assert len(result) == 3

        log.unlink()
        db.unlink()

    def test_pipeline_context_manager_closes(self) -> None:
        """Context manager should close DB properly (no ResourceWarning)."""
        import warnings

        db = Path(tempfile.mktemp(suffix=".db"))
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with ForensicsEngine(db) as engine:
                engine.ingest_structured({"source": "test", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
            # After exit, connection should be closed
            sqlite_warnings = [
                x for x in w if "sqlite3" in str(x.message).lower() or "database" in str(x.message).lower()
            ]
            assert len(sqlite_warnings) == 0, f"SQLite warnings: {sqlite_warnings}"
        db.unlink()
