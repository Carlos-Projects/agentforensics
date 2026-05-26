"""Tests for the forensics engine."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentforensics.engine import ForensicsEngine


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


class TestForensicsEngine:
    """Tests for ForensicsEngine."""

    def test_init(self) -> None:
        engine = ForensicsEngine()
        assert engine.event_count == 0

    def test_ingest_mcpguard(self) -> None:
        engine = ForensicsEngine()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(
                json.dumps({"event_type": "tool_call", "severity": "low", "timestamp": "2025-01-01T00:00:00Z"}) + "\n"
            )
            f.write(
                json.dumps({"event_type": "tool_result", "severity": "info", "timestamp": "2025-01-01T00:00:01Z"})
                + "\n"
            )
            path = Path(f.name)

        count = engine.ingest_mcpguard(path)
        assert count == 2
        assert engine.event_count == 2
        path.unlink()

    def test_ingest_agentgate(self) -> None:
        engine = ForensicsEngine()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"signal": "blocked", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        count = engine.ingest_agentgate(path)
        assert count == 1
        assert engine.event_count == 1
        path.unlink()

    def test_ingest_generic(self) -> None:
        engine = ForensicsEngine()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("some log line\n")
            path = Path(f.name)

        count = engine.ingest_generic(path)
        assert count == 1
        assert engine.event_count == 1
        path.unlink()

    def test_ingest_generic_jsonl(self) -> None:
        engine = ForensicsEngine()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"timestamp": "2025-01-01T00:00:00Z", "msg": "test"}) + "\n")
            f.write(json.dumps({"timestamp": "2025-01-01T00:00:01Z", "msg": "test2"}) + "\n")
            path = Path(f.name)

        count = engine.ingest_generic(path, fmt="jsonl")
        assert count == 2
        path.unlink()

    def test_ingest_structured(self) -> None:
        engine = ForensicsEngine()
        event = {"source": "test", "event_type": "test", "timestamp": "2025-01-01T00:00:00Z"}
        engine.ingest_structured(event)
        assert engine.event_count == 1

    def test_build_timeline_empty(self) -> None:
        engine = ForensicsEngine()
        timeline = engine.build_timeline()
        assert timeline == []

    def test_build_timeline_returns_events(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "a", "event_type": "t1", "timestamp": "2025-01-01T00:00:01Z"})
        engine.ingest_structured({"source": "b", "event_type": "t2", "timestamp": "2025-01-01T00:00:00Z"})
        timeline = engine.build_timeline()
        assert len(timeline) == 2

    def test_get_sources(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "mcpguard", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
        engine.ingest_structured({"source": "agentgate", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"})
        sources = engine.get_sources()
        assert "mcpguard" in sources
        assert "agentgate" in sources

    def test_get_event_types(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "x", "event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"})
        engine.ingest_structured({"source": "x", "event_type": "policy_violation", "timestamp": "2025-01-01T00:00:01Z"})
        types = engine.get_event_types()
        assert "tool_call" in types
        assert "policy_violation" in types

    def test_get_severity_counts(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {"source": "x", "event_type": "x", "severity": "high", "timestamp": "2025-01-01T00:00:00Z"}
        )
        engine.ingest_structured(
            {"source": "x", "event_type": "x", "severity": "high", "timestamp": "2025-01-01T00:00:01Z"}
        )
        engine.ingest_structured(
            {"source": "x", "event_type": "x", "severity": "low", "timestamp": "2025-01-01T00:00:02Z"}
        )
        counts = engine.get_severity_counts()
        assert counts.get("high") == 2
        assert counts.get("low") == 1

    def test_query_events_filter_by_source(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "mcpguard", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
        engine.ingest_structured({"source": "agentgate", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"})
        results = engine.query_events(source="mcpguard")
        assert len(results) == 1
        assert results[0]["source"] == "mcpguard"

    def test_query_events_limit(self) -> None:
        engine = ForensicsEngine()
        for i in range(5):
            engine.ingest_structured({"source": "a", "event_type": "x", "timestamp": f"2025-01-01T00:00:0{i}Z"})
        results = engine.query_events(limit=2)
        assert len(results) == 2

    def test_query_events_min_risk(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {"source": "a", "event_type": "x", "risk_score": 3.0, "timestamp": "2025-01-01T00:00:00Z"}
        )
        engine.ingest_structured(
            {"source": "a", "event_type": "x", "risk_score": 7.0, "timestamp": "2025-01-01T00:00:01Z"}
        )
        results = engine.query_events(min_risk=5.0)
        assert len(results) == 1
        assert results[0]["risk_score"] == 7.0

    def test_analyze_anomalies_with_blocked_chain(self) -> None:
        engine = ForensicsEngine()
        for i in range(4):
            engine.ingest_structured(
                {
                    "source": "test",
                    "event_type": "exploit",
                    "severity": "high",
                    "blocked": True,
                    "risk_score": 5.0,
                    "timestamp": f"2025-01-01T00:00:0{i}Z",
                }
            )
        anomalies = engine.analyze_anomalies()
        assert any(a["type"] == "blocked_chain" for a in anomalies)

    def test_analyze_deviations_with_policy_and_events(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {
                "source": "test",
                "event_type": "http_request",
                "severity": "high",
                "target": "evil.com",
                "risk_score": 9.0,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        )
        deviations = engine.analyze_deviations(policy={"blocked_tools": ["http_request"], "max_risk_score": 5.0})
        assert len(deviations) >= 2  # blocked tool + high risk
        assert deviations[0]["type"] == "policy_violation"

    def test_generate_report_with_evidence(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "test", "event_type": "test", "timestamp": "2025-01-01T00:00:00Z"})
        engine.add_evidence("EV-X", b"test data")
        report = engine.generate_report(fmt="markdown", incident_id="INC-EV")
        assert "INC-EV" in report

    def test_check_compliance_returns_checks(self) -> None:
        engine = ForensicsEngine()
        result = engine.check_compliance()
        assert len(result["checks"]) == 10
        assert "framework" in result
        assert result["framework"] == "nist_ai_rmf"
        engine = ForensicsEngine()
        engine.ingest_structured(
            {"source": "x", "event_type": "x", "severity": "critical", "timestamp": "2025-01-01T00:00:00Z"}
        )
        engine.ingest_structured(
            {"source": "x", "event_type": "x", "severity": "low", "timestamp": "2025-01-01T00:00:01Z"}
        )
        results = engine.query_events(severity="critical")
        assert len(results) == 1

    def test_analyze_anomalies_empty(self) -> None:
        engine = ForensicsEngine()
        assert engine.analyze_anomalies() == []

    def test_analyze_anomalies_with_high_risk(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {
                "source": "test",
                "event_type": "exploit",
                "severity": "critical",
                "risk_score": 9.5,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        )
        anomalies = engine.analyze_anomalies()
        assert len(anomalies) >= 1
        assert anomalies[0]["type"] == "high_risk"

    def test_analyze_deviations_empty(self) -> None:
        engine = ForensicsEngine()
        assert engine.analyze_deviations() == []

    def test_analyze_deviations_with_policy(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {
                "source": "test",
                "event_type": "http_request",
                "severity": "high",
                "risk_score": 8.0,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        )
        deviations = engine.analyze_deviations(policy={"blocked_tools": ["http_request"], "max_risk_score": 5.0})
        assert len(deviations) >= 1

    def test_generate_report(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "test", "event_type": "test", "timestamp": "2025-01-01T00:00:00Z"})
        report = engine.generate_report(fmt="markdown")
        assert isinstance(report, str)

    def test_generate_report_json(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "test", "event_type": "test", "timestamp": "2025-01-01T00:00:00Z"})
        report = engine.generate_report(fmt="json")
        data = json.loads(report)
        assert data["event_count"] == 1

    def test_generate_report_empty(self) -> None:
        engine = ForensicsEngine()
        report = engine.generate_report(fmt="markdown")
        assert "No events recorded" in report

    def test_check_compliance_empty(self) -> None:
        engine = ForensicsEngine()
        result = engine.check_compliance()
        assert result["status"] in ("pass", "partial", "fail")
        assert result["total_checks"] > 0

    def test_check_compliance_with_events(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured(
            {
                "source": "mcpguard",
                "event_type": "exploit",
                "risk_score": 9.0,
                "blocked": True,
                "timestamp": "2025-01-01T00:00:00Z",
            }
        )
        result = engine.check_compliance()
        assert result["total_checks"] == 10

    def test_add_evidence(self) -> None:
        engine = ForensicsEngine()
        entry = engine.add_evidence("EV-001", b"test data")
        assert entry["evidence_id"] == "EV-001"
        assert len(entry["entry_hash"]) == 64

    def test_clear_evidence(self) -> None:
        engine = ForensicsEngine()
        engine.add_evidence("EV-001", b"data")
        engine.clear_evidence()

    def test_event_count_across_sources(self) -> None:
        engine = ForensicsEngine()
        engine.ingest_structured({"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
        engine.ingest_structured({"source": "b", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"})
        assert engine.event_count == 2

    def test_close(self) -> None:
        engine = ForensicsEngine()
        engine.close()
