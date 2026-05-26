"""Tests for reports module."""

from __future__ import annotations

from agentforensics.reports.compliance import check_compliance
from agentforensics.reports.evidence import (
    clear_chain,
    compute_evidence_hash,
    create_chain_entry,
    get_chain,
    verify_chain,
)
from agentforensics.reports.generator import generate_report
from agentforensics.reports.incident import IncidentReport
from agentforensics.utils.crypto import hmac_sign, sha256, verify_hmac


class TestReportGenerator:
    def test_generate_markdown_empty(self) -> None:
        report = generate_report([], [], [], fmt="markdown")
        assert isinstance(report, str)
        assert "Forensics Report" in report

    def test_generate_html_empty(self) -> None:
        report = generate_report([], [], [], fmt="html")
        assert isinstance(report, str)
        assert "<html" in report

    def test_generate_json_empty(self) -> None:
        report = generate_report([], [], [], fmt="json")
        import json

        data = json.loads(report)
        assert data["event_count"] == 0

    def test_generate_markdown_with_data(self) -> None:
        timeline = [{"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "read", "severity": "low"}]
        report = generate_report(timeline, [], [], fmt="markdown", incident_id="INC-001")
        assert "INC-001" in report
        assert "read" in report

    def test_generate_html_with_data(self) -> None:
        timeline = [{"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "read", "severity": "high"}]
        report = generate_report(timeline, [], [], fmt="html")
        assert "<table" in report

    def test_generate_with_anomalies(self) -> None:
        timeline = [
            {"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "exploit", "severity": "critical"}
        ]
        anomalies = [{"type": "high_risk", "severity": "critical", "description": "High risk detected", "score": 9.0}]
        report = generate_report(timeline, anomalies, [], fmt="markdown")
        assert "High risk detected" in report

    def test_generate_with_deviations(self) -> None:
        timeline = [{"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "hack", "severity": "high"}]
        deviations = [{"type": "policy_violation", "description": "Violated policy"}]
        report = generate_report(timeline, [], deviations, fmt="markdown")
        assert "Violated policy" in report

    def test_generate_with_evidence(self) -> None:
        timeline = [{"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "test", "severity": "info"}]
        evidence = [
            {"evidence_id": "EV-001", "hash": "abc123", "collector": "test", "timestamp": "2025-01-01T00:00:00Z"}
        ]
        report = generate_report(timeline, [], [], evidence_chain=evidence, fmt="markdown")
        assert "EV-001" in report


class TestIncidentReport:
    def test_create_report(self) -> None:
        report = IncidentReport(incident_id="INC-001", title="Test Incident")
        assert report.incident_id == "INC-001"
        assert report.severity == "unknown"

    def test_report_with_data(self) -> None:
        report = IncidentReport(
            incident_id="INC-002",
            title="Critical Event",
            severity="high",
            anomalies_count=5,
            deviations_count=2,
            recommendations=["Revoke access", "Alert team"],
        )
        assert report.anomalies_count == 5
        assert len(report.recommendations) == 2


class TestCompliance:
    def test_check_compliance_empty(self) -> None:
        result = check_compliance([], framework="nist_ai_rmf")
        assert result["total_checks"] == 10
        assert "status" in result

    def test_check_compliance_returns_checks(self) -> None:
        result = check_compliance([])
        assert len(result["checks"]) == 10

    def test_check_compliance_with_events(self) -> None:
        events = [
            {"event_type": "exploit", "blocked": True, "risk_score": 9.0},
            {"event_type": "read", "blocked": False, "risk_score": 1.0},
        ]
        result = check_compliance(events)
        passed = result["passed"]
        assert passed >= 0
        assert result["passed"] + result["failed"] == result["total_checks"]


class TestEvidence:
    def setup_method(self) -> None:
        clear_chain()

    def test_compute_hash(self) -> None:
        h = compute_evidence_hash(b"test data")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_deterministic(self) -> None:
        h1 = compute_evidence_hash(b"same")
        h2 = compute_evidence_hash(b"same")
        assert h1 == h2

    def test_create_chain_entry(self) -> None:
        h = compute_evidence_hash(b"evidence")
        entry = create_chain_entry("EV-001", h, collector="test")
        assert entry["evidence_id"] == "EV-001"
        assert "entry_hash" in entry
        assert "parent_hash" in entry

    def test_chain_linking(self) -> None:
        clear_chain()
        h1 = compute_evidence_hash(b"first")
        h2 = compute_evidence_hash(b"second")
        e1 = create_chain_entry("EV-001", h1)
        e2 = create_chain_entry("EV-002", h2)
        assert e2["parent_hash"] == e1["entry_hash"]

    def test_verify_chain_valid(self) -> None:
        clear_chain()
        create_chain_entry("EV-001", compute_evidence_hash(b"a"))
        create_chain_entry("EV-002", compute_evidence_hash(b"b"))
        valid, errors = verify_chain()
        assert valid
        assert errors == []

    def test_get_chain(self) -> None:
        clear_chain()
        assert get_chain() == []
        create_chain_entry("EV-001", compute_evidence_hash(b"x"))
        assert len(get_chain()) == 1

    def test_clear_chain(self) -> None:
        clear_chain()
        create_chain_entry("EV-001", compute_evidence_hash(b"x"))
        clear_chain()
        assert get_chain() == []


class TestCrypto:
    def test_sha256(self) -> None:
        h = sha256(b"test")
        assert len(h) == 64

    def test_hmac_sign_and_verify(self) -> None:
        key = b"secret"
        data = b"evidence data"
        sig = hmac_sign(data, key)
        assert verify_hmac(data, key, sig)
        assert not verify_hmac(data, b"wrong-key", sig)
