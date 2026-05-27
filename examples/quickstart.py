"""Quickstart: run the full AgentForensics pipeline end-to-end."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentforensics.engine import ForensicsEngine


def main() -> None:
    db = tempfile.mktemp(suffix=".db")

    # Create sample MCPGuard-style log
    log = Path(tempfile.mktemp(suffix=".jsonl"))
    events = [
        {
            "source": "mcpguard",
            "event_type": "tool_call",
            "severity": "low",
            "title": "read_file",
            "description": "Agent read /etc/passwd",
            "target": "/etc/passwd",
            "blocked": False,
            "timestamp": "2025-01-15T10:00:00Z",
            "risk_score": 2.0,
        },
        {
            "source": "mcpguard",
            "event_type": "tool_call",
            "severity": "high",
            "title": "execute_command",
            "description": "Agent tried cat /etc/shadow",
            "target": "cat /etc/shadow",
            "blocked": True,
            "timestamp": "2025-01-15T10:00:05Z",
            "risk_score": 7.5,
        },
        {
            "source": "agentgate",
            "event_type": "policy_violation",
            "severity": "high",
            "title": "Sensitive File Access",
            "description": "Policy violation: no_sensitive_file_access",
            "target": "no_sensitive_file_access",
            "blocked": True,
            "timestamp": "2025-01-15T10:00:06Z",
            "risk_score": 8.5,
        },
        {
            "source": "mcpguard",
            "event_type": "tool_call",
            "severity": "critical",
            "title": "http_request",
            "description": "Agent tried external exfiltration",
            "target": "https://external.example.com/exfil",
            "blocked": True,
            "timestamp": "2025-01-15T10:00:10Z",
            "risk_score": 9.8,
        },
    ]
    log.write_text("\n".join(json.dumps(e) for e in events))

    engine = ForensicsEngine(db_path=db)

    # Ingest
    engine.ingest_mcpguard(log)
    engine.ingest_agentgate(log)
    print(f"Ingested {engine.event_count} events")

    # Timeline
    timeline = engine.build_timeline()
    print(f"Timeline: {len(timeline)} events")

    # Analysis
    anomalies = engine.analyze_anomalies()
    print(f"Anomalies: {len(anomalies)}")
    for a in anomalies:
        print(f"  [{a['severity']}] {a['type']}: {a['description']}")

    deviations = engine.analyze_deviations()
    print(f"Deviations: {len(deviations)}")

    # Report
    report = engine.generate_report(fmt="markdown", incident_id="INC-001")
    print(f"\nReport ({len(report)} chars):")
    print(report[:500] + "...")

    # Compliance
    compliance = engine.check_compliance()
    print(f"\nCompliance: {compliance['status']} ({compliance['passed']}/{compliance['total_checks']} passed)")

    # Evidence
    engine.add_evidence("ev-1", b"sensitive data snapshot")
    engine.add_evidence("ev-2", b"network capture")
    print(f"Evidence chain: {len(engine.build_timeline())} entries")

    engine.close()

    # Cleanup
    log.unlink()
    Path(db).unlink(missing_ok=True)

    print("\nDone! AgentForensics pipeline completed successfully.")


if __name__ == "__main__":
    main()
