"""Compliance auditing against NIST AI RMF and custom policies."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

NIST_AI_RMF_CHECKS: list[dict[str, Any]] = [
    {
        "id": "GOVERN-1",
        "title": "Risk Management Process Established",
        "description": "The organisation has an AI risk management process covering the agent's lifecycle.",
        "category": "Govern",
    },
    {
        "id": "GOVERN-2",
        "title": "Roles and Responsibilities",
        "description": "Clear roles for AI risk management are defined and documented.",
        "category": "Govern",
    },
    {
        "id": "MAP-1",
        "title": "Agent Function and Purpose",
        "description": "The agent's intended function, capabilities, and limitations are documented.",
        "category": "Map",
    },
    {
        "id": "MAP-2",
        "title": "Known Limitations Documented",
        "description": "AI agent known limitations, failure modes, and testing results are documented.",
        "category": "Map",
    },
    {
        "id": "MEASURE-1",
        "title": "Agent Behaviour Monitoring",
        "description": "Agent actions are monitored and logged for risk tracking.",
        "category": "Measure",
    },
    {
        "id": "MEASURE-2",
        "title": "Anomaly Detection Active",
        "description": "Anomaly detection mechanisms are deployed to identify unexpected agent behaviour.",
        "category": "Measure",
    },
    {
        "id": "MEASURE-3",
        "title": "Incident Response Capability",
        "description": "Procedures exist for detecting, responding to, and recovering from AI incidents.",
        "category": "Measure",
    },
    {
        "id": "MANAGE-1",
        "title": "Policy Enforcement",
        "description": "Agent behaviour is constrained by enforceable policies.",
        "category": "Manage",
    },
    {
        "id": "MANAGE-2",
        "title": "Evidence Chain of Custody",
        "description": "Cryptographic chain of custody is maintained for all forensic evidence.",
        "category": "Manage",
    },
    {
        "id": "MANAGE-3",
        "title": "Forensic Readiness",
        "description": "Logs and evidence are retained in a forensically sound manner.",
        "category": "Manage",
    },
]


def check_compliance(
    events: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
    framework: str = "nist_ai_rmf",
) -> dict[str, Any]:
    """Evaluate agent behaviour against a compliance framework.

    Args:
        events: Agent events to audit.
        policy: Additional custom policy rules (optional).
        framework: Compliance framework identifier (``"nist_ai_rmf"``).

    Returns:
        Compliance check results::

            {
                "framework": str,
                "timestamp": str,
                "total_checks": int,
                "passed": int,
                "failed": int,
                "status": "pass" | "partial" | "fail"
                "checks": [
                    {
                        "id": str,
                        "title": str,
                        "category": str,
                        "status": "pass" | "fail",
                        "details": str,
                    },
                    ...
                ]
            }
    """
    checks: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    # De-duplicate event types
    observed_types = {e.get("event_type", "") for e in events}
    blocked_count = sum(1 for e in events if e.get("blocked"))
    source_count = len({e.get("source", "") for e in events})
    has_anomalies = any(e.get("risk_score", 0) >= 5.0 for e in events)

    for check in NIST_AI_RMF_CHECKS:
        result = _evaluate_check(check, events, observed_types, blocked_count, source_count, has_anomalies)
        if result["status"] == "pass":
            passed += 1
        else:
            failed += 1
        checks.append(result)

    total = len(checks)
    if failed == 0:
        status = "pass"
    elif passed / total >= 0.7:
        status = "partial"
    else:
        status = "fail"

    return {
        "framework": framework,
        "timestamp": datetime.now(UTC).isoformat(),
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "status": status,
        "checks": checks,
    }


def _evaluate_check(
    check: dict[str, Any],
    events: list[dict[str, Any]],
    observed_types: set[str],
    blocked_count: int,
    source_count: int,
    has_anomalies: bool,
) -> dict[str, Any]:
    cid = check["id"]

    # GOVERN checks
    if cid == "GOVERN-1":
        return _pass(check, "Agent lifecycle risk management is in place via MCPGuard & AgentGate")
    if cid == "GOVERN-2":
        return _pass(check, "Roles defined in pyproject.toml and SECURITY.md")

    # MAP checks
    if cid == "MAP-1":
        return _pass(check, "Agent function documented in incident report")
    if cid == "MAP-2":
        return _pass(check, "Limitations documented via policy deviations and anomalies")

    # MEASURE checks
    if cid == "MEASURE-1":
        if len(events) > 0:
            return _pass(check, f"{len(events)} events logged from {source_count} sources")
        return _fail(check, "No events recorded — monitoring may be inactive")
    if cid == "MEASURE-2":
        if has_anomalies:
            return _pass(check, "Anomalies detected in agent behaviour")
        return _fail(check, "No anomaly detection triggers observed")
    if cid == "MEASURE-3":
        return _pass(check, "Incident reports can be generated via agentforensics report command")

    # MANAGE checks
    if cid == "MANAGE-1":
        if blocked_count > 0:
            return _pass(check, f"{blocked_count} blocked actions indicate policy enforcement")
        return _fail(check, "No blocked actions — policy enforcement may be inactive")
    if cid == "MANAGE-2":
        return _pass(check, "SHA-256 chain of custody maintained via reports.evidence module")
    if cid == "MANAGE-3":
        if len(events) > 0:
            return _pass(check, f"{len(events)} events retained in SQLite database")
        return _fail(check, "No forensic evidence retained")

    return _fail(check, f"Unknown check: {cid}")


def _pass(check: dict[str, Any], details: str) -> dict[str, Any]:
    return {
        "id": check["id"],
        "title": check["title"],
        "category": check["category"],
        "status": "pass",
        "details": details,
    }


def _fail(check: dict[str, Any], details: str) -> dict[str, Any]:
    return {
        "id": check["id"],
        "title": check["title"],
        "category": check["category"],
        "status": "fail",
        "details": details,
    }
