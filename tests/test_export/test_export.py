"""Tests for the export module (MCPGuard policy, MCPscop adapter)."""

from __future__ import annotations

from pathlib import Path

import httpx

from agentforensics.export.mcpguard_policy import generate_mcpguard_policy, save_mcpguard_policy
from agentforensics.export.mcpscop import export_compliance_to_mcpscop, export_events_to_mcpscop


class TestMCPGuardPolicy:
    def test_generate_policy_defaults(self) -> None:
        compliance = {
            "status": "pass",
            "passed": 10,
            "failed": 0,
            "framework": "nist_ai_rmf",
            "timestamp": "2026-01-01T00:00:00Z",
            "checks": [],
        }
        policy = generate_mcpguard_policy(compliance)
        assert "MCPGuard Policy" in policy
        assert "nist_ai_rmf" in policy
        assert "allow:" in policy
        assert "deny:" in policy
        assert "rate_limit: 100" in policy

    def test_generate_policy_with_failures(self) -> None:
        compliance = {
            "status": "partial",
            "passed": 4,
            "failed": 6,
            "framework": "nist_ai_rmf",
            "timestamp": "2026-01-01T00:00:00Z",
            "checks": [{"id": "MEASURE-2", "details": "Anomaly detected"}],
        }
        policy = generate_mcpguard_policy(compliance)
        assert "exec" in policy
        assert "shell" in policy
        assert "rate_limit: 20" in policy

    def test_generate_policy_with_blocked_tools(self) -> None:
        compliance = {
            "status": "pass",
            "passed": 10,
            "failed": 0,
            "framework": "nist_ai_rmf",
            "timestamp": "2026-01-01T00:00:00Z",
            "checks": [
                {
                    "id": "MANAGE-1",
                    "status": "pass",
                    "details": "2 blocked actions indicate policy enforcement: http_request, execute_command",
                },
            ],
        }
        policy = generate_mcpguard_policy(compliance)
        assert "http_request" in policy
        assert "execute_command" in policy

    def test_save_policy(self, tmp_path: Path) -> None:
        compliance = {
            "status": "pass",
            "passed": 10,
            "failed": 0,
            "framework": "nist_ai_rmf",
            "timestamp": "2026-01-01T00:00:00Z",
            "checks": [],
        }
        out = tmp_path / "policy.yaml"
        result = save_mcpguard_policy(compliance, out)
        assert result == out
        assert out.exists()
        assert "MCPGuard Policy" in out.read_text()

    def test_custom_url_and_rate(self) -> None:
        compliance = {
            "status": "pass",
            "passed": 10,
            "failed": 0,
            "framework": "nist_ai_rmf",
            "timestamp": "2026-01-01T00:00:00Z",
            "checks": [],
        }
        policy = generate_mcpguard_policy(compliance, target_url="https://my-server.com", rate_limit=50)
        assert "my-server.com" in policy
        assert "rate_limit: 50" in policy


class TestMCPscopExport:
    def test_export_events_success(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="http://localhost:9000/api/events", method="POST", status_code=201, is_reusable=True
        )
        events = [
            {
                "event_type": "tool_call",
                "severity": "high",
                "title": "Test event",
                "source": "mcpguard",
                "blocked": True,
                "risk_score": 7.5,
            },
            {
                "event_type": "anomaly",
                "severity": "critical",
                "title": "Critical",
                "source": "mcpguard",
                "blocked": True,
                "risk_score": 9.5,
            },
        ]
        result = export_events_to_mcpscop(events)
        assert result["sent"] == 2
        assert result["failed"] == 0
        assert result["total"] == 2

    def test_export_events_partial_failure(self, httpx_mock) -> None:
        httpx_mock.add_response(url="http://localhost:9000/api/events", method="POST", status_code=201)
        httpx_mock.add_response(url="http://localhost:9000/api/events", method="POST", status_code=500)
        events = [
            {
                "event_type": "tool_call",
                "severity": "low",
                "title": "OK",
                "source": "mcpguard",
                "blocked": False,
                "risk_score": 1.0,
            },
            {
                "event_type": "anomaly",
                "severity": "high",
                "title": "Fail",
                "source": "mcpguard",
                "blocked": True,
                "risk_score": 8.0,
            },
        ]
        result = export_events_to_mcpscop(events)
        assert result["sent"] == 1
        assert result["failed"] == 1
        assert result["total"] == 2

    def test_export_events_network_error(self, httpx_mock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        events = [
            {
                "event_type": "tool_call",
                "severity": "info",
                "title": "Fail",
                "source": "test",
                "blocked": False,
                "risk_score": 0.0,
            }
        ]
        result = export_events_to_mcpscop(events)
        assert result["sent"] == 0
        assert result["failed"] == 1

    def test_export_compliance_success(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="http://localhost:9000/api/taxonomy/normalize",
            method="POST",
            status_code=200,
            json={"source": "agentforensics", "severity": "medium", "attack_category": "policy_violation"},
        )
        compliance = {"framework": "nist_ai_rmf", "status": "pass", "passed": 10, "total_checks": 10, "checks": []}
        result = export_compliance_to_mcpscop(compliance)
        assert result["source"] == "agentforensics"
        assert result["severity"] == "medium"

    def test_export_compliance_server_error(self, httpx_mock) -> None:
        httpx_mock.add_response(
            url="http://localhost:9000/api/taxonomy/normalize", method="POST", status_code=500, text="Internal error"
        )
        compliance = {"framework": "nist_ai_rmf", "status": "pass", "passed": 10, "total_checks": 10, "checks": []}
        result = export_compliance_to_mcpscop(compliance)
        assert "error" in result
        assert "500" in result["error"]

    def test_export_compliance_network_error(self, httpx_mock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        compliance = {"framework": "nist_ai_rmf", "status": "fail", "passed": 2, "total_checks": 10, "checks": []}
        result = export_compliance_to_mcpscop(compliance)
        assert "error" in result

    def test_export_with_api_key(self, httpx_mock) -> None:
        httpx_mock.add_response(url="http://localhost:9000/api/events", method="POST", status_code=201)
        events = [
            {
                "event_type": "test",
                "severity": "info",
                "title": "test",
                "source": "test",
                "blocked": False,
                "risk_score": 0.0,
            }
        ]
        result = export_events_to_mcpscop(events, api_key="secret-123")
        assert result["sent"] == 1
