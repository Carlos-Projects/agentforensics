"""Tests for the CLI."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from agentforensics.cli import app

runner = CliRunner()


class TestCli:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "AgentForensics" in result.stdout

    def test_ingest_no_sources(self) -> None:
        result = runner.invoke(app, ["ingest"])
        assert result.exit_code == 0
        assert "No events ingested" in result.stdout

    def test_ingest_with_mcpguard(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        result = runner.invoke(app, ["ingest", "--mcpguard", str(path)])
        assert result.exit_code == 0
        assert "MCPGuard" in result.stdout
        path.unlink()

    def test_timeline_no_db(self) -> None:
        result = runner.invoke(app, ["timeline", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0
        assert "Database not found" in result.stdout

    def test_analyze_no_db(self) -> None:
        result = runner.invoke(app, ["analyze", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0

    def test_report_no_db(self) -> None:
        result = runner.invoke(app, ["report", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0

    def test_serve_help(self) -> None:
        # Just check that serve command is registered
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0

    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "ingest" in result.stdout
        assert "timeline" in result.stdout
        assert "analyze" in result.stdout
        assert "report" in result.stdout
        assert "serve" in result.stdout
