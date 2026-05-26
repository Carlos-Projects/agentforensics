"""Tests for the CLI."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from agentforensics.cli import app

runner = CliRunner()


def _make_log(events: list[dict]) -> Path:
    p = Path(tempfile.mktemp(suffix=".jsonl"))
    with open(p, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return p


def _make_agentgate_log(events: list[dict]) -> Path:
    p = Path(tempfile.mktemp(suffix=".log"))
    with open(p, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return p


class TestCli:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "AgentForensics" in result.stdout

    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "ingest" in result.stdout
        assert "timeline" in result.stdout
        assert "analyze" in result.stdout
        assert "report" in result.stdout
        assert "serve" in result.stdout

    def test_serve_help(self) -> None:
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0

    def test_ingest_no_sources(self) -> None:
        result = runner.invoke(app, ["ingest"])
        assert result.exit_code == 0
        assert "No events ingested" in result.stdout

    def test_ingest_mcpguard_only(self) -> None:
        p = _make_log([{"event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"}])
        result = runner.invoke(app, ["ingest", "--mcpguard", str(p)])
        assert result.exit_code == 0
        assert "MCPGuard" in result.stdout
        p.unlink()

    def test_ingest_agentgate_only(self) -> None:
        p = _make_agentgate_log([{"signal_type": "policy_violation", "weight": 80}])
        result = runner.invoke(app, ["ingest", "--agentgate", str(p)])
        assert result.exit_code == 0
        assert "AgentGate" in result.stdout
        p.unlink()

    def test_ingest_generic_only(self) -> None:
        p = _make_log([{"timestamp": "2025-01-01T00:00:00Z", "msg": "test"}])
        result = runner.invoke(app, ["ingest", "--generic", str(p)])
        assert result.exit_code == 0
        assert "generic" in result.stdout
        p.unlink()

    def test_ingest_all_sources(self) -> None:
        mcp = _make_log([{"event_type": "a", "timestamp": "2025-01-01T00:00:00Z"}])
        ag = _make_agentgate_log([{"signal_type": "b", "weight": 50}])
        gen = _make_log([{"msg": "c"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        result = runner.invoke(
            app,
            [
                "ingest",
                "--mcpguard",
                str(mcp),
                "--agentgate",
                str(ag),
                "--generic",
                str(gen),
                "--output",
                str(db),
            ],
        )
        assert result.exit_code == 0
        assert "3 events" in result.stdout or "Total events stored: 3" in result.stdout
        for p in (mcp, ag, gen, db):
            p.unlink()

    # --- timeline ---

    def test_timeline_no_db(self) -> None:
        result = runner.invoke(app, ["timeline", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0
        assert "Database not found" in result.stdout

    def test_timeline_with_data(self) -> None:
        mcp = _make_log([{"event_type": "a", "severity": "low", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["timeline", "--input", str(db)])
        assert result.exit_code == 0
        assert "a" in result.stdout or "Timeline" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_timeline_json_output(self) -> None:
        mcp = _make_log([{"event_type": "x", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["timeline", "--input", str(db), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) >= 1
        for p in (mcp, db):
            p.unlink()

    def test_timeline_with_source_filter(self) -> None:
        mcp = _make_log([{"event_type": "a", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["timeline", "--input", str(db), "--source", "mcpguard"])
        assert result.exit_code == 0
        for p in (mcp, db):
            p.unlink()

    def test_timeline_empty_db(self) -> None:
        db = Path(tempfile.mktemp(suffix=".db"))
        # Ingest empty file
        mcp = _make_log([])
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["timeline", "--input", str(db)])
        assert "No events found" in result.stdout
        for p in (mcp, db):
            p.unlink()

    # --- analyze ---

    def test_analyze_no_db(self) -> None:
        result = runner.invoke(app, ["analyze", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0

    def test_analyze_with_data(self) -> None:
        mcp = _make_log(
            [{"event_type": "exploit", "severity": "critical", "risk_score": 9.5, "timestamp": "2025-01-01T00:00:00Z"}]
        )
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["analyze", "--input", str(db)])
        assert result.exit_code == 0
        assert "Anomaly" in result.stdout or "Compliance" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_analyze_json(self) -> None:
        mcp = _make_log([{"event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["analyze", "--input", str(db), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "event_count" in data
        for p in (mcp, db):
            p.unlink()

    def test_analyze_empty_db(self) -> None:
        db = Path(tempfile.mktemp(suffix=".db"))
        mcp = _make_log([])
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["analyze", "--input", str(db)])
        assert "No events to analyze" in result.stdout
        for p in (mcp, db):
            p.unlink()

    # --- report ---

    def test_report_no_db(self) -> None:
        result = runner.invoke(app, ["report", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0

    def test_report_markdown(self) -> None:
        mcp = _make_log([{"event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["report", "--input", str(db), "--incident", "INC-TEST"])
        assert result.exit_code == 0
        assert "INC-TEST" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_report_html(self) -> None:
        mcp = _make_log([{"event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["report", "--input", str(db), "--format", "html"])
        assert result.exit_code == 0
        assert "<html" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_report_json(self) -> None:
        mcp = _make_log([{"event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        out = Path(tempfile.mktemp(suffix=".json"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["report", "--input", str(db), "--format", "json", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        with open(out) as f:
            data = json.load(f)
        assert data["event_count"] >= 1
        for p in (mcp, db, out):
            p.unlink()

    def test_report_to_file(self) -> None:
        mcp = _make_log([{"event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}])
        db = Path(tempfile.mktemp(suffix=".db"))
        out = Path(tempfile.mktemp(suffix=".md"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["report", "--input", str(db), "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "Agent" in content or "Forensics" in content
        for p in (mcp, db, out):
            p.unlink()

    # --- replay ---

    def test_replay_no_db(self) -> None:
        result = runner.invoke(app, ["replay", "--input", "/tmp/nonexistent.db"])
        assert result.exit_code != 0

    def test_replay_empty_db(self) -> None:
        db = Path(tempfile.mktemp(suffix=".db"))
        mcp = _make_log([])
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["replay", "--input", str(db)])
        assert "No events to replay" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_replay_with_events(self) -> None:
        mcp = _make_log(
            [
                {"event_type": "a", "timestamp": "2025-01-01T00:00:00Z"},
                {"event_type": "b", "timestamp": "2025-01-01T00:00:01Z"},
            ]
        )
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["replay", "--input", str(db), "--speed", "0"])
        assert result.exit_code == 0
        assert "Replaying" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_replay_with_limit(self) -> None:
        mcp = _make_log([{"event_type": f"e{i}", "timestamp": f"2025-01-01T00:00:0{i}Z"} for i in range(5)])
        db = Path(tempfile.mktemp(suffix=".db"))
        runner.invoke(app, ["ingest", "--mcpguard", str(mcp), "--output", str(db)])
        result = runner.invoke(app, ["replay", "--input", str(db), "--speed", "0", "--limit", "2"])
        assert result.exit_code == 0
        assert "Replaying 2" in result.stdout
        for p in (mcp, db):
            p.unlink()

    def test_help_includes_replay(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert "replay" in result.stdout
