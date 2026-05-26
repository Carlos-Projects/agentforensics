"""Tests for ingestion modules."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agentforensics.ingest.agentgate import parse_agentgate_signal
from agentforensics.ingest.generic import parse_generic_log
from agentforensics.ingest.mcpguard import parse_mcpguard_log
from agentforensics.ingest.parser import normalize_timestamp, safe_json_loads


class TestMcpguardIngest:
    def test_parse_single_event(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        events = list(parse_mcpguard_log(path))
        assert len(events) == 1
        assert events[0]["source"] == "mcpguard"
        assert "event_type" in events[0]
        path.unlink()

    def test_parse_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = Path(f.name)

        events = list(parse_mcpguard_log(path))
        assert events == []
        path.unlink()

    def test_parse_multiple_events(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"event_type": "a", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            f.write(json.dumps({"event_type": "b", "timestamp": "2025-01-01T00:00:01Z"}) + "\n")
            f.write("\n")
            f.write(json.dumps({"event_type": "c", "timestamp": "2025-01-01T00:00:02Z"}) + "\n")
            path = Path(f.name)

        events = list(parse_mcpguard_log(path))
        assert len(events) == 3
        path.unlink()

    def test_parse_skips_bad_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not valid json\n")
            f.write(json.dumps({"event_type": "b", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        events = list(parse_mcpguard_log(path))
        assert len(events) == 1
        path.unlink()

    def test_normalized_event_has_required_fields(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        ev = list(parse_mcpguard_log(path))[0]
        for key in ("source", "event_type", "severity", "title", "timestamp", "risk_score", "raw"):
            assert key in ev, f"Missing key: {key}"
        path.unlink()


class TestAgentgateIngest:
    def test_parse_single_signal(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"signal": "blocked", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        signals = list(parse_agentgate_signal(path))
        assert len(signals) == 1
        assert signals[0]["source"] == "agentgate"
        path.unlink()

    def test_parse_skips_bad_json(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("not json\n")
            path = Path(f.name)

        signals = list(parse_agentgate_signal(path))
        assert signals == []
        path.unlink()

    def test_agentgate_default_blocked(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"signal": "test", "timestamp": "2025-01-01T00:00:00Z"}) + "\n")
            path = Path(f.name)

        ev = list(parse_agentgate_signal(path))[0]
        assert ev["blocked"] is True
        path.unlink()


class TestGenericIngest:
    def test_parse_plain(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("log line 1\n")
            f.write("log line 2\n")
            path = Path(f.name)

        events = list(parse_generic_log(path))
        assert len(events) == 2
        assert events[0]["format"] == "plain"
        path.unlink()

    def test_parse_jsonl_auto(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"msg": "test"}) + "\n")
            path = Path(f.name)

        events = list(parse_generic_log(path))
        assert len(events) == 1
        assert events[0]["format"] == "jsonl"
        path.unlink()

    def test_parse_jsonl_explicit(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"timestamp": "2025-01-01T00:00:00Z", "msg": "test"}) + "\n")
            path = Path(f.name)

        events = list(parse_generic_log(path, fmt="jsonl"))
        assert len(events) == 1
        path.unlink()

    def test_parse_syslog(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("Jan 15 10:00:00 myhost myapp[123]: test message\n")
            path = Path(f.name)

        events = list(parse_generic_log(path, fmt="syslog"))
        assert len(events) == 1
        assert events[0]["format"] == "syslog"
        path.unlink()

    def test_parse_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = Path(f.name)

        events = list(parse_generic_log(path))
        assert events == []
        path.unlink()


class TestParser:
    def test_normalize_timestamp_iso(self) -> None:
        ts = normalize_timestamp("2025-01-01T00:00:00Z")
        assert ts.year == 2025

    def test_normalize_timestamp_epoch(self) -> None:
        ts = normalize_timestamp(1704067200.0)
        assert ts.year == 2024

    def test_normalize_timestamp_none(self) -> None:
        ts = normalize_timestamp(None)
        assert ts.year >= 2025

    def test_safe_json_loads_valid(self) -> None:
        result = safe_json_loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_safe_json_loads_invalid(self) -> None:
        result = safe_json_loads("not json")
        assert result == {}

    def test_safe_json_loads_empty(self) -> None:
        result = safe_json_loads("")
        assert result == {}
