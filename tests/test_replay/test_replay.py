"""Tests for replay module."""

from __future__ import annotations

from agentforensics.replay.anomaly import detect_anomalies
from agentforensics.replay.diff import diff_behavior
from agentforensics.replay.player import replay_events


class TestPlayer:
    def test_replay_empty(self) -> None:
        result = list(replay_events([]))
        assert result == []

    def test_replay_preserves_order(self) -> None:
        events = [
            {"id": 1, "timestamp": "2025-01-01T00:00:01Z"},
            {"id": 2, "timestamp": "2025-01-01T00:00:02Z"},
            {"id": 3, "timestamp": "2025-01-01T00:00:03Z"},
        ]
        result = list(replay_events(events))
        assert [r["id"] for r in result] == [1, 2, 3]

    def test_replay_sorts_by_timestamp(self) -> None:
        events = [
            {"id": 3, "timestamp": "2025-01-01T00:00:03Z"},
            {"id": 1, "timestamp": "2025-01-01T00:00:01Z"},
            {"id": 2, "timestamp": "2025-01-01T00:00:02Z"},
        ]
        result = list(replay_events(events))
        assert [r["id"] for r in result] == [1, 2, 3]

    def test_replay_adds_delay_field(self) -> None:
        events = [{"id": 1, "timestamp": "2025-01-01T00:00:01Z"}, {"id": 2, "timestamp": "2025-01-01T00:00:02Z"}]
        result = list(replay_events(events, speed=0))
        assert "_replay_delay" in result[1]

    def test_replay_invokes_callback(self) -> None:
        events = [{"id": 1, "timestamp": "2025-01-01T00:00:01Z"}]
        called = []

        def cb(ev):
            called.append(ev)

        list(replay_events(events, on_event=cb))
        assert len(called) == 1


class TestDiff:
    def test_empty_diff(self) -> None:
        assert diff_behavior([], []) == []

    def test_identical_behavior(self) -> None:
        behavior = [{"event_type": "read"}, {"event_type": "write"}]
        assert diff_behavior(behavior, behavior) == []

    def test_extra_action(self) -> None:
        actual = [{"event_type": "read"}, {"event_type": "write"}, {"event_type": "delete"}]
        expected = [{"event_type": "read"}, {"event_type": "write"}]
        deviations = diff_behavior(actual, expected)
        assert any(d["type"] == "extra_action" for d in deviations)

    def test_missing_action(self) -> None:
        actual = [{"event_type": "read"}]
        expected = [{"event_type": "read"}, {"event_type": "write"}]
        deviations = diff_behavior(actual, expected)
        assert any(d["type"] == "missing_action" for d in deviations)

    def test_policy_violation_blocked_tool(self) -> None:
        actual = [{"event_type": "http_request", "target": "example.com"}]
        policy = {"blocked_tools": ["http_request"]}
        deviations = diff_behavior(actual, policy=policy)
        assert any(d["type"] == "policy_violation" for d in deviations)

    def test_policy_violation_blocked_path(self) -> None:
        actual = [{"event_type": "read", "target": "/etc/shadow"}]
        policy = {"blocked_paths": ["/etc/shadow"]}
        deviations = diff_behavior(actual, policy=policy)
        assert any(d["type"] == "policy_violation" for d in deviations)

    def test_policy_violation_high_risk(self) -> None:
        actual = [{"event_type": "exploit", "risk_score": 9.0}]
        policy = {"max_risk_score": 5.0}
        deviations = diff_behavior(actual, policy=policy)
        assert any(d["type"] == "policy_violation" for d in deviations)

    def test_no_policy_no_expected(self) -> None:
        actual = [{"event_type": "read"}]
        assert diff_behavior(actual) == []


class TestAnomaly:
    def test_empty_anomaly(self) -> None:
        assert detect_anomalies([]) == []

    def test_no_anomalies(self) -> None:
        events = [
            {"event_type": "read", "risk_score": 1.0, "timestamp": "2025-01-01T00:00:00Z"},
            {"event_type": "write", "risk_score": 2.0, "timestamp": "2025-01-01T00:00:01Z"},
        ]
        assert detect_anomalies(events) == []

    def test_high_risk_anomaly(self) -> None:
        events = [{"event_type": "exploit", "risk_score": 9.5, "timestamp": "2025-01-01T00:00:00Z"}]
        anomalies = detect_anomalies(events)
        assert any(a["type"] == "high_risk" for a in anomalies)

    def test_rare_event_type(self) -> None:
        events = [{"event_type": "weird_exploit", "risk_score": 1.0, "timestamp": "2025-01-01T00:00:00Z"}]
        anomalies = detect_anomalies(events, rare_event_types=["weird_exploit"])
        assert any(a["type"] == "rare_event_type" for a in anomalies)

    def test_blocked_chain(self) -> None:
        events = [
            {"event_type": "a", "blocked": True, "timestamp": "2025-01-01T00:00:00Z"},
            {"event_type": "a", "blocked": True, "timestamp": "2025-01-01T00:00:01Z"},
            {"event_type": "a", "blocked": True, "timestamp": "2025-01-01T00:00:02Z"},
            {"event_type": "a", "blocked": True, "timestamp": "2025-01-01T00:00:03Z"},
        ]
        anomalies = detect_anomalies(events)
        assert any(a["type"] == "blocked_chain" for a in anomalies)
