"""Tests for timeline module."""

from __future__ import annotations

from agentforensics.timeline.builder import TimelineBuilder
from agentforensics.timeline.correlator import correlate_events
from agentforensics.timeline.visualizer import (
    render_risk_timeline,
    render_severity_pie,
    render_timeline_chart,
)


class TestTimelineBuilder:
    def test_init(self) -> None:
        tb = TimelineBuilder()
        assert tb.count() == 0

    def test_insert(self) -> None:
        tb = TimelineBuilder()
        event = {"source": "test", "event_type": "read", "timestamp": "2025-01-01T00:00:00Z"}
        row_id = tb.insert(event)
        assert row_id is not None
        assert tb.count() == 1

    def test_insert_many(self) -> None:
        tb = TimelineBuilder()
        events = [
            {"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"},
            {"source": "b", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"},
        ]
        ids = tb.insert_many(events)
        assert len(ids) == 2

    def test_get_timeline(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:01Z"})
        tb.insert({"source": "b", "event_type": "y", "timestamp": "2025-01-01T00:00:00Z"})
        timeline = tb.get_timeline()
        assert len(timeline) == 2

    def test_query_by_source(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "mcpguard", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "agentgate", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"})
        results = tb.query(source="mcpguard")
        assert len(results) == 1
        assert results[0]["source"] == "mcpguard"

    def test_query_by_event_type(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "tool_call", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "b", "event_type": "policy_violation", "timestamp": "2025-01-01T00:00:01Z"})
        results = tb.query(event_type="tool_call")
        assert len(results) == 1

    def test_query_by_severity(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "x", "severity": "critical", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "a", "event_type": "x", "severity": "low", "timestamp": "2025-01-01T00:00:01Z"})
        results = tb.query(severity="critical")
        assert len(results) == 1

    def test_query_by_min_risk(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "x", "risk_score": 2.0, "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "a", "event_type": "x", "risk_score": 8.0, "timestamp": "2025-01-01T00:00:01Z"})
        results = tb.query(min_risk=5.0)
        assert len(results) == 1

    def test_sources_distinct(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "b", "event_type": "y", "timestamp": "2025-01-01T00:00:01Z"})
        tb.insert({"source": "a", "event_type": "z", "timestamp": "2025-01-01T00:00:02Z"})
        src = tb.sources()
        assert sorted(src) == ["a", "b"]

    def test_event_types_distinct(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "read", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "a", "event_type": "write", "timestamp": "2025-01-01T00:00:01Z"})
        types = tb.event_types()
        assert sorted(types) == ["read", "write"]

    def test_severity_counts(self) -> None:
        tb = TimelineBuilder()
        tb.insert({"source": "a", "event_type": "x", "severity": "high", "timestamp": "2025-01-01T00:00:00Z"})
        tb.insert({"source": "a", "event_type": "x", "severity": "high", "timestamp": "2025-01-01T00:00:01Z"})
        tb.insert({"source": "a", "event_type": "x", "severity": "low", "timestamp": "2025-01-01T00:00:02Z"})
        counts = tb.severity_counts()
        assert counts.get("high") == 2
        assert counts.get("low") == 1

    def test_close(self) -> None:
        tb = TimelineBuilder()
        tb.close()


class TestCorrelator:
    def test_empty_correlation(self) -> None:
        assert correlate_events([], 60) == []

    def test_single_event(self) -> None:
        events = [{"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"}]
        groups = correlate_events(events)
        assert len(groups) == 1
        assert groups[0]["event_count"] == 1

    def test_correlation_groups(self) -> None:
        events = [
            {"source": "a", "event_type": "x", "timestamp": "2025-01-01T00:00:00Z"},
            {"source": "b", "event_type": "y", "timestamp": "2025-01-01T00:00:30Z"},
            {"source": "a", "event_type": "z", "timestamp": "2025-01-01T01:00:00Z"},
        ]
        groups = correlate_events(events, window_seconds=60)
        assert len(groups) == 2
        assert groups[0]["event_count"] == 2
        assert groups[1]["event_count"] == 1

    def test_correlation_risk_score(self) -> None:
        events = [
            {"source": "a", "event_type": "x", "risk_score": 2.0, "timestamp": "2025-01-01T00:00:00Z"},
            {"source": "a", "event_type": "y", "risk_score": 8.0, "timestamp": "2025-01-01T00:00:05Z"},
        ]
        groups = correlate_events(events)
        assert groups[0]["max_risk"] == 8.0


class TestVisualizer:
    def test_render_empty(self) -> None:
        html = render_timeline_chart([])
        assert "No events" in html

    def test_render_with_events(self) -> None:
        html = render_timeline_chart([{"timestamp": "2025-01-01T00:00:00Z", "source": "test", "event_type": "test"}])
        assert isinstance(html, str)

    def test_severity_pie_empty(self) -> None:
        html = render_severity_pie([])
        assert "No events" in html

    def test_severity_pie_with_data(self) -> None:
        events = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "low"},
        ]
        html = render_severity_pie(events)
        assert isinstance(html, str)

    def test_risk_timeline_empty(self) -> None:
        html = render_risk_timeline([])
        assert "No events" in html

    def test_risk_timeline_with_data(self) -> None:
        events = [
            {"timestamp": "2025-01-01T00:00:00Z", "risk_score": 2.0, "event_type": "read", "title": "Read file"},
            {"timestamp": "2025-01-01T00:00:01Z", "risk_score": 8.0, "event_type": "exploit", "title": "Exploit"},
        ]
        html = render_risk_timeline(events)
        assert isinstance(html, str)
