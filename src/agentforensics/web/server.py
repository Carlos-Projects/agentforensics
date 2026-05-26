"""FastAPI web server for AgentForensics dashboard with HTMX."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agentforensics.engine import ForensicsEngine
from agentforensics.reports.generator import generate_report

app = FastAPI(title="AgentForensics", version="0.1.0")

_engine = ForensicsEngine(db_path=":memory:")

_templates_dir = Path(__file__).parent / "templates"
_static_dir = Path(__file__).parent / "static"
templates = Jinja2Templates(directory=str(_templates_dir))
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


_SAMPLE_EVENTS: list[dict[str, Any]] = [
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
        "description": "Policy violation",
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
    {
        "source": "mcpguard",
        "event_type": "tool_call",
        "severity": "low",
        "title": "read_file",
        "description": "Agent read /var/log/app.log",
        "target": "/var/log/app.log",
        "blocked": False,
        "timestamp": "2025-01-15T10:00:03Z",
        "risk_score": 1.0,
    },
    {
        "source": "mcpguard",
        "event_type": "tool_call",
        "severity": "high",
        "title": "write_file",
        "description": "Agent wrote to unexpected path",
        "target": "/tmp/exploit.sh",
        "blocked": True,
        "timestamp": "2025-01-15T10:00:08Z",
        "risk_score": 8.0,
    },
    {
        "source": "agentgate",
        "event_type": "policy_violation",
        "severity": "medium",
        "title": "High Request Rate",
        "description": "Agent exceeded rate limit",
        "target": "rate_limit",
        "blocked": True,
        "timestamp": "2025-01-15T10:00:12Z",
        "risk_score": 6.0,
    },
]


def _load_sample_data() -> None:
    """Load sample forensic events into the in-memory engine."""
    for ev in _SAMPLE_EVENTS:
        ev["raw"] = {}
        _engine.ingest_structured(dict(ev))


_load_sample_data()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Render the main dashboard."""
    events = _engine.build_timeline()
    event_count = len(events)
    sources = _engine.get_sources()
    types = _engine.get_event_types()
    blocked = sum(1 for e in events if e.get("blocked"))
    recent = events[-20:] if events else []

    severity_html = ""
    timeline_html = ""
    if events:
        from agentforensics.timeline.visualizer import render_severity_pie, render_timeline_chart

        severity_html = render_severity_pie(events)
        timeline_html = render_timeline_chart(events, "Event Timeline")

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "title": "Dashboard",
            "event_count": event_count,
            "source_count": len(sources),
            "type_count": len(types),
            "blocked_count": blocked,
            "recent_events": recent,
            "severity_chart": severity_html,
            "timeline_chart": timeline_html,
        },
    )


@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request) -> HTMLResponse:
    """Render the forensic timeline view."""
    events = _engine.build_timeline()
    from agentforensics.timeline.correlator import correlate_events

    groups = correlate_events(events)

    timeline_html = ""
    risk_html = ""
    if events:
        from agentforensics.timeline.visualizer import render_risk_timeline, render_timeline_chart

        timeline_html = render_timeline_chart(events, "Forensic Timeline")
        risk_html = render_risk_timeline(events)

    return templates.TemplateResponse(
        request,
        "timeline.html",
        {
            "title": "Timeline",
            "event_count": len(events),
            "group_count": len(groups),
            "events": events,
            "timeline_chart": timeline_html,
            "risk_chart": risk_html,
        },
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(
    request: Request,
    format: str = Query("html"),
    download: bool = Query(False),
) -> HTMLResponse:
    """Render the reports and compliance view."""
    events = _engine.build_timeline()
    from agentforensics.replay.anomaly import detect_anomalies
    from agentforensics.replay.diff import diff_behavior

    anomalies = detect_anomalies(events)
    deviations = diff_behavior(events, policy={"blocked_tools": [], "blocked_paths": [], "max_risk_score": 10.0})

    compliance = _engine.check_compliance()

    report_body = generate_report(
        timeline=events,
        anomalies=anomalies,
        deviations=deviations,
        fmt=format,
        incident_id="INC-2025-001",
    )

    if download:
        from fastapi.responses import HTMLResponse as HTMLResp

        return HTMLResp(content=report_body)

    return templates.TemplateResponse(
        request,
        "reports.html",
        {
            "title": "Reports",
            "event_count": len(events),
            "compliance": compliance,
            "report_body": report_body,
        },
    )


@app.post("/ingest/sample", response_class=HTMLResponse)
async def ingest_sample(request: Request) -> HTMLResponse:
    """Reload sample data and return updated dashboard."""
    events = _engine.build_timeline()
    recent = events[-20:] if events else []
    sources = _engine.get_sources()
    types = _engine.get_event_types()
    blocked = sum(1 for e in events if e.get("blocked"))

    severity_html = ""
    timeline_html = ""
    if events:
        from agentforensics.timeline.visualizer import render_severity_pie, render_timeline_chart

        severity_html = render_severity_pie(events)
        timeline_html = render_timeline_chart(events, "Event Timeline")

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "title": "Dashboard",
            "event_count": len(events),
            "source_count": len(sources),
            "type_count": len(types),
            "blocked_count": blocked,
            "recent_events": recent,
            "severity_chart": severity_html,
            "timeline_chart": timeline_html,
        },
    )


@app.get("/api/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    """List all forensic incidents."""
    return [
        {
            "incident_id": "INC-2025-001",
            "event_count": len(_engine.build_timeline()),
            "sources": _engine.get_sources(),
        }
    ]


@app.get("/api/timeline/{incident_id}")
async def get_timeline(incident_id: str) -> dict[str, Any]:
    """Get timeline for a specific incident."""
    events = _engine.build_timeline()
    return {
        "incident_id": incident_id,
        "event_count": len(events),
        "events": events,
    }


@app.get("/api/compliance")
async def get_compliance() -> dict[str, Any]:
    """Get compliance check results."""
    return _engine.check_compliance()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}
