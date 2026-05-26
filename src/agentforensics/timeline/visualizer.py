"""Visualise forensic timelines with Plotly."""

from __future__ import annotations

from typing import Any


def render_timeline_chart(
    events: list[dict[str, Any]],
    title: str = "Agent Forensic Timeline",
) -> str:
    """Render a Gantt-style timeline chart as self-contained HTML.

    Args:
        events: List of timeline events.
        title: Chart title.

    Returns:
        Full HTML page string containing the Plotly chart.
    """
    if not events:
        return _empty_chart_html(title)

    try:
        import plotly.express as px
    except ImportError:
        return "<div>Install plotly: pip install plotly</div>"

    # Build a Gantt-like chart: each event is a point on the timeline
    df: list[dict[str, Any]] = []
    for ev in events:
        ts = ev.get("timestamp", "")
        sev = ev.get("severity", "info")
        src = ev.get("source", "?")
        etype = ev.get("event_type", "?")
        title_str = ev.get("title", etype)

        # Color by severity
        color_map = {
            "critical": "red",
            "high": "orange",
            "medium": "gold",
            "low": "green",
            "info": "blue",
        }

        df.append(
            {
                "Timestamp": ts,
                "Event": title_str,
                "Source": src,
                "Severity": sev,
                "Type": etype,
                "Color": color_map.get(sev, "gray"),
            }
        )

    fig = px.strip(
        df,
        x="Timestamp",
        y="Source",
        color="Severity",
        hover_data=["Event", "Type"],
        title=title,
        color_discrete_map={
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        },
        category_orders={"Severity": ["critical", "high", "medium", "low", "info"]},
    )

    fig.update_traces(marker=dict(size=10, line=dict(width=1, color="DarkSlateGrey")))
    fig.update_layout(
        xaxis_title="Timestamp",
        yaxis_title="Source",
        height=max(300, len(df) * 30 + 100),
        template="plotly_white",
        hovermode="closest",
    )

    return fig.to_html(include_plotlyjs="cdn", full_html=False)


def render_severity_pie(events: list[dict[str, Any]]) -> str:
    """Render a severity distribution pie chart.

    Args:
        events: List of timeline events.

    Returns:
        HTML string containing the Plotly chart.
    """
    if not events:
        return "<div>No events to display</div>"

    try:
        import plotly.express as px
    except ImportError:
        return "<div>Install plotly: pip install plotly</div>"

    counts: dict[str, int] = {}
    for ev in events:
        sev = ev.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    fig = px.pie(
        names=list(counts.keys()),
        values=list(counts.values()),
        title="Event Severity Distribution",
        color=list(counts.keys()),
        color_discrete_map={
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        },
    )
    return fig.to_html(include_plotlyjs="cdn", full_html=False)


def render_risk_timeline(events: list[dict[str, Any]]) -> str:
    """Render a risk score timeline (scatter + line).

    Args:
        events: List of timeline events.

    Returns:
        HTML string containing the Plotly chart.
    """
    if not events:
        return "<div>No events to display</div>"

    try:
        import plotly.graph_objects as go
    except ImportError:
        return "<div>Install plotly: pip install plotly</div>"

    timestamps = [e.get("timestamp", "") for e in events]
    scores = [float(e.get("risk_score", 0)) for e in events]
    titles = [e.get("title", e.get("event_type", "?")) for e in events]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=scores,
            mode="lines+markers",
            text=titles,
            hovertemplate="<b>%{text}</b><br>%{x}<br>Risk: %{y}<extra></extra>",
            line=dict(color="#dc3545", width=2),
            marker=dict(size=8, color="#dc3545"),
        )
    )

    fig.update_layout(
        title="Risk Score Over Time",
        xaxis_title="Timestamp",
        yaxis_title="Risk Score",
        template="plotly_white",
        height=400,
    )
    return fig.to_html(include_plotlyjs="cdn", full_html=False)


def _empty_chart_html(title: str) -> str:
    return f"<div style='padding:2rem;text-align:center;color:#666;'><h3>{title}</h3><p>No events to display</p></div>"
