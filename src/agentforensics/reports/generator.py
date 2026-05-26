"""Generate forensic reports from analysis results."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentforensics.timeline.correlator import correlate_events

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(),
    cache_size=50,
)

REPORT_TEMPLATE_MD = """\
# Agent Forensics Report

**Report generated**: {generated_at}
**Incident ID**: {incident_id}
**Total events**: {event_count}
**Sources**: {sources}

---

## Timeline Summary

{timeline_table}

## Correlated Event Groups

{correlation_summary}

## Policy Deviations

{deviations_summary}

## Anomalies Detected

{anomalies_summary}

## Evidence Chain of Custody

{evidence_summary}

## Raw Evidence

> Full evidence chain available in the database.
"""


def generate_report(
    timeline: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    deviations: list[dict[str, Any]],
    evidence_chain: list[dict[str, Any]] | None = None,
    fmt: str = "markdown",
    incident_id: str = "INC-UNKNOWN",
) -> str:
    """Generate a forensic report in the requested format.

    Args:
        timeline: Reconstructed event timeline.
        anomalies: Detected anomalies.
        deviations: Policy deviations found.
        evidence_chain: Chain of custody entries.
        fmt: Output format (``"markdown"``, ``"html"``, or ``"json"``).
        incident_id: Unique incident identifier.

    Returns:
        Formatted report string.
    """
    generated_at = datetime.now(UTC).isoformat()
    sources = sorted({e.get("source", "?") for e in timeline}) if timeline else []
    event_count = len(timeline)
    groups = correlate_events(timeline, window_seconds=60)
    evidence = evidence_chain or []

    if fmt == "json":
        return json.dumps(
            {
                "incident_id": incident_id,
                "generated_at": generated_at,
                "event_count": event_count,
                "sources": sources,
                "groups": groups,
                "timeline": timeline,
                "anomalies": anomalies,
                "deviations": deviations,
                "evidence_chain": evidence,
            },
            indent=2,
            default=str,
        )

    if fmt == "html":
        return _render_html(
            generated_at=generated_at,
            incident_id=incident_id,
            event_count=event_count,
            sources=", ".join(sources),
            events=timeline,
            groups=groups,
            anomalies=anomalies,
            deviations=deviations,
            evidence_chain=evidence,
        )

    timeline_table = _render_timeline_table(timeline, fmt="markdown")
    correlation_summary = _render_correlation_summary(groups, fmt="markdown")
    deviations_summary = _render_deviations(deviations, fmt="markdown")
    anomalies_summary = _render_anomalies(anomalies, fmt="markdown")
    evidence_summary = _render_evidence(evidence, fmt="markdown")

    return REPORT_TEMPLATE_MD.format(
        generated_at=generated_at,
        incident_id=incident_id,
        event_count=event_count,
        sources=", ".join(sources),
        timeline_table=timeline_table,
        correlation_summary=correlation_summary,
        deviations_summary=deviations_summary,
        anomalies_summary=anomalies_summary,
        evidence_summary=evidence_summary,
    )


def _render_html(**ctx: Any) -> str:
    template = _env.get_template("report.html.jinja2")
    return template.render(**ctx)


def _render_timeline_table(events: list[dict[str, Any]], fmt: str) -> str:
    if not events:
        return "No events recorded.\n" if fmt == "markdown" else "<p>No events recorded.</p>"

    lines: list[str] = []
    if fmt == "markdown":
        lines.append("| # | Source | Severity | Event | Timestamp | Risk |")
        lines.append("|---|---|---|---|---|---|")
        for i, ev in enumerate(events[:50], 1):
            sev = ev.get("severity", "?")
            title = (ev.get("title") or ev.get("event_type") or "?")[:60]
            ts = ev.get("timestamp", "?")[:19]
            risk = f"{float(ev.get('risk_score', 0)):.1f}"
            src = ev.get("source", "?")
            lines.append(f"| {i} | {src} | {sev} | {title} | {ts} | {risk} |")
        if len(events) > 50:
            lines.append(f"| ... | *{len(events) - 50} more events* | | | | |")
    else:
        lines.append(
            "<table><tr><th>#</th><th>Source</th><th>Severity</th><th>Event</th><th>Timestamp</th><th>Risk</th></tr>"
        )
        for i, ev in enumerate(events[:50], 1):
            sev = ev.get("severity", "?")
            css = f" severity-{sev}" if sev in ("critical", "high", "medium", "low") else ""
            title = (ev.get("title") or ev.get("event_type") or "?")[:60]
            ts = ev.get("timestamp", "?")[:19]
            risk = f"{float(ev.get('risk_score', 0)):.1f}"
            src = ev.get("source", "?")
            lines.append(
                f'<tr><td>{i}</td><td>{src}</td><td class="{css.strip()}">{sev}</td><td>{title}</td><td>{ts}</td><td>{risk}</td></tr>'
            )
        if len(events) > 50:
            lines.append(f"<tr><td colspan='6'><em>… {len(events) - 50} more events</em></td></tr>")
        lines.append("</table>")
    return "\n".join(lines)


def _render_correlation_summary(groups: list[dict[str, Any]], fmt: str) -> str:
    if not groups:
        return "No correlated event groups.\n" if fmt == "markdown" else "<p>No correlated event groups.</p>"

    lines: list[str] = []
    if fmt == "markdown":
        lines.append(f"**{len(groups)} correlated group(s) found**\n")
        for g in groups[:10]:
            lines.append(
                f"- Window: {g['window_start'][:19]} → {g['window_end'][:19]} | "
                f"{g['event_count']} events | Risk: {g['max_risk']:.1f} | "
                f"Sources: {', '.join(g['sources'])}"
            )
        if len(groups) > 10:
            lines.append(f"- … {len(groups) - 10} more groups")
    else:
        lines.append(f"<p><strong>{len(groups)} correlated group(s) found</strong></p><ul>")
        for g in groups[:10]:
            lines.append(
                f"<li>{g['window_start'][:19]} → {g['window_end'][:19]} — "
                f"{g['event_count']} events, risk {g['max_risk']:.1f} "
                f"({', '.join(g['sources'])})</li>"
            )
        if len(groups) > 10:
            lines.append(f"<li>… {len(groups) - 10} more groups</li>")
        lines.append("</ul>")
    return "\n".join(lines)


def _render_deviations(deviations: list[dict[str, Any]], fmt: str) -> str:
    if not deviations:
        return "No policy deviations detected.\n" if fmt == "markdown" else "<p>No policy deviations detected.</p>"

    lines: list[str] = []
    if fmt == "markdown":
        lines.append(f"**{len(deviations)} deviation(s) found**\n")
        for d in deviations:
            lines.append(f"- **[{d['type']}]** {d['description']}")
    else:
        lines.append(f"<p><strong>{len(deviations)} deviation(s) found</strong></p>")
        for d in deviations:
            lines.append(f'<div class="deviation"><strong>[{d["type"]}]</strong> {d["description"]}</div>')
    return "\n".join(lines)


def _render_anomalies(anomalies: list[dict[str, Any]], fmt: str) -> str:
    if not anomalies:
        return "No anomalies detected.\n" if fmt == "markdown" else "<p>No anomalies detected.</p>"

    lines: list[str] = []
    if fmt == "markdown":
        lines.append(f"**{len(anomalies)} anomaly(ies) found**\n")
        for a in anomalies:
            sev = a.get("severity", "?")
            score = f" (score: {a.get('score', 0):.1f})"
            lines.append(f"- **[severity: {sev}]{score}** {a['description']}")
    else:
        lines.append(f"<p><strong>{len(anomalies)} anomaly(ies) found</strong></p>")
        for a in anomalies:
            sev = a.get("severity", "?")
            lines.append(f'<div class="anomaly"><strong>[{sev}]</strong> {a["description"]}</div>')
    return "\n".join(lines)


def _render_evidence(evidence_chain: list[dict[str, Any]], fmt: str) -> str:
    if not evidence_chain:
        return "No evidence collected.\n" if fmt == "markdown" else "<p>No evidence collected.</p>"

    lines: list[str] = []
    if fmt == "markdown":
        lines.append(f"**{len(evidence_chain)} evidence entries**\n")
        lines.append("| ID | Hash | Collector | Timestamp |")
        lines.append("|---|---|---|---|")
        for e in evidence_chain:
            h = e.get("hash", "?")[:16]
            lines.append(
                f"| {e.get('evidence_id', '?')} | {h}… | {e.get('collector', '?')} | {e.get('timestamp', '?')[:19]} |"
            )
    else:
        lines.append(f"<p><strong>{len(evidence_chain)} evidence entries</strong></p><table>")
        lines.append("<tr><th>ID</th><th>Hash</th><th>Collector</th><th>Timestamp</th></tr>")
        for e in evidence_chain:
            h = e.get("hash", "?")[:16]
            lines.append(
                f"<tr><td>{e.get('evidence_id', '?')}</td><td>{h}…</td><td>{e.get('collector', '?')}</td>"
                f"<td>{e.get('timestamp', '?')[:19]}</td></tr>"
            )
        lines.append("</table>")
    return "\n".join(lines)
