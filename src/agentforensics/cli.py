"""CLI for AgentForensics — post-incident forensics for AI agents."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentforensics import __version__
from agentforensics.engine import ForensicsEngine
from agentforensics.replay.player import replay_events

app = typer.Typer(
    name="agentforensics",
    help="Post-incident forensics system for AI agents",
    add_completion=False,
)
console = Console()


def _make_engine(db_path: Path) -> ForensicsEngine:
    return ForensicsEngine(db_path=str(db_path))


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bold]AgentForensics[/bold] v{__version__}")
    console.print("[dim]Post-incident forensics for AI agents[/dim]")


@app.command()
def ingest(
    mcpguard: Path | None = typer.Option(
        None,
        "--mcpguard",
        help="Path to MCPGuard JSONL log",
    ),
    agentgate: Path | None = typer.Option(
        None,
        "--agentgate",
        help="Path to AgentGate signal file",
    ),
    generic: Path | None = typer.Option(
        None,
        "--generic",
        help="Path to generic log file",
    ),
    fmt: str = typer.Option(
        "auto",
        "--format",
        "-f",
        help="Format for generic logs (auto/jsonl/csv/syslog/plain)",
    ),
    output: Path = typer.Option(
        Path("forensics.db"),
        "--output",
        "-o",
        help="Output database path",
    ),
) -> None:
    """Ingest logs from multiple sources into the forensic timeline."""
    engine = _make_engine(output)
    total = 0

    if mcpguard:
        n = engine.ingest_mcpguard(mcpguard)
        console.print(f"[green]✓[/green] Ingested [bold]{n}[/bold] events from MCPGuard")
        total += n

    if agentgate:
        n = engine.ingest_agentgate(agentgate)
        console.print(f"[green]✓[/green] Ingested [bold]{n}[/bold] events from AgentGate")
        total += n

    if generic:
        n = engine.ingest_generic(generic, fmt=fmt)
        console.print(f"[green]✓[/green] Ingested [bold]{n}[/bold] events from generic source")
        total += n

    if total == 0:
        console.print("[yellow]No events ingested. Specify at least one log source.[/yellow]")
        return

    console.print(f"\n[bold]Total events stored:[/bold] {engine.event_count}")
    console.print(f"[dim]Database: {output.resolve()}[/dim]")
    engine.close()


@app.command()
def timeline(
    input_db: Path = typer.Option(
        Path("forensics.db"),
        "--input",
        "-i",
        help="Input database path",
    ),
    source: str | None = typer.Option(
        None,
        "--source",
        "-s",
        help="Filter by source",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical/high/medium/low/info)",
    ),
    limit: int = typer.Option(
        50,
        "--limit",
        "-n",
        help="Max events to show",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
) -> None:
    """Reconstruct and display the forensic timeline."""
    if not input_db.exists():
        console.print(f"[red]Error:[/red] Database not found: {input_db}")
        raise typer.Exit(1)

    engine = _make_engine(input_db)
    events = engine.query_events(source=source, severity=severity, limit=limit)

    if not events:
        console.print("[yellow]No events found matching filters.[/yellow]")
        return

    if json_output:
        console.print_json(json.dumps(events, default=str))
        return

    console.print(Panel(f"[bold]Forensic Timeline[/bold] — {len(events)} events", title="Timeline"))

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Source", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Event", width=30)
    table.add_column("Target", width=25)
    table.add_column("Risk", width=6)
    table.add_column("Blocked", width=8)
    table.add_column("Timestamp", width=20)

    for i, ev in enumerate(events, 1):
        sev = ev.get("severity", "?")
        sev_style = {"critical": "red", "high": "orange3", "medium": "gold1", "low": "green", "info": "blue"}.get(
            sev, ""
        )
        blocked = "[red]BLOCKED[/red]" if ev.get("blocked") else "[green]OK[/green]"
        table.add_row(
            str(i),
            ev.get("source", "?"),
            f"[{sev_style}]{sev}[/{sev_style}]" if sev_style else sev,
            (ev.get("title") or ev.get("event_type") or "?")[:30],
            (ev.get("target", "") or "—")[:25],
            f"{float(ev.get('risk_score', 0)):.1f}",
            blocked,
            ev.get("timestamp", "?")[:19],
        )

    console.print(table)
    engine.close()


@app.command()
def analyze(
    input_db: Path = typer.Option(
        Path("forensics.db"),
        "--input",
        "-i",
        help="Input database path",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
) -> None:
    """Run anomaly detection and policy deviation analysis."""
    if not input_db.exists():
        console.print(f"[red]Error:[/red] Database not found: {input_db}")
        raise typer.Exit(1)

    engine = _make_engine(input_db)
    events = engine.build_timeline()

    if not events:
        console.print("[yellow]No events to analyze.[/yellow]")
        return

    anomalies = engine.analyze_anomalies()
    deviations = engine.analyze_deviations()

    if json_output:
        console.print_json(
            json.dumps(
                {
                    "event_count": len(events),
                    "anomalies": anomalies,
                    "deviations": deviations,
                },
                default=str,
            )
        )
        return

    console.print(Panel(f"[bold]Analysis Results[/bold] — {len(events)} events", title="Analysis"))

    # Anomalies
    if anomalies:
        console.print(f"\n[red]⚠ {len(anomalies)} Anomaly(ies) Detected[/red]")
        anom_table = Table(show_header=True, header_style="bold")
        anom_table.add_column("Type", width=20)
        anom_table.add_column("Severity", width=10)
        anom_table.add_column("Score", width=6)
        anom_table.add_column("Description", width=60)
        for a in anomalies:
            anom_table.add_row(
                a.get("type", "?"),
                f"[red]{a.get('severity', '?')}[/red]"
                if a.get("severity") in ("critical", "high")
                else a.get("severity", "?"),
                f"{float(a.get('score', 0)):.1f}",
                a.get("description", "")[:60],
            )
        console.print(anom_table)
    else:
        console.print("[green]✓ No anomalies detected[/green]")

    # Deviations
    if deviations:
        console.print(f"\n[orange3]⚠ {len(deviations)} Policy Deviation(s)[/orange3]")
        dev_table = Table(show_header=True, header_style="bold")
        dev_table.add_column("Type", width=18)
        dev_table.add_column("Description", width=80)
        for d in deviations:
            dev_table.add_row(d.get("type", "?"), d.get("description", "")[:80])
        console.print(dev_table)
    else:
        console.print("[green]✓ No policy deviations detected[/green]")

    # Compliance
    compliance = engine.check_compliance()
    status_color = {"pass": "green", "partial": "gold1", "fail": "red"}.get(compliance["status"], "white")
    console.print(
        f"\n[bold]Compliance:[/bold] [{status_color}]{compliance['status']}[/{status_color}] "
        f"({compliance['passed']}/{compliance['total_checks']} checks passed)"
    )

    engine.close()


@app.command()
def replay(
    input_db: Path = typer.Option(
        Path("forensics.db"),
        "--input",
        "-i",
        help="Input database path",
    ),
    speed: float = typer.Option(
        1.0,
        "--speed",
        "-s",
        help="Playback speed multiplier (0 = instant)",
    ),
    limit: int = typer.Option(
        100,
        "--limit",
        "-n",
        help="Max events to replay",
    ),
) -> None:
    """Replay agent behaviour from the forensic timeline."""
    if not input_db.exists():
        console.print(f"[red]Error:[/red] Database not found: {input_db}")
        raise typer.Exit(1)

    engine = _make_engine(input_db)
    events = engine.build_timeline()[:limit]
    engine.close()

    if not events:
        console.print("[yellow]No events to replay.[/yellow]")
        return

    console.print(f"[bold]Replaying {len(events)} event(s) at {speed}x speed[/bold]")
    console.print()

    for ev in replay_events(events, speed=speed):
        ts = ev.get("timestamp", "?")[:19]
        src = ev.get("source", "?")
        title = escape((ev.get("title") or ev.get("event_type") or "?")[:50])
        delay = ev.get("_replay_delay", 0)
        console.print(f"  [{ts}] [bold]{src}[/bold] {title}  [dim](+{delay:.1f}s)[/dim]")


@app.command()
def report(
    input_db: Path = typer.Option(
        Path("forensics.db"),
        "--input",
        "-i",
        help="Input database path",
    ),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format (markdown/html/json)",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    incident_id: str = typer.Option(
        "INC-UNKNOWN",
        "--incident",
        help="Incident identifier",
    ),
) -> None:
    """Generate a forensic incident report."""
    if not input_db.exists():
        console.print(f"[red]Error:[/red] Database not found: {input_db}")
        raise typer.Exit(1)

    engine = _make_engine(input_db)
    report_text = engine.generate_report(fmt=fmt, incident_id=incident_id)
    engine.close()

    if output:
        output.write_text(report_text, encoding="utf-8")
        console.print(f"[green]✓[/green] Report written to [bold]{output}[/bold]")
    else:
        console.print(report_text)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    db_path: Path = typer.Option(
        Path("forensics.db"),
        "--db",
        help="Database path",
    ),
) -> None:
    """Start the web dashboard server."""
    import uvicorn

    console.print("[bold]AgentForensics Dashboard[/bold]")
    console.print(f"  URL:  [underline]http://{host}:{port}[/underline]")
    console.print(f"  DB:   {db_path.resolve()}")
    console.print(f"  API:  http://{host}:{port}/api/incidents")
    console.print()
    console.print("[dim]Sample data pre-loaded for demo[/dim]")

    from agentforensics.web.server import app as web_app

    uvicorn.run(web_app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
