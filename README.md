# AgentForensics 🔍⚖️

[![CI](https://img.shields.io/github/actions/workflow/status/Carlos-Projects/agentforensics/ci.yml?branch=main&logo=github)](https://github.com/Carlos-Projects/agentforensics/actions)
[![PyPI version](https://img.shields.io/pypi/v/agentforensics?logo=pypi)](https://pypi.org/project/agentforensics/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/github/license/Carlos-Projects/agentforensics?logo=opensourceinitiative)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Carlos-Projects/agentforensics?style=social)](https://github.com/Carlos-Projects/agentforensics)

**Reconstruct what the AI agent did — after the damage is done.**

---

**AgentForensics** is the post-incident forensics system for autonomous AI agents. Your stack has prevention (AgentGate, MCPGuard) and detection (MCPscop, Palisade) — but when an agent goes rogue, you need **forensics**. This project closes that gap by recording, reconstructing, and analyzing agent behavior after security events.

Built for security teams investigating AI agent incidents, AgentForensics ingests logs from MCPGuard and AgentGate, reconstructs complete behavioral timelines, replays agent actions interactively, detects policy deviations, and generates audit-ready incident reports with full chain of custody.

---

## What it does

- **Event Ingestion** — Ingest logs from MCPGuard, AgentGate, and generic sources
- **Timeline Reconstruction** — Build complete chronological timelines of agent behavior
- **Behavior Replay** — Interactively replay what the agent did, step by step
- **Policy Deviation Detection** — Detect when agents strayed from their approved policies
- **Incident Report Generation** — Generate automated, audit-ready forensic reports
- **Evidence Chain** — Maintain cryptographic chain of custody for all evidence
- **Compliance Auditing** — Verify agent behavior against NIST AI RMF and internal policies

## What makes it unique

| Capability | **AgentForensics** | Generic Log Tools | SIEM Platforms |
|---|---|---|---|
| AI agent behavior replay | ✅ | ❌ | ❌ |
| Policy deviation detection | ✅ | ❌ | Partial |
| MCP/AgentGate native ingest | ✅ | ❌ | ❌ |
| Chain of custody (SHA-256) | ✅ | ❌ | ❌ |
| Interactive timeline | ✅ | Partial | Partial |
| mcp-taxonomy integration | ✅ | ❌ | ❌ |

## Quick Start

```bash
# Installation
pip install agentforensics

# Or from source
git clone https://github.com/Carlos-Projects/agentforensics
cd agentforensics
pip install -e ".[dev]"
```

### CLI

```bash
# Ingest logs from multiple sources
agentforensics ingest --mcpguard /var/log/mcpguard.jsonl --agentgate /var/log/agentgate.log

# Reconstruct timeline
agentforensics timeline

# Replay agent behavior
agentforensics replay --speed 2.0

# Generate incident report
agentforensics report --format markdown --output incident_report.md

# Start web dashboard
agentforensics serve --port 8000
```

### Python API

```python
from agentforensics.engine import ForensicsEngine
from pathlib import Path

engine = ForensicsEngine()
engine.ingest_mcpguard(Path("mcpguard.jsonl"))
engine.ingest_agentgate(Path("agentgate.log"))

timeline = engine.build_timeline()
report = engine.generate_report(fmt="markdown")
print(report)
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AgentForensics                        │
├─────────────────────────────────────────────────────────┤
│  CLI (Typer)          Web Dashboard (FastAPI + HTMX)    │
├─────────────────────────────────────────────────────────┤
│                    Forensics Engine                      │
├──────────┬──────────────┬──────────┬────────────────────┤
│  Ingest  │   Timeline   │  Replay  │     Reports        │
│          │              │          │                    │
│ MCPGuard │  Builder     │ Player   │  Incident Report   │
│ AgentGate│  Correlator  │ Diff     │  Compliance Audit  │
│ Generic  │  Visualizer  │ Anomaly  │  Evidence Chain    │
├──────────┴──────────────┴──────────┴────────────────────┤
│              SQLite + Pydantic + Plotly                  │
└─────────────────────────────────────────────────────────┘
         ▲                    ▲
         │                    │
    MCPGuard logs      AgentGate signals
```

## Integration with the MCP Security Ecosystem

- **Consumes** logs from [MCPGuard](https://github.com/Carlos-Projects/mcpguard) and signals from [AgentGate](https://github.com/Carlos-Projects/agentgate)
- **Feeds** forensic reports to [MCPscop](https://github.com/Carlos-Projects/mcpscope) dashboard
- **Uses** [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) for standardized classification
- **Follows** the same stack pattern as MCPscop (FastAPI, SQLite, Plotly, HTMX)

## Testing

```bash
python -m pytest tests/ -v
```

## Related

- [MCPGuard](https://github.com/Carlos-Projects/mcpguard) — Runtime security proxy for MCP/A2A
- [AgentGate](https://github.com/Carlos-Projects/agentgate) — Policy-based firewall for AI agents
- [MCPscop](https://github.com/Carlos-Projects/mcpscope) — Unified security dashboard
- [mcpwn](https://github.com/Carlos-Projects/mcpwn) — Offensive security testing for MCP
- [palisade-scanner](https://github.com/Carlos-Projects/palisade-scanner) — Prompt injection scanner
- [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) — Classification taxonomy
- [AIAO](https://aiagentobservatory.org) — AI Agent Observatory
- [veeduria](https://veeduria.online) — Public procurement monitoring

## License

MIT — see [LICENSE](LICENSE)
