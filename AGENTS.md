# agentforensics

Post-incident forensics system for AI agents — record, reconstruct, and analyze agent behavior after security events.

## Info

- Python, FastAPI, SQLite, Plotly, Typer, Rich, Pydantic, Jinja2, HTMX
- Event ingestion from MCPGuard, AgentGate, generic sources
- Timeline builder, behavior replay, policy deviation diff, anomaly detection
- Incident reports (markdown/HTML/JSON), SHA-256 evidence chain, NIST AI RMF compliance
- Web dashboard with HTMX, REST API, CLI
- mcp-taxonomy integration for normalized event classification
- MCPGuard policy exporter, MCPscop webhook integration
- Test: `python -m pytest tests/ -v` (165 tests, 93% coverage)
- Lint: `ruff check src/ tests/` (0 errors)
- Type check: `mypy src/agentforensics/` (0 errors, strict config)
- Sphinx docs at `docs/`, ReadTheDocs ready
- GitHub: Carlos-Projects/agentforensics
- PyPI: `agentforensics` (v0.1.1)
