# Current State

Status: active
Last updated: 2026-05-29

## Current Goal

Install the shared Codex/OpenCode harness and connect AgentForensics to the evidence/replay role in the AI security stack.

## Known Good Commands

- setup: `pip install -e ".[all]"`
- test: `python -m pytest tests/ -v --tb=short`
- lint: `ruff check src/ tests/`
- typecheck: `mypy src/agentforensics/`
- build: `python -m build`

## Open Risks

- Do not mutate evidence during replay or report generation.
- Preserve chain-of-custody hashes and source provenance.
- Avoid committing local databases, coverage files, or generated forensic exports.

## Next Step

- Add harness audit/Decision BOM ingestion fixtures and verify replay/report outputs.
