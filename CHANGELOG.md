# Changelog

## [0.1.1] — 2026-05-26

### Security (Round 2 — 12 fixes)

**HIGH**
- H-1: Fix TOCTOU in generic parser — use single file handle for detect+parse
- H-2: Enable Jinja2 autoescape for `.jinja2` templates to prevent stored XSS

**MEDIUM**
- M-1: Enable SQLite WAL mode + batch transactions in `insert_many()`
- M-2: Add `USER appuser` to Dockerfile (no longer runs as root)
- M-3: Add `_safe_int()` helper in agentgate parser to prevent coercion attacks
- M-4: Restrict CORS to `http://127.0.0.1` and `http://localhost`
- M-5: Isolate evidence chain per engine instance via `clear_chain()` in `__init__`
- M-6: Lazy-init web server engine with temp-file DB instead of module-level state

**LOW**
- L-1: Escape user data in Rich CLI output with `html.escape()`
- L-2: Enforce 10MB max line length in all parsers
- L-3: Remove unused `httpx` dependency
- L-4: Deduplicate `_to_epoch()` to `utils/dates.py`

### Security (Round 1 — 20 fixes)

- Add `CORSMiddleware` with safe defaults
- Add `SecurityHeadersMiddleware` (X-Frame-Options, X-Content-Type-Options, etc.)
- Restrict `/reports` format parameter to `Literal['html','markdown','json']`
- Disable OpenAPI/Swagger docs in production mode
- Remove version disclosure from `/health` endpoint
- Add SRI integrity attribute to HTMX CDN script tag
- Remove unused dependencies (`sqlite-utils`, `apscheduler`)
- Escape markdown/json report bodies before `| safe` filter
- Remove unused `hmac_sign`/`verify_hmac` functions from `utils/crypto.py`
- Structured logging for web server
- XSS: Escape report bodies in HTML templates
- SQL injection warning comments in timeline builder
- Delete stale `forensics.db` from project root

### Features

- Add unique ID generation for compliance checks (`NIST-01` through `NIST-10`)
- Add `ReportTemplate` Pydantic model for type-safe report generation
- Add compliance-summary endpoint to web dashboard

### Fixes

- Fix `.gitignore` pattern `reports/` → `./reports` (was ignoring `src/agentforensics/reports/`)
- Fix Starlette 1.0.1 `TemplateResponse` signature: now `(request, name, context)`
- Fix Jinja2 3.1.6 LRUCache dict-in-key issue via `templates.env.cache = {}`
- Fix AgentGate parser: `agentgate_signal_to_taxonomy()` keyword args
- Fix mcp-taxonomy risk_score range handling (10.0–250.0)

### Chores

- Add `.dockerignore` for efficient Docker builds
- Add `.pre-commit-config.yaml` (ruff, mypy, hygiene hooks)
- Remove dead HTML branches from report generator (Jinja2 handles all HTML)
- Move HTML report template to `report.html.jinja2`
- Consolidate inline CSS into `static/style.css`
- Move web server sample data to module-level constant

### Docs

- Add coverage/mypy/ruff badges to README
- Security hardening notes in SECURITY.md

### Tests

- 9 new test files, 153 total tests
- End-to-end integration test (ingest → timeline → analyze → report)
- CLI tests for replay command, analyze, timeline --json, report --output
- Coverage: 82% → 93%

## [0.1.0] — 2026-05-26

### Initial Release

- Event ingestion from MCPGuard, AgentGate, and generic sources (JSONL, CSV, syslog, plain text)
- Timeline reconstruction with SQLite backend
- Behavior replay with step-by-step player, policy diff, and anomaly detection
- Incident report generation (markdown, HTML, JSON)
- Evidence chain with SHA-256 cryptographic linking
- Compliance auditing with 10 NIST AI RMF checks
- Web dashboard with FastAPI + HTMX + Plotly
- CLI with 7 commands: version, ingest, timeline, analyze, replay, report, serve
- REST API for all core functions
- mcp-taxonomy integration for normalized event classification
- 142 tests, 82% coverage
