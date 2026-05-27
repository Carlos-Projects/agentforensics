"""Export forensic events and compliance results to the MCPscop dashboard."""

from __future__ import annotations

from typing import Any

MCPscop_API_URL = "http://localhost:9000"


def export_events_to_mcpscop(
    events: list[dict[str, Any]],
    base_url: str = MCPscop_API_URL,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Send forensic events to MCPscop's event ingestion endpoint.

    Each event is sent as a ``POST /api/events`` request to the MCPscop
    dashboard. Uses the ``SecurityEvent`` schema expected by MCPscop.

    Args:
        events: List of forensic event dicts.
        base_url: MCPscop server base URL.
        api_key: Optional API key for authenticated deployments.

    Returns:
        Summary dict with ``sent`` and ``failed`` counts.
    """
    import httpx as _httpx

    sent = 0
    failed = 0
    errors: list[str] = []

    with _httpx.Client(timeout=10.0) as client:
        for ev in events:
            payload = _to_security_event(ev)
            headers = _build_headers(api_key)
            try:
                resp = client.post(f"{base_url}/api/events", json=payload, headers=headers)
                if resp.is_success:
                    sent += 1
                else:
                    failed += 1
                    errors.append(f"HTTP {resp.status_code}")
            except _httpx.RequestError as exc:
                failed += 1
                errors.append(str(exc))

    return {
        "sent": sent,
        "failed": failed,
        "total": len(events),
        "errors": errors[:5],
    }


def export_compliance_to_mcpscop(
    compliance: dict[str, Any],
    base_url: str = MCPscop_API_URL,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Send compliance results to MCPscop via taxonomy normalization.

    Posts the compliance summary to ``POST /api/taxonomy/normalize``
    for standardized classification.

    Args:
        compliance: Compliance check results.
        base_url: MCPscop server base URL.
        api_key: Optional API key.

    Returns:
        Normalized finding response from MCPscop, or error dict.
    """
    import httpx as _httpx

    payload = {
        "source": "agentforensics",
        "raw": {
            "framework": compliance.get("framework"),
            "status": compliance.get("status"),
            "passed": compliance.get("passed"),
            "total_checks": compliance.get("total_checks"),
            "checks": compliance.get("checks", []),
        },
    }

    headers = _build_headers(api_key)
    try:
        with _httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{base_url}/api/taxonomy/normalize", json=payload, headers=headers)
            if resp.is_success:
                return resp.json()  # type: ignore[no-any-return]
            return {"error": f"HTTP {resp.status_code}", "detail": resp.text}
    except _httpx.RequestError as exc:
        return {"error": str(exc)}


def _to_security_event(ev: dict[str, Any]) -> dict[str, Any]:
    """Convert a forensic event to MCPscop SecurityEvent format."""
    return {
        "event_type": ev.get("event_type", "unknown"),
        "severity": ev.get("severity", "info"),
        "message": ev.get("title") or ev.get("description") or "No message",
        "source": "agentforensics",
        "tool": ev.get("target", ""),
        "details": {
            "risk_score": ev.get("risk_score", 0),
            "source": ev.get("source", "unknown"),
        },
        "blocked": bool(ev.get("blocked", False)),
    }


def _build_headers(api_key: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    return headers
