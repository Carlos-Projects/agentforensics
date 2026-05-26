"""Incident report generation."""

from __future__ import annotations

from pydantic import BaseModel


class IncidentReport(BaseModel):
    """Structured incident report."""

    incident_id: str
    title: str
    severity: str = "unknown"
    timeline_summary: str = ""
    anomalies_count: int = 0
    deviations_count: int = 0
    recommendations: list[str] = []
