"""Tests for the web server."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from agentforensics.web.server import app


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client: AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_index(client: AsyncClient) -> None:
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "AgentForensics" in resp.text


@pytest.mark.asyncio
async def test_timeline_page(client: AsyncClient) -> None:
    resp = await client.get("/timeline")
    assert resp.status_code == 200
    assert "Timeline" in resp.text


@pytest.mark.asyncio
async def test_reports_page(client: AsyncClient) -> None:
    resp = await client.get("/reports")
    assert resp.status_code == 200
    assert "Reports" in resp.text or "report" in resp.text.lower()


@pytest.mark.asyncio
async def test_ingest_sample(client: AsyncClient) -> None:
    resp = await client.post("/ingest/sample")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_incidents(client: AsyncClient) -> None:
    resp = await client.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_api_timeline(client: AsyncClient) -> None:
    resp = await client.get("/api/timeline/INC-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-001"


@pytest.mark.asyncio
async def test_api_compliance(client: AsyncClient) -> None:
    resp = await client.get("/api/compliance")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
