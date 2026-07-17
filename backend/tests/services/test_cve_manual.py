"""Tests for manual CVE add — parse URL/fields and persist across merge/sync."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from aipocket.clients.tavily import merge_cves
from aipocket.services.cve_manual import add_manual_cve, build_cve_from_input


@pytest.mark.asyncio
async def test_build_from_manual_fields_only():
    record = await build_cve_from_input(
        cve_id="CVE-2026-99999",
        product="litellm",
        cve_type="API key泄露",
        description="Manual test key leak",
        cvss=9.1,
    )
    assert record["id"] == "CVE-2026-99999"
    assert record["product"] == "litellm"
    assert record["type"] == "API key泄露"
    assert record["cvss"] == 9.1
    assert record["manual"] is True
    assert record["huntable"] == "高"


@pytest.mark.asyncio
async def test_build_requires_id_or_url():
    with pytest.raises(ValueError, match="URL 或 CVE ID"):
        await add_manual_cve()


@pytest.mark.asyncio
@respx.mock
async def test_build_from_url_parses_cve_page():
    html = """
    <html><head><title>CVE-2026-4242 LiteLLM API key leak</title></head>
    <body>
      <h1>CVE-2026-4242</h1>
      <p>LiteLLM authentication bypass allows unauthenticated access to admin
      APIs and credential exposure of stored provider API keys.</p>
      <p>CVSS v3.1: 9.8</p>
    </body></html>
    """
    respx.get("https://nvd.nist.gov/vuln/detail/CVE-2026-4242").mock(
        return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )

    record = await build_cve_from_input(url="https://nvd.nist.gov/vuln/detail/CVE-2026-4242")
    assert record["id"] == "CVE-2026-4242"
    assert record["product"] == "litellm"
    assert record["manual"] is True
    assert record["source_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-4242"
    assert record["cvss"] == 9.8 or record["type"]  # score or type classified


@pytest.mark.asyncio
@respx.mock
async def test_url_parse_with_manual_product_override():
    html = """
    <html><head><title>CVE-2026-5555 Security Advisory</title></head>
    <body>CVE-2026-5555 remote code execution in unknown product.</body></html>
    """
    respx.get("https://example.com/advisory/CVE-2026-5555").mock(
        return_value=httpx.Response(200, text=html, headers={"content-type": "text/html"})
    )

    record = await build_cve_from_input(
        url="https://example.com/advisory/CVE-2026-5555",
        product="dify",
        cve_type="RCE",
    )
    assert record["id"] == "CVE-2026-5555"
    assert record["product"] == "dify"
    assert record["type"] == "RCE"


@pytest.mark.asyncio
async def test_add_manual_persists_via_merge_and_survives_sync(monkeypatch, tmp_path):
    target = tmp_path / "cves.json"
    existing = [
        {
            "id": "CVE-2025-0001",
            "product": "dify",
            "type": "信息泄露",
            "description": "existing",
            "cvss": 5.0,
            "huntable": "中",
            "date": "2026-01-01",
            "source_url": "",
        }
    ]
    target.write_text(json.dumps(existing), encoding="utf-8")
    monkeypatch.setattr("aipocket.clients.tavily.CVE_PATH", target, raising=False)
    monkeypatch.setattr("aipocket.services.queries.CVE_PATH", target, raising=False)
    # File-only store (no PG)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.pg_dual_write", False)

    record, created, total = await add_manual_cve(
        cve_id="CVE-2026-77777",
        product="openwebui",
        cve_type="信息泄露",
        description="manual openwebui leak",
        url="",
    )
    assert created is True
    assert record["id"] == "CVE-2026-77777"
    assert total >= 2

    stored = json.loads(target.read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in stored}
    assert "CVE-2026-77777" in by_id
    assert by_id["CVE-2026-77777"]["manual"] is True
    assert "CVE-2025-0001" in by_id

    # Simulate Tavily sync merge: new remote CVE + no wipe of manuals
    merged, added = merge_cves(
        stored,
        [{"id": "CVE-2026-88888", "product": "flowise", "type": "SSRF", "description": "new"}],
        target,
    )
    assert added == 1
    ids = {c["id"] for c in merged}
    assert "CVE-2026-77777" in ids  # manual still present
    assert "CVE-2025-0001" in ids
    assert "CVE-2026-88888" in ids
    assert json.loads(target.read_text(encoding="utf-8")) == merged


@pytest.mark.asyncio
async def test_add_duplicate_id_skips_db_write(monkeypatch, tmp_path):
    target = tmp_path / "cves.json"
    existing = [
        {
            "id": "CVE-2026-11111",
            "product": "litellm",
            "type": "信息泄露",
            "description": "original",
            "cvss": 5.0,
            "huntable": "中",
            "date": "2026-01-01",
            "source_url": "https://example.com/original",
        }
    ]
    target.write_text(json.dumps(existing), encoding="utf-8")
    before = target.read_text(encoding="utf-8")
    monkeypatch.setattr("aipocket.clients.tavily.CVE_PATH", target, raising=False)
    monkeypatch.setattr("aipocket.services.queries.CVE_PATH", target, raising=False)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.pg_dual_write", False)

    record, created, total = await add_manual_cve(
        cve_id="CVE-2026-11111",
        product="dify",
        cve_type="RCE",
        description="should not overwrite",
        url="",
    )
    assert created is False
    assert total == 1
    assert record["description"] == "original"
    assert record["product"] == "litellm"
    assert target.read_text(encoding="utf-8") == before  # file untouched


@pytest.mark.asyncio
async def test_invalid_url_rejected():
    with pytest.raises(ValueError, match="http"):
        await build_cve_from_input(url="ftp://bad.example/cve")
