from __future__ import annotations

import json

from aipocket.clients.tavily import merge_cves
from aipocket.services.queries import CVE_PATH


def test_merge_cves_defaults_to_loader_path(monkeypatch, tmp_path):
    target = tmp_path / "cve_2026_ai.json"
    monkeypatch.setattr("aipocket.clients.tavily.CVE_PATH", target, raising=False)

    merge_cves([], [{"id": "CVE-2026-1000", "product": "Dify"}])

    assert json.loads(target.read_text(encoding="utf-8"))[0]["id"] == "CVE-2026-1000"
    assert CVE_PATH.name == target.name


def test_merge_cves_updates_existing_record(monkeypatch, tmp_path):
    target = tmp_path / "cves.json"
    existing = [
        {
            "id": "CVE-2026-1000",
            "product": "Dify",
            "cvss": 0.0,
            "type": "",
            "source_url": "",
            "updated_at": "2026-07-01T00:00:00Z",
        }
    ]
    discovered = [
        {
            "id": "CVE-2026-1000",
            "product": "Dify",
            "cvss": 9.8,
            "type": "认证绕过",
            "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
            "updated_at": "2026-07-10T00:00:00Z",
        }
    ]

    merged, changed = merge_cves(existing, discovered, target)

    assert changed == 0
    assert merged[0]["cvss"] == 9.8
    assert merged[0]["type"] == "认证绕过"
    assert merged[0]["source_url"].startswith("https://nvd.nist.gov/")
    assert json.loads(target.read_text(encoding="utf-8")) == merged
