"""API tests for manual targets router + scan source=manual wiring."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("WEB_PASSWORD", "test-pass")
    monkeypatch.setenv("WEB_JWT_SECRET", "test-secret-key-at-least-32-chars!!")
    monkeypatch.setattr("aipocket.core.config.settings.web_password", "test-pass")
    monkeypatch.setattr(
        "aipocket.core.config.settings.web_jwt_secret",
        "test-secret-key-at-least-32-chars!!",
    )
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    # Avoid schema init side effects
    monkeypatch.setattr("aipocket.core.db.ensure_schema", lambda: None)

    from aipocket.api.app import create_app

    app = create_app()
    return TestClient(app)


def _auth_headers(client: TestClient) -> dict[str, str]:
    res = client.post("/api/auth/login", json={"password": "test-pass"})
    assert res.status_code == 200
    token = res.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_list_requires_auth(client: TestClient) -> None:
    res = client.get("/api/manual-targets")
    assert res.status_code == 401


def test_list_empty_without_pg(client: TestClient) -> None:
    headers = _auth_headers(client)
    res = client.get("/api/manual-targets", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["results"] == []
    assert body["total"] == 0


def test_save_requires_pg(client: TestClient) -> None:
    headers = _auth_headers(client)
    res = client.post(
        "/api/manual-targets",
        headers=headers,
        json={"urls": "https://web.ymocode.com"},
    )
    assert res.status_code == 400
    msg = res.json()["error"]["message"]
    assert "PostgreSQL" in msg
    assert "自定义狩猎" in msg


def test_save_success(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers(client)

    def fake_add(urls, *, notes=""):
        return {
            "added": 1,
            "updated": 0,
            "rejected": ["bad!!!"],
            "targets": [
                {
                    "url": "https://web.ymocode.com",
                    "host_key": "web.ymocode.com:443",
                    "scheme": "https",
                    "hostname": "web.ymocode.com",
                    "port": 443,
                    "enabled": True,
                    "notes": notes,
                    "first_seen": "2026-01-01T00:00:00+00:00",
                    "last_seen": "2026-01-01T00:00:00+00:00",
                }
            ],
        }

    monkeypatch.setattr(
        "aipocket.services.manual_target_store.add_targets",
        fake_add,
    )
    res = client.post(
        "/api/manual-targets",
        headers=headers,
        json={"urls": "https://web.ymocode.com/login\nbad!!!"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["added"] == 1
    assert body["rejected"] == ["bad!!!"]
    assert body["targets"][0]["url"] == "https://web.ymocode.com"


def test_replace_flag(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers(client)
    called: dict = {}

    def fake_replace(urls, *, notes=""):
        called["urls"] = urls
        return {"added": 1, "updated": 0, "rejected": [], "targets": []}

    monkeypatch.setattr(
        "aipocket.services.manual_target_store.replace_targets",
        fake_replace,
    )
    res = client.post(
        "/api/manual-targets",
        headers=headers,
        json={"urls": "https://web.ymocode.com", "replace": True},
    )
    assert res.status_code == 200
    assert "web.ymocode.com" in called["urls"]


def test_delete_not_found(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers(client)
    monkeypatch.setattr(
        "aipocket.services.manual_target_store.delete_target",
        lambda url: False,
    )
    res = client.delete(
        "/api/manual-targets",
        headers=headers,
        params={"url": "https://missing.example.com"},
    )
    assert res.status_code == 404


def test_delete_ok(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers(client)
    monkeypatch.setattr(
        "aipocket.services.manual_target_store.delete_target",
        lambda url: True,
    )
    res = client.delete(
        "/api/manual-targets",
        headers=headers,
        params={"url": "https://web.ymocode.com"},
    )
    assert res.status_code == 200
    assert res.json()["deleted"] == 1


def test_bulk_delete(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = _auth_headers(client)
    monkeypatch.setattr(
        "aipocket.services.manual_target_store.delete_targets",
        lambda urls: 2,
    )
    res = client.post(
        "/api/manual-targets/bulk-delete",
        headers=headers,
        json={"urls": ["https://a.example.com", "https://b.example.com"]},
    )
    assert res.status_code == 200
    assert res.json()["deleted"] == 2


def test_scan_start_accepts_manual_source(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = _auth_headers(client)
    captured: dict = {}

    def fake_start(
        self,
        source,
        mode="incremental",
        github_pack_ids=(),
        resume_run_id="",
        manual_enrich=(),
    ):
        captured["source"] = source
        captured["mode"] = mode
        captured["manual_enrich"] = tuple(manual_enrich)
        return {
            "state": "running",
            "source": source,
            "mode": mode,
            "github_pack_ids": list(github_pack_ids),
            "manual_enrich": list(manual_enrich),
            "run_id": "run_test",
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": None,
            "error": None,
            "progress": {},
            "phase": "启动中",
            "log_seq": 0,
        }

    monkeypatch.setattr(
        "aipocket.api.scan_manager.ScanManager.start",
        fake_start,
    )
    res = client.post(
        "/api/scan/start",
        headers=headers,
        json={
            "source": "manual",
            "mode": "incremental",
            "manual_enrich": ["shodan", "fofa"],
        },
    )
    assert res.status_code == 200
    assert captured["source"] == "manual"
    assert captured["manual_enrich"] == ("fofa", "shodan")
    assert res.json()["source"] == "manual"
    assert res.json()["manual_enrich"] == ["fofa", "shodan"]


def test_scan_start_request_manual_label() -> None:
    from aipocket.api.schemas import ScanStartRequest

    assert ScanStartRequest(source="manual").resolved_source_label() == "manual"
    assert ScanStartRequest(sources=["manual"]).resolved_source_label() == "manual"
    assert ScanStartRequest(
        source="manual", manual_enrich=["shodan", "fofa"]
    ).resolved_manual_enrich() == ("fofa", "shodan")
    assert ScanStartRequest(source="fofa", manual_enrich=["shodan"]).resolved_manual_enrich() == ()


@pytest.mark.asyncio
async def test_scan_manager_passes_manual_source(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aipocket.api.scan_manager import ScanManager
    from aipocket.core.models import ScanRunResult

    captured: dict = {}
    result = ScanRunResult(
        started_at="2026-07-16T00:00:00Z",
        finished_at="2026-07-16T00:01:00Z",
        sources=["manual"],
        total_hosts=1,
        total_credentials=0,
        total_valid=0,
        queries_used=[],
        results=[],
    )

    async def fake_run_scan(**kwargs):
        captured.update(kwargs)
        return result

    monkeypatch.setattr("aipocket.services.scanner.run_scan", fake_run_scan)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    manager = ScanManager()
    manager._run_dir = tmp_path

    await manager._run("manual", manual_enrich=("fofa", "shodan"))

    assert captured["sources"] == {"manual"}
    assert captured["manual_enrich"] == ("fofa", "shodan")
    assert ScanManager._sources_for_scan("manual") == {"manual"}
