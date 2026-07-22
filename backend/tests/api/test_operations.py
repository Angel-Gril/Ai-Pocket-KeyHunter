from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aipocket.api.app import create_app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr("aipocket.core.config.settings.web_password", "ops-password")
    monkeypatch.setattr("aipocket.core.config.settings.web_jwt_secret", "ops-jwt-secret")
    return TestClient(create_app())


def _auth(client: TestClient) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"password": "ops-password"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_promote_requires_auth_and_nonempty_ids(client: TestClient) -> None:
    assert client.post("/api/keys/promote", json={"result_ids": [1]}).status_code == 401
    response = client.post(
        "/api/keys/promote",
        headers=_auth(client),
        json={"result_ids": []},
    )
    assert response.status_code == 422


def test_promote_maps_not_found_and_conflict_contracts(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aipocket.services import result_operations

    monkeypatch.setattr(
        result_operations,
        "promote_results",
        lambda *_args: (_ for _ in ()).throw(LookupError("missing")),
    )
    missing = client.post(
        "/api/keys/promote",
        headers=_auth(client),
        json={"result_ids": [11]},
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"

    monkeypatch.setattr(
        result_operations,
        "promote_results",
        lambda *_args: (_ for _ in ()).throw(ValueError("changed")),
    )
    conflict = client.post(
        "/api/keys/promote",
        headers=_auth(client),
        json={"result_ids": [11]},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "conflict"


def test_promote_maps_postgres_disabled(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    response = client.post(
        "/api/keys/promote",
        headers=_auth(client),
        json={"result_ids": [11]},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "postgres_required"


def test_promote_returns_stable_ids_and_audit_report(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aipocket.services import result_operations

    seen: dict[str, object] = {}

    def fake_promote(ids: list[int], note: str) -> dict[str, list[int]]:
        seen.update(ids=ids, note=note)
        return {"promoted": [3], "skipped": [4]}

    monkeypatch.setattr(result_operations, "promote_results", fake_promote)
    response = client.post(
        "/api/keys/promote",
        headers=_auth(client),
        json={"result_ids": [3, 3, 4], "note": "manual balance recheck"},
    )
    assert response.status_code == 200
    assert response.json() == {"promoted": [3], "skipped": [4]}
    assert seen == {"ids": [3, 3, 4], "note": "manual balance recheck"}


def test_delete_run_maps_not_found_and_nonempty_conflict(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aipocket.services import result_operations

    headers = _auth(client)
    monkeypatch.setattr(
        result_operations,
        "delete_run",
        lambda _run_id: (_ for _ in ()).throw(LookupError("missing")),
    )
    missing = client.delete("/api/runs/run_2026_07_22_00-00-00", headers=headers)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"

    monkeypatch.setattr(
        result_operations,
        "delete_run",
        lambda _run_id: (_ for _ in ()).throw(ValueError("not empty")),
    )
    conflict = client.delete("/api/runs/run_2026_07_22_00-00-00", headers=headers)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "run_not_empty"

def test_delete_run_requires_valid_id_and_maps_database_disabled(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = _auth(client)
    invalid = client.delete("/api/runs/not-a-run", headers=headers)
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "bad_request"

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    disabled = client.delete("/api/runs/run_2026_07_22_00-00-00", headers=headers)
    assert disabled.status_code == 409
    assert disabled.json()["error"]["code"] == "postgres_required"


def test_delete_run_returns_disk_cleanup_status(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aipocket.services import result_operations

    monkeypatch.setattr(
        result_operations,
        "delete_run",
        lambda run_id: {"run_id": run_id, "deleted": True, "disk_removed": False},
    )
    response = client.delete(
        "/api/runs/run_2026_07_22_00-00-00",
        headers=_auth(client),
    )
    assert response.status_code == 200
    assert response.json() == {
        "run_id": "run_2026_07_22_00-00-00",
        "deleted": True,
        "disk_removed": False,
    }
