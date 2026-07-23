"""Persist manual balance probes onto results / high_value_keys rows."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.services.result_operations import apply_balance_fields, update_balance_fields


def test_apply_balance_fields_merges_probe_and_strips_ephemeral() -> None:
    record = {
        "result_id": 99,
        "source_run_id": "run_x",
        "source_index": 3,
        "created_at": "old",
        "credential": {"apikey": "sk-test"},
        "balance": "",
        "tier": "unknown",
        "gateway": "",
        "provider_info": {
            "provider": "unknown",
            "validation_provider": "unknown",
            "credential_issuer": "unknown",
        },
    }
    out = apply_balance_fields(
        record,
        balance="12.5",
        tier="tier-1",
        gateway="openai",
        provider_evidence={
            "source": "openai:credit_grants",
            "evidence_kind": "cash_balance",
            "observed_at": "2026-01-01T00:00:00+00:00",
        },
    )
    assert "result_id" not in out
    assert "source_run_id" not in out
    assert "source_index" not in out
    assert "created_at" not in out
    assert out["balance"] == "12.5"
    assert out["tier"] == "tier-1"
    assert out["gateway"] == "openai"
    assert out["provider_info"]["provider"] == "openai"
    assert out["provider_info"]["balance_provider"] == "openai"
    assert out["provider_info"]["evidence_source"] == "openai:credit_grants"
    assert out["provider_evidence"]["evidence_kind"] == "cash_balance"


def test_update_balance_fields_no_target_is_noop() -> None:
    report = update_balance_fields(apikey="sk-x", balance="1")
    assert report == {
        "persisted": False,
        "result_id": None,
        "high_value": False,
        "reason": "no_target",
    }


def test_update_balance_fields_requires_pg_for_result_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        update_balance_fields(apikey="sk-x", balance="1", result_id=1)


class _FakeConn:
    def __init__(self, rows: dict[str, list[dict[str, Any]]]):
        self.rows = rows
        self.executed: list[tuple[str, Any]] = []

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def transaction(self) -> _FakeConn:
        return self

    def execute(self, sql: str, params: Any = None) -> _FakeConn:
        self.executed.append((sql, params))
        for needle, data in self.rows.items():
            if needle in sql:
                self._result = data
                break
        else:
            self._result = []
        return self

    def fetchone(self) -> dict[str, Any] | None:
        return self._result[0] if self._result else None


class _FakePool:
    def __init__(self, conn: _FakeConn):
        self._conn = conn

    def connection(self) -> _FakeConn:
        return self._conn


def test_update_balance_fields_updates_result_and_syncs_high_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aipocket.core.config.settings.database_url",
        "postgresql://x/y",
    )
    record = {
        "credential": {"apikey": "sk-proj-abc"},
        "balance": "",
        "tier": "",
        "gateway": "",
        "provider_info": {"provider": "openai"},
    }
    hv_record = {
        "apikey": "sk-proj-abc",
        "balance": "",
        "tier": "",
        "gateway": "",
        "provider_info": {"provider": "openai"},
    }
    conn = _FakeConn(
        {
            "FROM results WHERE id": [{"id": 7, "record": record}],
            "FROM high_value_keys WHERE apikey": [
                {
                    "apikey": "sk-proj-abc",
                    "run_id": "run_1",
                    "saved_at": None,
                    "record": hv_record,
                }
            ],
            "SELECT 1 FROM high_value_keys": [{"?column?": 1}],
        }
    )
    monkeypatch.setattr(
        "aipocket.core.db.get_pool",
        lambda: _FakePool(conn),
    )

    report = update_balance_fields(
        apikey="sk-proj-abc",
        balance="99.0",
        tier="scale",
        gateway="openai",
        provider_evidence={"evidence_kind": "cash_balance", "source": "x"},
        result_id=7,
    )
    assert report["persisted"] is True
    assert report["result_id"] == 7
    assert report["high_value"] is True

    updates = [sql for sql, _ in conn.executed if sql.strip().upper().startswith("UPDATE")]
    assert any("UPDATE results" in u for u in updates)
    assert any("UPDATE high_value_keys" in u for u in updates)

    # Last results UPDATE params should carry the new balance in JSONB payload.
    result_update = next(p for s, p in conn.executed if "UPDATE results" in s)
    payload = result_update[0]
    # Jsonb wrapper — unwrap if present
    rec = getattr(payload, "obj", payload)
    assert rec["balance"] == "99.0"
    assert rec["tier"] == "scale"
    assert rec["gateway"] == "openai"


def test_update_balance_fields_rejects_apikey_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aipocket.core.config.settings.database_url",
        "postgresql://x/y",
    )
    conn = _FakeConn(
        {
            "FROM results WHERE id": [{"id": 7, "record": {"credential": {"apikey": "sk-other"}}}],
        }
    )
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))
    with pytest.raises(ValueError, match="apikey does not match"):
        update_balance_fields(apikey="sk-mine", balance="1", result_id=7)


def test_key_balance_endpoint_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from aipocket.api.app import create_app

    monkeypatch.setattr("aipocket.core.config.settings.web_password", "ops-password")
    monkeypatch.setattr("aipocket.core.config.settings.web_jwt_secret", "ops-jwt-secret")

    async def fake_balance(apikey: str, apiurl: str) -> dict[str, Any]:
        return {"gateway": "openai", "balance_usd": "3.5", "tier": "default"}

    seen: dict[str, Any] = {}

    def fake_persist(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"persisted": True, "result_id": kwargs.get("result_id"), "high_value": False}

    monkeypatch.setattr("aipocket.api.routers.key.query_key_balance", fake_balance)
    monkeypatch.setattr(
        "aipocket.services.result_operations.update_balance_fields",
        fake_persist,
    )

    tc = TestClient(create_app())
    token = tc.post("/api/auth/login", json={"password": "ops-password"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    res = tc.post(
        "/api/key/balance",
        headers=headers,
        json={
            "apikey": "sk-test",
            "apiurl": "https://api.openai.com/v1",
            "result_id": 42,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["balance_usd"] == "3.5"
    assert body["persisted"] is True
    assert body["result_id"] == 42
    assert seen["result_id"] == 42
    assert seen["balance"] == "3.5"
    assert seen["apikey"] == "sk-test"
