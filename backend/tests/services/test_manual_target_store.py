"""Tests for manual_target_store (PG-gated CRUD + sanitize integration)."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.services import manual_target_store as store


class _FakeCursor:
    def __init__(self, conn: _FakeConn, rowcount: int = 0):
        self._conn = conn
        self.rowcount = rowcount

    def fetchone(self) -> dict[str, Any] | None:
        return self._conn._last_fetchone

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._conn._last_fetchall)


class _FakeConn:
    def __init__(self) -> None:
        self.statements: list[tuple[str, Any]] = []
        self._last_fetchone: dict[str, Any] | None = None
        self._last_fetchall: list[dict[str, Any]] = []
        self._rowcount = 0
        self.committed = False

    def execute(self, sql: str, params: Any = None) -> _FakeCursor:
        self.statements.append((sql, params))
        return _FakeCursor(self, rowcount=self._rowcount)

    def commit(self) -> None:
        self.committed = True

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self.conn = conn

    def connection(self) -> _FakeConn:
        return self.conn


def test_list_targets_pg_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    rows, total = store.list_targets()
    assert rows == []
    assert total == 0


def test_load_enabled_urls_pg_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert store.load_enabled_urls() == []


def test_add_targets_requires_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    with pytest.raises(ValueError, match="自定义狩猎.*PostgreSQL"):
        store.add_targets("https://web.ymocode.com")


def test_add_targets_rejects_all_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    with pytest.raises(ValueError, match="没有有效地址"):
        store.add_targets("not a host!!!\nftp://x.com\njavascript:alert(1)")


def test_add_targets_empty_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    with pytest.raises(ValueError, match="至少"):
        store.add_targets("  \n  ")


def test_add_targets_upserts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    # Simulate INSERT ... RETURNING with inserted=True then False
    rows = [
        {
            "url": "https://web.ymocode.com",
            "host_key": "web.ymocode.com:443",
            "scheme": "https",
            "hostname": "web.ymocode.com",
            "port": 443,
            "enabled": True,
            "notes": "",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "inserted": True,
        },
        {
            "url": "https://web2.ymocode.com",
            "host_key": "web2.ymocode.com:443",
            "scheme": "https",
            "hostname": "web2.ymocode.com",
            "port": 443,
            "enabled": True,
            "notes": "",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "inserted": False,
        },
    ]
    call_idx = {"i": 0}

    def execute(sql: str, params: Any = None) -> _FakeCursor:
        conn.statements.append((sql, params))
        if "INSERT INTO manual_targets" in sql:
            conn._last_fetchone = rows[call_idx["i"]]
            call_idx["i"] += 1
        return _FakeCursor(conn)

    conn.execute = execute  # type: ignore[method-assign]
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))

    result = store.add_targets(
        "https://web.ymocode.com/login/xxx\nhttps://web2.ymocode.com\nbad!!!"
    )
    assert result["added"] == 1
    assert result["updated"] == 1
    assert result["rejected"] == ["bad!!!"]
    assert len(result["targets"]) == 2
    assert conn.committed
    # Path stripped before insert
    insert_params = [p for s, p in conn.statements if "INSERT" in s]
    assert insert_params[0][0] == "https://web.ymocode.com"


def test_delete_target_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    conn._rowcount = 0
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))
    assert store.delete_target("https://missing.example.com") is False


def test_delete_target_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    conn._rowcount = 1
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))
    assert store.delete_target("https://web.ymocode.com/path") is True
    # Sanitized URL used in DELETE
    sql, params = conn.statements[0]
    assert "DELETE FROM manual_targets" in sql
    assert params == ("https://web.ymocode.com",)


def test_delete_targets_bulk(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    conn._rowcount = 2
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))
    n = store.delete_targets(["https://a.example.com/x", "https://b.example.com"])
    assert n == 2


def test_replace_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    returned = {
        "url": "https://web.ymocode.com",
        "host_key": "web.ymocode.com:443",
        "scheme": "https",
        "hostname": "web.ymocode.com",
        "port": 443,
        "enabled": True,
        "notes": "",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
    }

    def execute(sql: str, params: Any = None) -> _FakeCursor:
        conn.statements.append((sql, params))
        if "INSERT INTO manual_targets" in sql:
            conn._last_fetchone = returned
        return _FakeCursor(conn)

    conn.execute = execute  # type: ignore[method-assign]
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))

    result = store.replace_targets("https://web.ymocode.com/login")
    assert result["added"] == 1
    assert any("DELETE FROM manual_targets" in s for s, _ in conn.statements)
    assert conn.committed


def test_list_targets_with_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    conn = _FakeConn()
    conn._last_fetchone = {"n": 1}
    conn._last_fetchall = [
        {
            "url": "https://web.ymocode.com",
            "host_key": "web.ymocode.com:443",
            "scheme": "https",
            "hostname": "web.ymocode.com",
            "port": 443,
            "enabled": True,
            "notes": "",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
        }
    ]
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: _FakePool(conn))
    rows, total = store.list_targets()
    assert total == 1
    assert rows[0]["url"] == "https://web.ymocode.com"
