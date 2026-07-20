"""Unit tests for scan_discovery_hits spill / page load."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.services import discovery_store as ds


class FakeCursor:
    def __init__(self, conn: FakeConnection):
        self._conn = conn
        self._result: list[dict[str, Any]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        self._conn.executed.append((sql, params))
        self._result = self._conn.responses.get("default", [])
        return self

    def executemany(self, sql: str, rows: list[Any]) -> None:
        self._conn.executed.append((sql, None))
        self._conn.executemany_rows.append((sql, list(rows)))

    def fetchone(self) -> dict[str, Any] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._result)


class FakeConnection:
    def __init__(self, pool: FakePool):
        self._pool = pool
        self.executed = pool.executed
        self.executemany_rows = pool.executemany_rows
        self.responses = pool.responses

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def transaction(self) -> FakeConnection:
        return self


class FakePool:
    def __init__(self) -> None:
        self.executed: list[tuple] = []
        self.executemany_rows: list[tuple] = []
        self.responses: dict[str, list[dict[str, Any]]] = {}

    def connection(self) -> FakeConnection:
        return FakeConnection(self)


@pytest.fixture
def enable_pg(monkeypatch: pytest.MonkeyPatch) -> FakePool:
    pool = FakePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    assert ds.spill_enabled()
    return pool


def test_upsert_hits_writes_full_body_banner_header(enable_pg: FakePool) -> None:
    body = "x" * 100_000
    hits = [
        {
            "host": "https://example.com",
            "ip": "1.2.3.4",
            "port": "443",
            "protocol": "https",
            "header": "Server: nginx",
            "banner": "HTTP/1.1 200",
            "body": body,
            "_source": "fofa",
            "_query_id": "q1",
        }
    ]
    n = ds.upsert_hits("run_test", "fofa", hits)
    assert n == 1
    assert enable_pg.executemany_rows
    sql, rows = enable_pg.executemany_rows[0]
    assert "INSERT INTO scan_discovery_hits" in sql
    # Jsonb wrapper — extract underlying dict
    record = rows[0][-1]
    payload = getattr(record, "obj", record)
    if hasattr(payload, "obj"):
        payload = payload.obj
    assert isinstance(payload, dict)
    assert payload["body"] == body
    assert payload["banner"] == "HTTP/1.1 200"
    assert payload["header"] == "Server: nginx"
    assert len(payload["body"]) == 100_000


def test_upsert_hits_noop_when_pg_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert not ds.spill_enabled()
    n = ds.upsert_hits("r", "fofa", [{"host": "https://x"}])
    assert n == 0


def test_iter_hits_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    # Simulate 3 pages of 500 with keyset paging.
    pages = [
        [{"id": i, "record": {"host": f"h{i}", "body": f"b{i}"}} for i in range(1, 501)],
        [{"id": i, "record": {"host": f"h{i}", "body": f"b{i}"}} for i in range(501, 1001)],
        [{"id": i, "record": {"host": f"h{i}", "body": f"b{i}"}} for i in range(1001, 1201)],
    ]
    call = {"n": 0}

    class PagingCursor(FakeCursor):
        def execute(self, sql: str, params: Any = None) -> FakeCursor:
            self._conn.executed.append((sql, params))
            idx = call["n"]
            call["n"] += 1
            self._result = pages[idx] if idx < len(pages) else []
            return self

    class PagingConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return PagingCursor(self)

    class PagingPool(FakePool):
        def connection(self) -> FakeConnection:
            return PagingConn(self)

    pool = PagingPool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    got = list(ds.iter_hits("run_x", batch_size=500))
    assert len(got) == 3
    assert len(got[0]) == 500
    assert len(got[1]) == 500
    assert len(got[2]) == 200
    assert got[0][0]["body"] == "b1"


def test_upsert_hits_dedupes_entry_id(enable_pg: FakePool) -> None:
    hit = {
        "host": "https://same.example.com",
        "port": "443",
        "protocol": "https",
        "body": "first",
    }
    ds.upsert_hits("run_d", "fofa", [hit])
    hit2 = {**hit, "body": "second-longer-body-xxxxx"}
    ds.upsert_hits("run_d", "fofa", [hit2])
    # Both upserts attempted; SQL has ON CONFLICT on (run_id, entry_id)
    assert len(enable_pg.executemany_rows) == 2
    sql, _ = enable_pg.executemany_rows[0]
    assert "ON CONFLICT (run_id, entry_id)" in sql
    eid1 = ds.entry_id_for_hit(hit)
    eid2 = ds.entry_id_for_hit(hit2)
    assert eid1 == eid2


def test_count_hits(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"n": 42}]
    assert ds.count_hits("run_c") == 42


def test_no_truncation_of_body_roundtrip(enable_pg: FakePool) -> None:
    body = "secret-sk-test-" + ("Z" * 50_000)
    hits = [{"host": "https://body.example", "protocol": "https", "port": "443", "body": body}]
    ds.upsert_hits("run_b", "fofa", hits)
    _sql, rows = enable_pg.executemany_rows[0]
    record = rows[0][-1]
    payload = getattr(record, "obj", record)
    if hasattr(payload, "obj"):
        payload = payload.obj
    assert len(payload["body"]) == len(body)
    assert payload["body"] == body


def test_spill_path_requires_run_id(enable_pg: FakePool) -> None:
    assert ds.upsert_hits("", "fofa", [{"host": "https://x"}]) == 0
    assert not enable_pg.executemany_rows


def test_slim_hit_drops_body() -> None:
    slim = ds.slim_hit_for_target(
        {
            "host": "https://x",
            "header": "H",
            "banner": "B",
            "body": "huge",
            "_source": "fofa",
        }
    )
    assert "body" not in slim
    assert slim["header"] == "H"
    assert slim["banner"] == "B"


def test_slim_hit_truncates_large_header_banner() -> None:
    huge = "H" * 20_000
    slim = ds.slim_hit_for_target({"host": "https://x", "header": huge, "banner": huge})
    assert len(slim["header"]) == 16_384
    assert len(slim["banner"]) == 16_384


def test_entry_id_fallback_when_identity_missing() -> None:
    # No host/link → _identity returns None → SHA1 fallback
    hit = {"ip": "10.0.0.1", "port": "8080"}
    eid = ds.entry_id_for_hit(hit)
    assert isinstance(eid, str) and len(eid) == 40
    assert eid == ds.entry_id_for_hit(hit)


def test_entry_id_stable_for_normal_host() -> None:
    hit = {"host": "https://stable.example.com", "port": "443", "protocol": "https"}
    assert ds.entry_id_for_hit(hit) == ds.entry_id_for_hit(dict(hit))


def test_upsert_hits_skips_non_dict_and_empty(enable_pg: FakePool) -> None:
    assert ds.upsert_hits("run_e", "fofa", []) == 0
    assert ds.upsert_hits("run_e", "fofa", ["not-a-dict", 42]) == 0  # type: ignore[list-item]
    assert not enable_pg.executemany_rows


def test_upsert_hits_uses_hit_source_fallback(enable_pg: FakePool) -> None:
    n = ds.upsert_hits(
        "run_s",
        "",
        [{"host": "https://src.example", "protocol": "https", "port": "443", "_source": "shodan"}],
    )
    assert n == 1
    _sql, rows = enable_pg.executemany_rows[0]
    assert rows[0][1] == "shodan"


def test_iter_hits_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert list(ds.iter_hits("run_x")) == []


def test_iter_hits_empty_table(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = []
    assert list(ds.iter_hits("run_empty", batch_size=10)) == []


def test_iter_hits_filters_by_source(monkeypatch: pytest.MonkeyPatch) -> None:
    call = {"params": None}

    class SrcCursor(FakeCursor):
        def execute(self, sql: str, params: Any = None) -> FakeCursor:
            call["params"] = params
            self._conn.executed.append((sql, params))
            self._result = [{"id": 1, "record": {"host": "https://a", "_source": "fofa"}}]
            return self

    class SrcConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return SrcCursor(self)

    class SrcPool(FakePool):
        def connection(self) -> FakeConnection:
            return SrcConn(self)

    pool = SrcPool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    pages = list(ds.iter_hits("run_f", source="fofa", batch_size=10))
    assert len(pages) == 1
    assert call["params"] is not None
    assert "fofa" in call["params"]
    # Non-dict records are skipped
    assert pages[0][0]["host"] == "https://a"


def test_iter_hits_skips_non_dict_records(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadCursor(FakeCursor):
        def execute(self, sql: str, params: Any = None) -> FakeCursor:
            self._conn.executed.append((sql, params))
            self._result = [
                {"id": 1, "record": "not-a-dict"},
                {"id": 2, "record": {"host": "https://ok"}},
            ]
            return self

    class BadConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return BadCursor(self)

    class BadPool(FakePool):
        def connection(self) -> FakeConnection:
            return BadConn(self)

    pool = BadPool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    pages = list(ds.iter_hits("run_bad", batch_size=50))
    assert len(pages) == 1
    assert pages[0] == [{"host": "https://ok"}]


def test_count_hits_with_source_and_empty(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"n": 7}]
    assert ds.count_hits("run_c", source="fofa") == 7
    enable_pg.responses["default"] = []
    assert ds.count_hits("run_c") == 0


def test_count_hits_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert ds.count_hits("run_c") == 0


def test_load_hit_found_and_missing(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"record": {"host": "https://one", "body": "FULL"}}]
    hit = ds.load_hit("run_l", "entry-1")
    assert hit is not None
    assert hit["body"] == "FULL"

    enable_pg.responses["default"] = []
    assert ds.load_hit("run_l", "entry-missing") is None
    assert ds.load_hit("run_l", "") is None
    assert ds.load_hit("", "entry-1") is None


def test_load_hit_tuple_row(enable_pg: FakePool, monkeypatch: pytest.MonkeyPatch) -> None:
    class TupleCursor(FakeCursor):
        def fetchone(self) -> Any:
            return ({"host": "https://t", "body": "B"},)

    class TupleConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return TupleCursor(self)

    class TuplePool(FakePool):
        def connection(self) -> FakeConnection:
            return TupleConn(self)

    pool = TuplePool()
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    hit = ds.load_hit("run_t", "eid")
    assert hit == {"host": "https://t", "body": "B"}


def test_load_hit_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert ds.load_hit("run_l", "e") is None


def test_load_hits_by_entry_ids(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [
        {"entry_id": "e1", "record": {"host": "https://a", "body": "A"}},
        {"entry_id": "e2", "record": {"host": "https://b", "body": "B"}},
        {"entry_id": "e3", "record": "bad"},
    ]
    out = ds.load_hits_by_entry_ids("run_m", ["e1", "e2", "e3", ""])
    assert set(out) == {"e1", "e2"}
    assert out["e1"]["body"] == "A"
    assert out["e2"]["body"] == "B"


def test_load_hits_by_entry_ids_empty_and_disabled(
    enable_pg: FakePool, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert ds.load_hits_by_entry_ids("run_m", []) == {}
    assert ds.load_hits_by_entry_ids("run_m", ["", ""]) == {}
    assert ds.load_hits_by_entry_ids("", ["e1"]) == {}
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert ds.load_hits_by_entry_ids("run_m", ["e1"]) == {}
