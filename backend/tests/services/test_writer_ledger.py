"""persist_ledger_batch_pg batch insert."""

from __future__ import annotations

from aipocket.core.request_ledger import make_entry
from aipocket.services.writer import persist_ledger_batch_pg


class _FakeCursor:
    def __init__(self):
        self.rows = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None

    def executemany(self, sql, rows):
        self.rows = list(rows)
        self.sql = sql


class _FakeConn:
    def __init__(self):
        self.cur = _FakeCursor()
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None

    def transaction(self):
        return self

    def cursor(self):
        return self.cur

    def execute(self, *a, **k):
        self.executed.append((a, k))


class _FakePool:
    def __init__(self):
        self.conn = _FakeConn()

    def connection(self):
        return self.conn


def test_persist_ledger_batch_empty_is_noop(monkeypatch):
    persist_ledger_batch_pg([])


def test_persist_ledger_batch_inserts_rows(monkeypatch):
    pool = _FakePool()
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    entries = [
        make_entry(
            run_id="run_l",
            stage="discovery",
            source="fofa",
            status_code=200,
            endpoint_class="/api/v1/search/all",
            attempt=1,
        ),
        make_entry(
            run_id="run_l",
            stage="validation",
            source="validator",
            status_code=401,
            attempt=1,
        ),
    ]
    persist_ledger_batch_pg(entries)
    assert pool.conn.cur.rows is not None
    assert len(pool.conn.cur.rows) == 2
    assert "request_ledger" in pool.conn.cur.sql
    # No secret-looking fields in the row tuple values
    flat = " ".join(str(v) for row in pool.conn.cur.rows for v in row)
    assert "sk-" not in flat
