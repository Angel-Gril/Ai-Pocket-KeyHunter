"""Tests for the PostgreSQL persistence paths added alongside the JSONL writers.

These exercise the SQL-shaping logic in the write/read code (writer.persist_run_pg,
high_value_writer PG upsert/load, writer.load_latest, queries.load_cves, and
results_reader's PG branch) WITHOUT a live database. A small in-memory FakePool
stands in for :class:`psycopg_pool.ConnectionPool`: it records every executed
statement and lets each test preload the rows a read query should return, so we
can assert on the SQL/params the code emits and on how it maps rows back.

Why a fake instead of a real Postgres: the suite must stay runnable anywhere
(CI, ``docker run`` without a DB), and these tests are about the code's query
shape, not Postgres semantics. The conftest ``_disable_pg_by_default`` fixture
turns PG off globally; each test here re-enables it by setting ``database_url``
and monkeypatching ``get_pool`` with a FakePool.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from aipocket.core.metrics import (
    ExtractionMethodAggregate,
    QueryFunnel,
    QueryMetric,
    ValidationOutcomeAggregate,
)
from aipocket.core.models import Credential, ValidationResult


# ---------------------------------------------------------------------------
# Fake connection pool
# ---------------------------------------------------------------------------
class FakeCursor:
    """Cursor stand-in supporting execute/executemany + fetchone/fetchall.

    ``responses`` maps an SQL substring → list-of-dict-rows to return for a query
    whose text contains that substring (first match wins). Statements and their
    params are appended to ``executed`` on the owning connection so tests can
    assert on them.
    """

    def __init__(self, conn: FakeConnection):
        self._conn = conn
        self._result: list[dict[str, Any]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        self._conn.executed.append((_norm(sql), params))
        self._result = self._conn._lookup(sql)
        return self

    def executemany(self, sql: str, rows: list[Any]) -> None:
        self._conn.executed.append((_norm(sql), None))
        self._conn.executemany_rows.append((_norm(sql), list(rows)))

    def fetchone(self) -> dict[str, Any] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._result)


class FakeTransaction:
    def __enter__(self) -> FakeTransaction:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class FakeConnection:
    def __init__(self, pool: FakePool):
        self._pool = pool
        self.executed = pool.executed
        self.executemany_rows = pool.executemany_rows
        self.commits = pool.commits

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def _lookup(self, sql: str) -> list[dict[str, Any]]:
        for needle, rows in self._pool.responses.items():
            if needle in sql:
                return rows
        return []

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        cur = FakeCursor(self)
        return cur.execute(sql, params)

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def transaction(self) -> FakeTransaction:
        return FakeTransaction()

    def commit(self) -> None:
        self.commits.append(True)


class FakePool:
    """Minimal ConnectionPool: hands out FakeConnections and records activity."""

    def __init__(self, responses: dict[str, list[dict[str, Any]]] | None = None):
        self.responses = responses or {}
        self.executed: list[tuple[str, Any]] = []
        self.executemany_rows: list[tuple[str, list[Any]]] = []
        self.commits: list[bool] = []

    def connection(self) -> FakeConnection:
        return FakeConnection(self)

    # Helpers -----------------------------------------------------------------
    def sql_containing(self, needle: str) -> list[tuple[str, Any]]:
        return [(s, p) for (s, p) in self.executed if needle in s]


def _norm(sql: str) -> str:
    return " ".join(sql.split())


@pytest.fixture
def fake_pg(monkeypatch):
    """Enable PG (override the conftest disable) and install a FakePool.

    Returns a factory: call ``fake_pg(responses)`` to install a pool preloaded
    with read responses and get it back for assertions.
    """
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x/y")

    def _install(responses: dict[str, list[dict[str, Any]]] | None = None) -> FakePool:
        pool = FakePool(responses)
        monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
        return pool

    return _install


def _vr(
    apikey: str, *, valid: bool = True, status: int = 200, url: str = "https://a.com"
) -> ValidationResult:
    cred = Credential(apikey=apikey, apiurl=url, host="a.com")
    return ValidationResult(credential=cred, valid=valid, status_code=status)


# ---------------------------------------------------------------------------
# writer.persist_run_pg
# ---------------------------------------------------------------------------
class TestPersistRunPg:
    def test_upserts_run_and_inserts_results(self, fake_pg):
        pool = fake_pg()
        from aipocket.services.writer import persist_run_pg

        meta = {
            "started_at": "2026-01-01T00:00:00",
            "finished_at": "2026-01-01T00:01:00",
            "state": "finished",
            "sources": ["fofa"],
            "hits_by_source": {"fofa": 3},
            "queries_used": ["q1"],
            "total_hosts": 3,
            "total_credentials": 2,
        }
        valid = [_vr("sk-proj-aaa"), _vr("sk-proj-bbb")]
        suspicious = [_vr("sk-proj-ccc", status=429)]

        persist_run_pg("run_2026_01_01_00-00-00", meta, valid, suspicious)

        # runs UPSERT ran with total_valid = len(valid).
        run_stmts = pool.sql_containing("INSERT INTO runs")
        assert len(run_stmts) == 1
        assert "ON CONFLICT (run_id) DO UPDATE" in run_stmts[0][0]
        run_params = run_stmts[0][1]
        assert run_params[0] == "run_2026_01_01_00-00-00"
        assert run_params[9] == 2  # total_valid == len(valid)

        # Old rows for the run are deleted first (idempotent re-persist).
        assert pool.sql_containing("DELETE FROM results WHERE run_id")

        # All valid+suspicious rows inserted via one executemany.
        assert len(pool.executemany_rows) == 1
        _sql, rows = pool.executemany_rows[0]
        assert len(rows) == 3  # 2 valid + 1 suspicious
        # seq is 0-based within each (run_id, kind); kind tags the split.
        kinds = [r[1] for r in rows]
        seqs = [r[2] for r in rows]
        assert kinds == ["valid", "valid", "suspicious"]
        assert seqs == [0, 1, 0]

    def test_empty_run_skips_executemany(self, fake_pg):
        pool = fake_pg()
        from aipocket.services.writer import persist_run_pg

        persist_run_pg("run_2026_01_01_00-00-00", {"started_at": "t0"}, [], [])
        assert pool.sql_containing("INSERT INTO runs")
        # No result rows → no executemany call.
        assert pool.executemany_rows == []

    def test_query_metrics_are_replaced_atomically_without_additive_retry(self, fake_pg):
        pool = fake_pg()
        from aipocket.services.writer import persist_run_pg

        metrics = [
            QueryMetric(
                source="fofa",
                query="product=example",
                funnel=QueryFunnel(raw_hits=4, unique_targets=3, final_verified=1),
            )
        ]

        persist_run_pg("run_metrics", {"started_at": "2026-01-01T00:00:00Z"}, [], [], metrics)
        persist_run_pg("run_metrics", {"started_at": "2026-01-01T00:00:00Z"}, [], [], metrics)

        upserts = pool.sql_containing("INSERT INTO query_metrics")
        assert len(upserts) == 2
        assert "ON CONFLICT (run_id, source, query) DO UPDATE" in upserts[0][0]
        assert "raw_hits = EXCLUDED.raw_hits" in upserts[0][0]
        assert "+ EXCLUDED.raw_hits" not in upserts[0][0]
        assert upserts[0][1] == (
            "run_metrics",
            "fofa",
            "product=example",
            4,
            3,
            0,  # active_requests
            0,  # candidates
            0,  # prefilter_survivors
            0,  # auth_confirmed
            1,  # final_verified
            0,  # noauth_rejected
            0,  # query_credits
            2,  # attribution_version
        )

    def test_persists_low_cardinality_outcomes_without_secret_material(self, fake_pg):
        pool = fake_pg()
        from aipocket.services.writer import persist_run_pg

        outcomes = [
            ValidationOutcomeAggregate(
                source="fofa",
                query="q1",
                provider="openai",
                validation_state="final_verified",
                error_class="none",
                status_code=200,
                count=1,
            ),
            ValidationOutcomeAggregate(
                source="fofa",
                query="q1",
                provider="openai",
                validation_state="auth_rejected",
                error_class="auth",
                status_code=401,
                count=1,
            ),
        ]
        methods = [ExtractionMethodAggregate(method="regex", count=2)]
        secret = "sk-proj-must-not-be-persisted"

        persist_run_pg(
            "run_outcomes",
            {"started_at": "2026-01-01T00:00:00Z", "active_requests": 2},
            [],
            [],
            validation_outcomes=outcomes,
            observation_counts=methods,
        )

        outcome_rows = pool.sql_containing("INSERT INTO validation_outcome_aggregates")
        assert len(outcome_rows) == 2
        method_rows = pool.sql_containing("INSERT INTO extraction_method_aggregates")
        assert len(method_rows) == 1
        assert secret not in repr(outcome_rows)
        assert secret not in repr(method_rows)

    def test_outcome_count_mismatch_persists_with_warning(self, fake_pg, caplog):
        """Metrics invariant break must soft-fail — not discard a finished scan."""
        import logging

        pool = fake_pg()
        from aipocket.services.writer import persist_run_pg

        outcomes = [
            ValidationOutcomeAggregate(
                source="fofa",
                query="q1",
                provider="unknown",
                validation_state="transient_error",
                error_class="timeout",
                status_code=None,
                count=1,
            )
        ]
        with caplog.at_level(logging.WARNING, logger="aipocket.services.writer"):
            persist_run_pg(
                "run_bad_outcomes",
                {"started_at": "2026-01-01T00:00:00Z", "active_requests": 2},
                [],
                [],
                validation_outcomes=outcomes,
            )

        assert any("active_requests" in r.message for r in caplog.records)
        # Run + outcome rows still written despite mismatch.
        assert pool.sql_containing("INSERT INTO runs")
        assert pool.sql_containing("INSERT INTO validation_outcome_aggregates")


# ---------------------------------------------------------------------------
# writer.append_results_pg — GPT-failed retry path (append, never replace)
# ---------------------------------------------------------------------------
class TestAppendResultsPg:
    def test_inserts_with_next_seq_never_deletes(self, fake_pg):
        pool = fake_pg(
            {
                "SELECT 1 FROM runs": [{"?column?": 1}],
                "SELECT COALESCE(MAX(seq)": [{"m": 4}],
            }
        )
        from aipocket.services.writer import append_results_pg

        valid = [_vr("sk-new-aaa")]
        suspicious = [_vr("sk-new-bbb", status=429)]
        append_results_pg("run_2026_07_15_14-44-29", valid, suspicious)

        # Must NOT wipe existing result rows (unlike persist_run_pg).
        assert pool.sql_containing("DELETE FROM results") == []

        assert len(pool.executemany_rows) == 2
        kinds_and_seqs = []
        for _sql, rows in pool.executemany_rows:
            for row in rows:
                kinds_and_seqs.append((row[1], row[2]))  # kind, seq
        assert ("valid", 5) in kinds_and_seqs  # MAX was 4 → next 5
        assert ("suspicious", 5) in kinds_and_seqs

        updates = pool.sql_containing("UPDATE runs SET")
        assert len(updates) == 1
        assert "total_valid" in updates[0][0]

    def test_missing_run_raises(self, fake_pg):
        pool = fake_pg({"SELECT 1 FROM runs": []})
        from aipocket.services.writer import append_results_pg

        with pytest.raises(LookupError, match="not in PG"):
            append_results_pg("run_2026_07_15_14-44-29", [_vr("sk-x")], [])
        assert pool.executemany_rows == []


# ---------------------------------------------------------------------------
# high_value_writer PG paths
# ---------------------------------------------------------------------------
class TestHighValuePg:
    @pytest.fixture(autouse=True)
    def _reset(self):
        from aipocket.services.high_value_writer import reset_session

        reset_session()
        yield
        reset_session()

    def test_save_upserts_and_skips_jsonl(self, fake_pg, tmp_path, monkeypatch):
        pool = fake_pg()
        # PG on + dual-write off ⇒ write_jsonl is False, so no file is written.
        monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
        from aipocket.services.high_value_writer import save_high_value_key

        r = _vr("sk-proj-highvalue123", url="https://api.openai.com")
        assert save_high_value_key(r, run_id="run_2026_01_01_00-00-00") is True

        upserts = pool.sql_containing("INSERT INTO high_value_keys")
        assert len(upserts) == 1
        assert "ON CONFLICT (apikey) DO UPDATE" in upserts[0][0]
        params = upserts[0][1]
        assert params[0] == "sk-proj-highvalue123"  # apikey
        assert params[1] == "run_2026_01_01_00-00-00"  # run_id
        assert pool.commits  # committed

        # write_jsonl False → no keys.jsonl on disk.
        assert not (tmp_path / "high_value_keys" / "keys.jsonl").exists()

    def test_dual_write_writes_both(self, fake_pg, tmp_path, monkeypatch):
        pool = fake_pg()
        monkeypatch.setattr("aipocket.core.config.settings.pg_dual_write", True)
        monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
        from aipocket.services.high_value_writer import save_high_value_key

        assert save_high_value_key(_vr("sk-ant-dualwrite12"), run_id="r1") is True

        assert pool.sql_containing("INSERT INTO high_value_keys")  # PG hit
        path = tmp_path / "high_value_keys" / "keys.jsonl"
        assert path.exists()  # AND JSONL written
        data = json.loads(path.read_text(encoding="utf-8").strip())
        assert data["apikey"] == "sk-ant-dualwrite12"
        assert data["run_id"] == "r1"

    def test_load_all_reads_pg(self, fake_pg):
        rows = [
            {"record": {"apikey": "sk-proj-one", "status_code": 200}},
            {"record": {"apikey": "sk-ant-two", "status_code": 429}},
        ]
        fake_pg({"FROM high_value_keys": rows})
        from aipocket.services.high_value_writer import load_all

        loaded = load_all()
        assert [e["apikey"] for e in loaded] == ["sk-proj-one", "sk-ant-two"]


# ---------------------------------------------------------------------------
# writer.load_latest (PG branch)
# ---------------------------------------------------------------------------
class TestLoadLatestPg:
    def test_reads_newest_run_valid_records(self, fake_pg):
        fake_pg(
            {
                "SELECT run_id FROM runs": [{"run_id": "run_2026_07_06_10-00-00"}],
                "FROM results WHERE run_id": [
                    {"record": {"credential": {"apikey": "sk-proj-latest"}, "valid": True}},
                ],
            }
        )
        from aipocket.services.writer import load_latest

        out = load_latest()
        assert out is not None
        assert out[0]["credential"]["apikey"] == "sk-proj-latest"

    def test_returns_none_when_no_runs(self, fake_pg):
        fake_pg({"SELECT run_id FROM runs": []})
        from aipocket.services.writer import load_latest

        assert load_latest() is None


# ---------------------------------------------------------------------------
# queries.load_cves (PG branch + empty-table fallback)
# ---------------------------------------------------------------------------
class TestLoadCvesPg:
    def test_reads_cves_from_pg(self, fake_pg):
        # PG rows are merged with the file by id (PG wins on conflict), so a
        # partial-but-non-empty PG table no longer shadows the full file set.
        rows = [{"record": {"id": "CVE-2026-1", "product": "Dify"}}]
        fake_pg({"FROM cves": rows})
        from aipocket.services.queries import load_cves

        cves = load_cves()
        # PG row is present and wins over any same-id file entry.
        by_id = {c["id"]: c for c in cves}
        assert by_id["CVE-2026-1"] == {"id": "CVE-2026-1", "product": "Dify"}
        # File's full set is also present (result is the union), sorted by id.
        assert len(cves) > 1
        assert cves == sorted(cves, key=lambda c: c.get("id", ""))

    def test_empty_table_falls_back_to_file(self, fake_pg):
        # Empty cves table → load_cves reads the bundled CVE file instead.
        fake_pg({"FROM cves": []})
        from aipocket.services.queries import load_cves

        cves = load_cves()
        assert isinstance(cves, list)
        assert len(cves) > 0
        assert "id" in cves[0]

    def test_explicit_path_bypasses_pg(self, fake_pg, tmp_path):
        pool = fake_pg({"FROM cves": [{"record": {"id": "should-not-be-used"}}]})
        p = tmp_path / "cves.json"
        p.write_text(json.dumps([{"id": "CVE-FILE", "product": "X"}]), encoding="utf-8")
        from aipocket.services.queries import load_cves

        cves = load_cves(p)
        assert cves == [{"id": "CVE-FILE", "product": "X"}]
        assert pool.executed == []  # PG never touched when a path is given


# ---------------------------------------------------------------------------
# results_reader PG branch
# ---------------------------------------------------------------------------
class TestResultsReaderPg:
    def test_list_runs_uses_pg_aggregation(self, fake_pg):
        import datetime as _dt

        started = _dt.datetime(2026, 7, 6, 10, 0, 0)
        fake_pg(
            {
                "FROM runs ORDER BY run_id DESC": [
                    {
                        "run_id": "run_2026_07_06_10-00-00",
                        "started_at": started,
                        "total_hosts": 5,
                        "total_credentials": 13,
                        "total_valid": 2,
                        "raw_hits": 23,
                        "unique_targets": 17,
                        "candidates": 11,
                        "active_requests": 7,
                        "final_verified": 3,
                        "suspicious": 2,
                        "high_value_final": 1,
                        "sources": ["fofa", "shodan"],
                        "has_log": True,
                    }
                ],
                "GROUP BY run_id, kind": [
                    {"run_id": "run_2026_07_06_10-00-00", "kind": "valid", "n": 2},
                    {"run_id": "run_2026_07_06_10-00-00", "kind": "suspicious", "n": 1},
                ],
                "FROM high_value_keys": [{"run_id": "run_2026_07_06_10-00-00", "n": 1}],
                "regexp_split_to_table": [
                    {"run_id": "run_2026_07_06_10-00-00", "backend": "fofa"},
                    {"run_id": "run_2026_07_06_10-00-00", "backend": "shodan"},
                ],
            }
        )
        from aipocket.api import results_reader

        days = results_reader.list_runs()
        assert days[0]["day"] == "2026-07-06"
        entry = days[0]["runs"][0]
        assert entry["valid_count"] == 2
        assert entry["suspicious_count"] == 1
        assert entry["raw_hits"] == 23
        assert entry["unique_targets"] == 17
        assert entry["candidates"] == 11
        assert entry["active_requests"] == 7
        # Live results counts win over stale funnel columns (final_verified=3).
        assert entry["final_verified"] == 2
        assert entry["suspicious"] == 1
        assert entry["high_value_final"] == 1
        assert entry["sources"] == ["fofa", "shodan"]

    def test_list_runs_falls_back_when_funnel_columns_are_zero(self, fake_pg):
        """Pre-funnel imports: raw_hits=0 but total_hosts / results still set."""
        import datetime as _dt

        started = _dt.datetime(2026, 7, 7, 14, 57, 50)
        fake_pg(
            {
                "FROM runs ORDER BY run_id DESC": [
                    {
                        "run_id": "run_2026_07_07_14-57-50",
                        "started_at": started,
                        "total_hosts": 1200,
                        "total_credentials": 40,
                        "total_valid": 9,
                        "raw_hits": 0,
                        "unique_targets": 0,
                        "candidates": 0,
                        "active_requests": 0,
                        "final_verified": 0,
                        "suspicious": 0,
                        "high_value_final": 0,
                        "sources": ["fofa", "shodan"],
                        "has_log": True,
                    }
                ],
                "GROUP BY run_id, kind": [
                    {"run_id": "run_2026_07_07_14-57-50", "kind": "valid", "n": 9},
                    {"run_id": "run_2026_07_07_14-57-50", "kind": "suspicious", "n": 9},
                ],
                "FROM high_value_keys": [
                    {"run_id": "run_2026_07_07_14-57-50", "n": 2},
                ],
                "regexp_split_to_table": [
                    {"run_id": "run_2026_07_07_14-57-50", "backend": "fofa"},
                    {"run_id": "run_2026_07_07_14-57-50", "backend": "shodan"},
                ],
            }
        )
        from aipocket.api import results_reader

        entry = results_reader.list_runs()[0]["runs"][0]
        assert entry["raw_hits"] == 1200  # total_hosts fallback
        assert entry["unique_targets"] == 1200
        assert entry["candidates"] == 40
        assert entry["final_verified"] == 9  # total_valid / results count
        assert entry["suspicious"] == 9
        assert entry["high_value_final"] == 2
        assert entry["sources"] == ["fofa", "shodan"]

    def test_load_kind_prefers_pg_when_run_exists(self, fake_pg):
        fake_pg(
            {
                "SELECT 1 FROM runs WHERE run_id": [{"?column?": 1}],
                "FROM results WHERE run_id": [
                    {"record": {"credential": {"apikey": "sk-proj-pgrec"}, "valid": True}}
                ],
            }
        )
        from aipocket.api import results_reader

        recs = results_reader.load_run_records_plain("run_2026_07_06_10-00-00", "valid")
        assert recs[0]["credential"]["apikey"] == "sk-proj-pgrec"

    def test_load_all_stamps_dense_source_index_not_raw_seq(self, fake_pg):
        """source_index must be 0..n-1 within each run, even when seq is sparse."""
        fake_pg(
            {
                "FROM results": [
                    {
                        "run_id": "run_2026_07_15_14-44-29",
                        "record": {"credential": {"apikey": "sk-proj-aaaa1111aaaa"}},
                    },
                    {
                        "run_id": "run_2026_07_15_14-44-29",
                        "record": {"credential": {"apikey": "sk-proj-bbbb2222bbbb"}},
                    },
                    {
                        "run_id": "run_2026_07_15_14-44-29",
                        "record": {"credential": {"apikey": "sk-proj-cccc3333cccc"}},
                    },
                ],
            }
        )
        from aipocket.api import results_reader

        plain = results_reader.load_all_records_plain("valid")
        assert [r["source_index"] for r in plain] == [0, 1, 2]
        assert all(r["source_run_id"] == "run_2026_07_15_14-44-29" for r in plain)

    def test_reveal_falls_back_to_sparse_seq(self, fake_pg):
        """Legacy All-Keys clients may still send source_index == raw seq."""
        target = {
            "credential": {
                "apikey": "sk-proj-legacyseqkey99",
                "apiurl": "https://api.openai.com/v1",
            }
        }
        fake_pg(
            {
                "SELECT 1 FROM runs WHERE run_id": [{"?column?": 1}],
                # Dense list for array-index path (only 1 row → index 1001 OOB)
                "ORDER BY seq": [
                    {"record": {"credential": {"apikey": "sk-proj-otherkey0000"}}},
                ],
                # Direct seq lookup for legacy index=1001
                "AND seq =": [{"record": target}],
            }
        )
        from aipocket.api import results_reader

        found = results_reader.reveal_apikey(
            "run_2026_07_15_14-44-29", "valid", index=1001
        )
        assert found["apikey"] == "sk-proj-legacyseqkey99"
        assert found["apiurl"] == "https://api.openai.com/v1"

    def test_read_run_log_from_pg(self, fake_pg):
        fake_pg(
            {
                "SELECT 1 FROM runs WHERE run_id": [{"?column?": 1}],
                "SELECT log FROM runs WHERE run_id": [{"log": "line-a\nline-b"}],
            }
        )
        from aipocket.api import results_reader

        assert results_reader.read_run_log("run_2026_07_06_10-00-00") == "line-a\nline-b"
