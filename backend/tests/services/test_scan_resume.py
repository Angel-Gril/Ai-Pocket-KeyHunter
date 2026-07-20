"""Phase checkpoint + resume entry-point tests."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.services import scan_checkpoint as sc


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

    def fetchone(self) -> dict[str, Any] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._result)


class FakeConnection:
    def __init__(self, pool: FakePool):
        self._pool = pool
        self.executed = pool.executed
        self.responses = pool.responses

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def transaction(self) -> FakeConnection:
        return self

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        cur = FakeCursor(self)
        cur.execute(sql, params)
        return cur


class FakePool:
    def __init__(self) -> None:
        self.executed: list[tuple] = []
        self.responses: dict[str, list[dict[str, Any]]] = {}

    def connection(self) -> FakeConnection:
        return FakeConnection(self)


@pytest.fixture
def enable_pg(monkeypatch: pytest.MonkeyPatch) -> FakePool:
    pool = FakePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    return pool


def test_mark_phase_updates_runs(enable_pg: FakePool) -> None:
    sc.mark_phase("run_x", sc.PHASE_VALIDATE, validate_cursor=18000)
    assert enable_pg.executed
    sql, params = enable_pg.executed[0]
    assert "UPDATE runs" in sql
    assert "phase" in sql
    assert params[0] == sc.PHASE_VALIDATE
    assert params[-1] == "run_x"


def test_phase_at_least() -> None:
    assert sc.phase_at_least(sc.PHASE_VALIDATE, sc.PHASE_EXTRACT)
    assert not sc.phase_at_least(sc.PHASE_DISCOVERY, sc.PHASE_VALIDATE)
    assert sc.phase_at_least(sc.PHASE_FINISHED, sc.PHASE_VALIDATE)


def test_load_run_state_missing(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = []
    assert sc.load_run_state("missing") is None


def test_load_run_state_found(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [
        {
            "run_id": "run_1",
            "state": "interrupted",
            "phase": sc.PHASE_VALIDATE,
            "phase_detail": {"validate_cursor": 10},
            "scan_mode": "full",
            "started_at": "2026-01-01T00:00:00+00:00",
        }
    ]
    row = sc.load_run_state("run_1")
    assert row is not None
    assert row["phase"] == sc.PHASE_VALIDATE


@pytest.mark.asyncio
async def test_resume_rejects_missing_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr(
        "aipocket.services.scan_checkpoint.load_run_state",
        lambda run_id: None,
    )
    from aipocket.services.scanner import run_scan

    with pytest.raises(RuntimeError, match="not found"):
        await run_scan(resume_run_id="run_nope")


@pytest.mark.asyncio
async def test_resume_rejects_finished_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr(
        "aipocket.services.scan_checkpoint.load_run_state",
        lambda run_id: {
            "run_id": run_id,
            "state": "finished",
            "phase": sc.PHASE_FINISHED,
            "phase_detail": {},
            "scan_mode": "full",
            "started_at": "2026-01-01T00:00:00+00:00",
        },
    )
    from aipocket.services.scanner import run_scan

    with pytest.raises(RuntimeError, match="already finished"):
        await run_scan(resume_run_id="run_done")


def test_cli_resume_run_flag() -> None:
    from typer.testing import CliRunner

    from aipocket.cli import app

    runner = CliRunner()
    # --help includes the flag without running a scan
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--resume-run" in result.output


def test_api_scan_accepts_resume_run_id() -> None:
    from aipocket.api.schemas import ScanStartRequest

    body = ScanStartRequest(resume_run_id="run_2026_07_19_15-57-10")
    assert body.resume_run_id == "run_2026_07_19_15-57-10"


def test_phase_rank_unknown() -> None:
    assert sc.phase_rank("not-a-phase") == -1
    assert sc.phase_rank(sc.PHASE_STARTED) == 0
    assert not sc.phase_at_least("bogus", sc.PHASE_DISCOVERY)


def test_mark_phase_without_detail(enable_pg: FakePool) -> None:
    sc.mark_phase("run_x", sc.PHASE_EXTRACT)
    sql, params = enable_pg.executed[0]
    assert "UPDATE runs SET phase" in sql
    assert "phase_detail" not in sql
    assert params == (sc.PHASE_EXTRACT, "run_x")


def test_mark_phase_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    sc.mark_phase("run_x", sc.PHASE_EXTRACT)  # no raise


def test_mark_phase_swallows_db_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomPool:
        def connection(self):
            raise RuntimeError("down")

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: BoomPool())
    sc.mark_phase("run_x", sc.PHASE_VALIDATE, cursor=1)  # no raise


def test_load_phase_found(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [
        {
            "phase": sc.PHASE_GPT,
            "phase_detail": {"gpt_batch_idx": 12},
            "state": "running",
        }
    ]
    phase, detail = sc.load_phase("run_1")
    assert phase == sc.PHASE_GPT
    assert detail == {"gpt_batch_idx": 12}


def test_load_phase_missing_and_non_dict_detail(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = []
    assert sc.load_phase("missing") == ("", {})

    enable_pg.responses["default"] = [
        {"phase": sc.PHASE_PROBE, "phase_detail": "not-a-dict", "state": "running"}
    ]
    phase, detail = sc.load_phase("run_2")
    assert phase == sc.PHASE_PROBE
    assert detail == {}


def test_load_phase_tuple_row(monkeypatch: pytest.MonkeyPatch) -> None:
    class TupleCursor(FakeCursor):
        def fetchone(self) -> Any:
            return (sc.PHASE_FINALIZE, {"n": 1}, "running")

    class TupleConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return TupleCursor(self)

    class TuplePool(FakePool):
        def connection(self) -> FakeConnection:
            return TupleConn(self)

    pool = TuplePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    phase, detail = sc.load_phase("run_t")
    assert phase == sc.PHASE_FINALIZE
    assert detail == {"n": 1}


def test_load_phase_noop_and_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert sc.load_phase("r") == ("", {})

    class BoomPool:
        def connection(self):
            raise RuntimeError("nope")

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: BoomPool())
    assert sc.load_phase("r") == ("", {})


def test_load_run_state_tuple_and_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class TupleCursor(FakeCursor):
        def fetchone(self) -> Any:
            return (
                "run_t",
                "interrupted",
                sc.PHASE_VALIDATE,
                {"validate_cursor": 3},
                "full",
                "2026-01-01",
            )

    class TupleConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return TupleCursor(self)

    class TuplePool(FakePool):
        def connection(self) -> FakeConnection:
            return TupleConn(self)

    pool = TuplePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    row = sc.load_run_state("run_t")
    assert row is not None
    assert row["run_id"] == "run_t"
    assert row["phase"] == sc.PHASE_VALIDATE
    assert row["phase_detail"]["validate_cursor"] == 3

    class BoomPool:
        def connection(self):
            raise RuntimeError("x")

    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: BoomPool())
    assert sc.load_run_state("run_t") is None


def test_load_run_state_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert sc.load_run_state("r") is None


@pytest.mark.asyncio
async def test_resume_requires_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    from aipocket.services.scanner import run_scan

    with pytest.raises(RuntimeError, match="resume requires"):
        await run_scan(resume_run_id="run_x")


@pytest.mark.asyncio
async def test_resume_validate_skips_discovery(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """phase=validate resume must not call FOFA/Shodan/GitHub discovery clients."""
    from aipocket.core.models import Credential, ValidationResult
    from aipocket.services.scanner import run_scan

    fetch_called: list[str] = []

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "key")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    monkeypatch.setattr("aipocket.services.scan_checkpoint.mark_phase", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.honeypot_store.load_known_host_keys", lambda: set())
    monkeypatch.setattr("aipocket.services.writer.create_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_ledger_batch_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.mark_run_interrupted_pg", lambda *a, **k: None)
    monkeypatch.setattr(
        "aipocket.services.scan_checkpoint.load_run_state",
        lambda run_id: {
            "run_id": run_id,
            "state": "interrupted",
            "phase": sc.PHASE_VALIDATE,
            "phase_detail": {"validate_cursor": 0},
            "scan_mode": "full",
            "started_at": "2026-01-01T00:00:00+00:00",
        },
    )

    async def boom_fetch(*_a, **_k):
        fetch_called.append("fetch_all")
        raise AssertionError("discovery must be skipped on validate resume")

    monkeypatch.setattr("aipocket.discovery.registry.SourceRegistry.fetch_all", boom_fetch)

    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr("aipocket.services.discovery_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.iter_candidate_pages",
        lambda *a, **k: iter(()),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.count_candidates",
        lambda *a, **k: 0,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validation_results",
        lambda *a, **k: [],
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validated_identities",
        lambda *a, **k: set(),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results",
        lambda *a, **k: 0,
    )

    async def fake_validate_from_store(run_id, **kwargs):  # noqa: ANN001
        return [
            ValidationResult(
                credential=Credential(
                    apikey="sk-resume-" + "i" * 32,
                    apiurl="https://resume.example/v1",
                ),
                valid=True,
                validation_state="authentication_confirmed",
            )
        ]

    monkeypatch.setattr(
        "aipocket.services.validator.validate_from_store",
        fake_validate_from_store,
    )
    # Also patch the name scanner imports from inside the branch
    monkeypatch.setattr(
        "aipocket.services.scanner.validate_from_store",
        fake_validate_from_store,
        raising=False,
    )

    result = await run_scan(resume_run_id="run_resume_validate")
    assert fetch_called == []
    assert result is not None


def test_config_validate_batch_size_positive() -> None:
    from pydantic import ValidationError

    from aipocket.core.config import Settings

    assert Settings.model_fields["validate_batch_size"].default == 500
    with pytest.raises(ValidationError):
        Settings(validate_batch_size=0)
    with pytest.raises(ValidationError):
        Settings(validate_batch_size=-1)
