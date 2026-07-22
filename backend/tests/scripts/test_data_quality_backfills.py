from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT_DIR = Path(__file__).parents[2] / "scripts" / "oneoff"
sys.path.insert(0, str(SCRIPT_DIR))

import _data_quality_common as common  # noqa: E402
import backfill_honeypot_sites  # noqa: E402
import canonicalize_endpoints  # noqa: E402
import delete_empty_runs  # noqa: E402
import purge_google_generative_language  # noqa: E402
import reclassify_providers  # noqa: E402


class Cursor:
    def __init__(self, rows: list[dict]):
        self.rows = rows

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


class Conn:
    def __init__(self, rows: list[dict] | None = None):
        self.rows = rows or []
        self.executed: list[tuple[str, object]] = []

    def execute(self, sql: str, params=()):
        self.executed.append((sql, params))
        return Cursor(self.rows)


def args(*, apply: bool = False, run_id: str = "", limit: int = 0):
    return SimpleNamespace(apply=apply, dry_run=not apply, run_id=run_id, limit=limit)


@pytest.mark.parametrize(
    "module",
    [canonicalize_endpoints, reclassify_providers, purge_google_generative_language, backfill_honeypot_sites, delete_empty_runs],
)
def test_all_five_repairs_expose_run_and_default_dry_run(module) -> None:
    assert callable(module.run)
    parsed = common.parser(module.__name__).parse_args([])
    assert parsed.apply is False
    assert parsed.dry_run is False


def test_repair_cli_rejects_conflicting_modes() -> None:
    with pytest.raises(SystemExit):
        common.parser("repair").parse_args(["--apply", "--dry-run"])


def test_backfill_honeypot_dry_run_has_no_write_and_apply_is_idempotent() -> None:
    rows = [
        {
            "run_id": "run_2026_07_22_00-00-00",
            "record": {
                "error": "honeypot:steganography",
                "credential": {"host": "https://Evil.Example:8443/v1"},
            },
        }
    ]
    dry_conn = Conn(rows)
    dry_summary = backfill_honeypot_sites.run(dry_conn, args())
    assert dry_summary == {"eligible_hosts": 1, "written_hosts": 0}
    assert not any("INSERT INTO honeypot_sites" in sql for sql, _ in dry_conn.executed)

    apply_conn = Conn(rows)
    apply_summary = backfill_honeypot_sites.run(apply_conn, args(apply=True))
    assert apply_summary == {"eligible_hosts": 1, "written_hosts": 1}
    sql = "\n".join(statement for statement, _ in apply_conn.executed)
    assert "ON CONFLICT (host_key) DO UPDATE SET" in sql
    assert "GREATEST(honeypot_sites.hit_count, 1)" in sql


def test_delete_empty_runs_only_deletes_in_apply_mode() -> None:
    row = {"run_id": "run_2026_07_22_00-00-00"}
    dry_conn = Conn([row])
    assert delete_empty_runs.run(dry_conn, args()) == {"candidates": 1, "deleted": 0}
    assert not any("DELETE FROM runs" in sql for sql, _ in dry_conn.executed)

    apply_conn = Conn([row])
    assert delete_empty_runs.run(apply_conn, args(apply=True)) == {"candidates": 1, "deleted": 1}
    assert any("DELETE FROM runs" in sql for sql, _ in apply_conn.executed)


def test_google_purge_counts_without_mutating_in_dry_run() -> None:
    class PurgeConn(Conn):
        def execute(self, sql: str, params=()):
            self.executed.append((sql, params))
            if "SELECT DISTINCT run_id" in sql:
                return Cursor([{"run_id": "run_google"}])
            if "COUNT(*)" in sql:
                return Cursor([{"n": 2}])
            return Cursor([])

    conn = PurgeConn()
    summary = purge_google_generative_language.run(conn, args())
    assert summary["affected_runs"] == 1
    assert summary["results"] == 2
    assert not any("DELETE FROM" in sql for sql, _ in conn.executed)
