from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from typing import Any

from psycopg.types.json import Jsonb

from aipocket.core.config import settings
from aipocket.core.models import ValidationResult
from aipocket.services.high_value_writer import _build_entry, should_save

log = logging.getLogger(__name__)


def run_is_deletable(metrics: dict[str, Any]) -> bool:
    return all(
        int(metrics.get(field) or 0) == 0
        for field in (
            "raw_hits",
            "unique_targets",
            "final_verified",
            "suspicious",
            "high_value_final",
        )
    )


def _result_from_record(record: dict[str, Any]) -> ValidationResult:
    allowed = {key: value for key, value in record.items() if key in ValidationResult.model_fields}
    return ValidationResult(**allowed)


def promote_results(result_ids: list[int], note: str = "") -> dict[str, list[int]]:
    if not settings.pg_enabled:
        raise RuntimeError("PostgreSQL is required for promotion")
    from aipocket.core.db import get_pool

    ids = list(dict.fromkeys(int(value) for value in result_ids))
    promoted_at = datetime.now(UTC)
    promoted: list[int] = []
    skipped: list[int] = []
    pool = get_pool()
    with pool.connection() as conn, conn.transaction():
        rows = conn.execute(
            """
            SELECT id, run_id, kind, record, created_at
            FROM results
            WHERE id = ANY(%s)
            ORDER BY run_id, id
            FOR UPDATE
            """,
            (ids,),
        ).fetchall()
        found = {int(row["id"]) for row in rows}
        missing = set(ids) - found
        if missing:
            raise LookupError(f"result ids not found: {sorted(missing)}")
        if any(row["kind"] != "suspicious" for row in rows):
            conflict_ids = [int(row["id"]) for row in rows if row["kind"] != "suspicious"]
            raise ValueError(f"results are not suspicious: {conflict_ids}")

        next_seq: dict[str, int] = {}
        for row in rows:
            run_id = str(row["run_id"])
            if run_id not in next_seq:
                conn.execute("SELECT 1 FROM runs WHERE run_id=%s FOR UPDATE", (run_id,))
                seq_row = conn.execute(
                    """
                    SELECT COALESCE(MAX(seq), -1) + 1 AS next_seq
                    FROM results WHERE run_id = %s AND kind = 'valid'
                    """,
                    (run_id,),
                ).fetchone()
                next_seq[run_id] = int(seq_row["next_seq"] if seq_row else 0)
            record = dict(row["record"])
            record["previous_validation_state"] = str(record.get("validation_state") or "")
            record["promoted_at"] = promoted_at.isoformat()
            record["promoted_by"] = "manual"
            record["promotion_note"] = note
            record["validation_state"] = "final_verified"
            record["valid"] = True
            record["suspicious"] = False
            record["suspicious_reason"] = ""
            seq = next_seq[run_id]
            next_seq[run_id] += 1
            conn.execute(
                """
                UPDATE results
                SET kind = 'valid', seq = %s, valid = TRUE, record = %s
                WHERE id = %s AND kind = 'suspicious'
                """,
                (seq, Jsonb(record), row["id"]),
            )
            promoted.append(int(row["id"]))

            result = _result_from_record(record)
            if should_save(result):
                entry = _build_entry(result, run_id)
                entry["saved_at"] = promoted_at.isoformat()
                conn.execute(
                    """
                    INSERT INTO high_value_keys (apikey, run_id, saved_at, record)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (apikey) DO UPDATE SET
                        run_id = EXCLUDED.run_id,
                        saved_at = EXCLUDED.saved_at,
                        record = EXCLUDED.record
                    """,
                    (result.credential.apikey, run_id, promoted_at, Jsonb(entry)),
                )

        for run_id in next_seq:
            conn.execute(
                """
                UPDATE runs SET
                    total_valid = (SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'valid'),
                    final_verified = (SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'valid'),
                    suspicious = (SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'suspicious'),
                    high_value_final = (SELECT COUNT(*) FROM high_value_keys WHERE run_id = %s)
                WHERE run_id = %s
                """,
                (run_id, run_id, run_id, run_id, run_id),
            )
    return {"promoted": promoted, "skipped": skipped}


def delete_run(run_id: str) -> dict[str, Any]:
    if not settings.pg_enabled:
        raise RuntimeError("PostgreSQL is required for run deletion")
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction():
        row = conn.execute(
            """
            SELECT run_id, raw_hits, unique_targets,
                   (SELECT COUNT(*) FROM results WHERE run_id = runs.run_id AND kind = 'valid') AS final_verified,
                   (SELECT COUNT(*) FROM results WHERE run_id = runs.run_id AND kind = 'suspicious') AS suspicious,
                   (SELECT COUNT(*) FROM high_value_keys WHERE run_id = runs.run_id) AS high_value_final
            FROM runs WHERE run_id = %s
            FOR UPDATE
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise LookupError(run_id)
        if not run_is_deletable(dict(row)):
            raise ValueError("run is not empty")
        conn.execute("DELETE FROM runs WHERE run_id = %s", (run_id,))

    disk_removed = False
    run_dir = (settings.results_path / run_id).resolve()
    root = settings.results_path.resolve()
    try:
        if run_dir.parent != root or run_dir.name != run_id:
            raise ValueError("invalid run path")
        if run_dir.exists():
            shutil.rmtree(run_dir)
            disk_removed = True
    except Exception as exc:  # noqa: BLE001 - disk is secondary to committed PG state
        log.warning("run %s deleted from PG but disk cleanup failed: %s", run_id, exc)
    return {"run_id": run_id, "deleted": True, "disk_removed": disk_removed}
