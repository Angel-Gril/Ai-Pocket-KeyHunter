from __future__ import annotations

import json
import logging
import shutil
from datetime import UTC, datetime
from typing import Any

from psycopg.types.json import Jsonb

from aipocket.core.config import settings
from aipocket.core.models import ValidationResult
from aipocket.services.high_value_writer import _build_entry, should_save

log = logging.getLogger(__name__)

# Ephemeral fields injected at read time — never write them back into JSONB.
_EPHEMERAL_RECORD_KEYS = frozenset(
    {
        "result_id",
        "source_run_id",
        "source_index",
        "created_at",
    }
)


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


def _stored_apikey(record: dict[str, Any]) -> str:
    cred = record.get("credential")
    if isinstance(cred, dict) and cred.get("apikey"):
        return str(cred["apikey"])
    return str(record.get("apikey") or "")


def apply_balance_fields(
    record: dict[str, Any],
    *,
    balance: str,
    tier: str = "",
    gateway: str = "",
    provider_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge live balance probe fields into a stored result/high-value record."""
    out = {k: v for k, v in record.items() if k not in _EPHEMERAL_RECORD_KEYS}
    # Empty balance is a valid outcome (e.g. unsupported gateway) — still clear stale values.
    out["balance"] = balance
    if tier:
        out["tier"] = tier
    if gateway:
        out["gateway"] = gateway
    if provider_evidence is not None:
        out["provider_evidence"] = provider_evidence
        pi = out.get("provider_info")
        if isinstance(pi, dict):
            pi = dict(pi)
            if gateway:
                pi["provider"] = gateway
                pi["validation_provider"] = gateway
            if provider_evidence.get("evidence_kind") == "cash_balance" and gateway:
                pi["balance_provider"] = gateway
            if provider_evidence.get("source"):
                pi["evidence_source"] = provider_evidence["source"]
            if provider_evidence.get("evidence_kind"):
                pi["evidence_kind"] = provider_evidence["evidence_kind"]
            if provider_evidence.get("observed_at"):
                pi["evidence_observed_at"] = provider_evidence["observed_at"]
            out["provider_info"] = pi
    return out


def update_balance_fields(
    *,
    apikey: str,
    balance: str,
    tier: str = "",
    gateway: str = "",
    provider_evidence: dict[str, Any] | None = None,
    result_id: int | None = None,
    high_value: bool = False,
) -> dict[str, Any]:
    """Persist a manual balance probe onto stored rows.

    Updates:
    * the ``results`` row identified by ``result_id`` (when provided)
    * the matching ``high_value_keys`` row when ``high_value`` is set, or when
      the same apikey already exists there (so run-result probes stay in sync)

    Requires PostgreSQL for ``result_id`` updates. High-value-only updates can
    fall back to appending a JSONL line when PG is disabled.
    """
    if not apikey:
        raise ValueError("apikey required")
    if result_id is None and not high_value:
        return {"persisted": False, "result_id": None, "high_value": False, "reason": "no_target"}

    if result_id is not None and not settings.pg_enabled:
        raise RuntimeError("PostgreSQL is required to persist balance on a result")

    updated_result = False
    updated_high_value = False
    fields = {
        "balance": balance,
        "tier": tier,
        "gateway": gateway,
        "provider_evidence": provider_evidence,
    }

    if settings.pg_enabled:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn, conn.transaction():
            if result_id is not None:
                row = conn.execute(
                    """
                    SELECT id, record FROM results WHERE id = %s FOR UPDATE
                    """,
                    (int(result_id),),
                ).fetchone()
                if row is None:
                    raise LookupError(f"result id not found: {result_id}")
                record = dict(row["record"] or {})
                stored = _stored_apikey(record)
                if stored and stored != apikey:
                    raise ValueError("apikey does not match result_id")
                new_record = apply_balance_fields(record, **fields)
                conn.execute(
                    "UPDATE results SET record = %s WHERE id = %s",
                    (Jsonb(new_record), int(result_id)),
                )
                updated_result = True

            # Sync high-value store when requested, or when the key is already there.
            should_touch_hv = high_value
            if not should_touch_hv and result_id is not None:
                exists = conn.execute(
                    "SELECT 1 FROM high_value_keys WHERE apikey = %s",
                    (apikey,),
                ).fetchone()
                should_touch_hv = exists is not None

            if should_touch_hv:
                hv_row = conn.execute(
                    """
                    SELECT apikey, run_id, saved_at, record
                    FROM high_value_keys WHERE apikey = %s FOR UPDATE
                    """,
                    (apikey,),
                ).fetchone()
                if hv_row is None:
                    if high_value:
                        raise LookupError("high-value key not found")
                else:
                    hv_record = dict(hv_row["record"] or {})
                    new_hv = apply_balance_fields(hv_record, **fields)
                    # Keep top-level apikey stable; refresh saved_at for recency sort.
                    new_hv["apikey"] = apikey
                    saved_at = datetime.now(UTC)
                    new_hv["saved_at"] = saved_at.isoformat()
                    conn.execute(
                        """
                        UPDATE high_value_keys
                        SET record = %s, saved_at = %s
                        WHERE apikey = %s
                        """,
                        (Jsonb(new_hv), saved_at, apikey),
                    )
                    updated_high_value = True
    elif high_value:
        # JSONL-only fallback: append an updated entry (load_all dedups last-write-wins).
        from aipocket.services.high_value_writer import _output_path, load_all

        entries = load_all()
        match = next((e for e in entries if str(e.get("apikey") or "") == apikey), None)
        if match is None:
            raise LookupError("high-value key not found")
        new_hv = apply_balance_fields(dict(match), **fields)
        new_hv["apikey"] = apikey
        new_hv["saved_at"] = datetime.now(UTC).isoformat()
        if settings.write_jsonl:
            path = _output_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(new_hv, ensure_ascii=False, default=str) + "\n")
            updated_high_value = True
        else:
            raise RuntimeError("No persistence backend available for high-value balance update")

    return {
        "persisted": updated_result or updated_high_value,
        "result_id": int(result_id) if result_id is not None and updated_result else None,
        "high_value": updated_high_value,
    }


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
