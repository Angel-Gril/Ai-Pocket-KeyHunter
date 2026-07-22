#!/usr/bin/env python
from __future__ import annotations

from typing import Any

from _data_quality_common import main
from psycopg.types.json import Jsonb

from aipocket.services.honeypot_store import (
    extract_reason_label,
    is_host_level_honeypot_error,
    normalize_site_key,
)


def run(conn: Any, args: Any) -> dict[str, Any]:
    params: tuple[Any, ...] = (args.run_id,) if args.run_id else ()
    where = " WHERE run_id=%s" if args.run_id else ""
    candidates: dict[str, tuple[str, str]] = {}
    for table in ("results", "scan_validation_results"):
        records = conn.execute(f"SELECT run_id, record FROM {table}{where}", params).fetchall()
        for row in records:
            record = row["record"]
            if not isinstance(record, dict):
                continue
            error = str(record.get("error") or "")
            if not is_host_level_honeypot_error(error):
                continue
            credential = record.get("credential")
            if not isinstance(credential, dict):
                continue
            host_key = normalize_site_key(
                str(credential.get("host") or credential.get("apiurl") or credential.get("leak_host") or "")
            )
            if host_key:
                candidates[host_key] = (extract_reason_label(error), str(row["run_id"]))
    if args.limit > 0:
        candidates = dict(list(candidates.items())[: args.limit])
    if args.apply:
        for host_key, (reason, run_id) in candidates.items():
            record = {"host_key": host_key, "reason": reason, "source": "auto", "run_id": run_id}
            conn.execute(
                """
                INSERT INTO honeypot_sites (host_key, host, reason, source, run_id, record)
                VALUES (%s, %s, %s, 'auto', %s, %s)
                ON CONFLICT (host_key) DO UPDATE SET
                    reason=EXCLUDED.reason, source='auto', run_id=EXCLUDED.run_id,
                    last_seen=NOW(), hit_count=GREATEST(honeypot_sites.hit_count, 1), record=EXCLUDED.record
                """,
                (host_key, host_key, reason, run_id, Jsonb(record)),
            )
    return {"eligible_hosts": len(candidates), "written_hosts": len(candidates) if args.apply else 0}


if __name__ == "__main__":
    raise SystemExit(main("Backfill host-level honeypot cache", run))
