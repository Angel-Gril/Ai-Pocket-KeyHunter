#!/usr/bin/env python
from __future__ import annotations

from typing import Any

from _data_quality_common import main

_HOST = "generativelanguage.googleapis.com"


def run(conn: Any, args: Any) -> dict[str, Any]:
    run_filter = " AND run_id=%s" if args.run_id else ""
    params = (f"%{_HOST}%", args.run_id) if args.run_id else (f"%{_HOST}%",)
    counts: dict[str, int] = {}
    predicates = {
        "results": "apiurl ILIKE %s" + run_filter,
        "high_value_keys": "record->>'apiurl' ILIKE %s" + run_filter,
        "scan_candidates": "apiurl ILIKE %s" + run_filter,
        "scan_validation_results": "record->'credential'->>'apiurl' ILIKE %s" + run_filter,
    }
    affected_runs: set[str] = set()
    for table, predicate in predicates.items():
        if table == "results":
            affected_runs.update(
                str(row["run_id"])
                for row in conn.execute(f"SELECT DISTINCT run_id FROM {table} WHERE {predicate}", params).fetchall()
            )
        count = int(conn.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE {predicate}", params).fetchone()["n"])
        counts[table] = count
        if args.apply and count:
            conn.execute(f"DELETE FROM {table} WHERE {predicate}", params)
    if args.apply:
        for run_id in affected_runs:
            conn.execute(
                """
                UPDATE runs SET
                    total_valid=(SELECT COUNT(*) FROM results WHERE run_id=%s AND kind='valid'),
                    final_verified=(SELECT COUNT(*) FROM results WHERE run_id=%s AND kind='valid'),
                    suspicious=(SELECT COUNT(*) FROM results WHERE run_id=%s AND kind='suspicious'),
                    high_value_final=(SELECT COUNT(*) FROM high_value_keys WHERE run_id=%s)
                WHERE run_id=%s
                """,
                (run_id, run_id, run_id, run_id, run_id),
            )
    counts["affected_runs"] = len(affected_runs)
    return counts


if __name__ == "__main__":
    raise SystemExit(main("Purge Google Generative Language credentials", run))
