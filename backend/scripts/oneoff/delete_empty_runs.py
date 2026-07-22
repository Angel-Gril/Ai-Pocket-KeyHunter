#!/usr/bin/env python
from __future__ import annotations

from typing import Any

from _data_quality_common import main


def run(conn: Any, args: Any) -> dict[str, Any]:
    params: list[Any] = []
    where = ""
    if args.run_id:
        where = " WHERE r.run_id=%s"
        params.append(args.run_id)
    sql = f"""
        SELECT r.run_id
        FROM runs r
        LEFT JOIN LATERAL (
            SELECT COUNT(*) FILTER (WHERE kind='valid') AS valid,
                   COUNT(*) FILTER (WHERE kind='suspicious') AS suspicious
            FROM results WHERE run_id=r.run_id
        ) result_counts ON TRUE
        LEFT JOIN LATERAL (
            SELECT COUNT(*) AS high_value FROM high_value_keys WHERE run_id=r.run_id
        ) hv ON TRUE
        {where}
          {'AND' if where else 'WHERE'} COALESCE(r.raw_hits,0)=0
          AND COALESCE(r.unique_targets,0)=0
          AND COALESCE(result_counts.valid,0)=0
          AND COALESCE(result_counts.suspicious,0)=0
          AND COALESCE(hv.high_value,0)=0
        ORDER BY r.run_id
    """
    if args.limit > 0:
        sql += " LIMIT %s"
        params.append(args.limit)
    run_ids = [str(row["run_id"]) for row in conn.execute(sql, tuple(params)).fetchall()]
    if args.apply and run_ids:
        conn.execute("DELETE FROM runs WHERE run_id = ANY(%s)", (run_ids,))
    return {"candidates": len(run_ids), "deleted": len(run_ids) if args.apply else 0}


if __name__ == "__main__":
    raise SystemExit(main("Delete runs whose five UI metrics are zero", run))
