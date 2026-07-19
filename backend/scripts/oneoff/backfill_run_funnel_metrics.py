#!/usr/bin/env python
"""Backfill ``runs`` funnel columns for historical rows that defaulted to 0.

Context: History UI switched from ``hits`` / ``valid_count`` / ``high_value`` to
funnel fields (``raw_hits``, ``unique_targets``, ``final_verified``,
``high_value_final``). Older imports and pre-funnel persists left those columns
at DEFAULT 0 even when ``total_hosts`` / ``results`` / ``scan_*.jsonl`` still
hold the real numbers.

GitHub-only runs are a special case: discovery never produced host hits, so
``raw_hits`` / ``unique_targets`` were written as 0 even though
``hits_by_source.github`` and ``total_credentials`` hold real counts.

This script is idempotent and only fills zeros:

  1. Prefer ``scan_*.jsonl`` first-line metadata when present under RESULTS_DIR
     (and when those meta values are > 0)
  2. Else use ``hits_by_source`` sum (covers GitHub observation counts)
  3. Else use ``runs.total_hosts`` / ``total_credentials`` / ``candidates``
  4. ``final_verified`` / ``suspicious`` from ``results`` counts
  5. ``high_value_final`` from ``high_value_keys`` COUNT when still 0

Usage (Docker, recommended on the VPS)::

    docker compose -f docker-compose.yml exec backend \\
      uv run python scripts/oneoff/backfill_run_funnel_metrics.py

    # preview only
    docker compose -f docker-compose.yml exec backend \\
      uv run python scripts/oneoff/backfill_run_funnel_metrics.py --dry-run

Local (DATABASE_URL + RESULTS_DIR set)::

    cd backend && uv run python scripts/oneoff/backfill_run_funnel_metrics.py
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aipocket.core.config import settings  # noqa: E402
from aipocket.core.db import ensure_schema, get_pool  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("backfill_run_funnel")

_RUN_ID_RE = re.compile(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")


def _read_scan_meta(run_dir: Path) -> dict[str, Any]:
    files = sorted(run_dir.glob("scan_*.jsonl"), reverse=True)
    if not files:
        return {}
    try:
        first = files[0].read_text(encoding="utf-8").splitlines()
    except OSError as e:
        log.warning("cannot read %s: %s", files[0], e)
        return {}
    if not first:
        return {}
    try:
        meta = json.loads(first[0])
    except json.JSONDecodeError:
        return {}
    return meta if isinstance(meta, dict) else {}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _hits_by_source_sum(value: Any) -> int:
    """Sum discovery counts from hits_by_source JSONB (host or GitHub obs)."""
    if value is None:
        return 0
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return 0
    if not isinstance(value, dict):
        return 0
    total = 0
    for item in value.values():
        n = _int(item)
        if n > 0:
            total += n
    return total


def _plan_updates(
    row: dict[str, Any],
    *,
    meta: dict[str, Any],
    valid_n: int,
    susp_n: int,
    hv_n: int,
) -> dict[str, int]:
    """Compute column patches for one run (only keys that should change)."""
    patch: dict[str, int] = {}

    hbs = _hits_by_source_sum(row.get("hits_by_source"))
    meta_hbs = _hits_by_source_sum(meta.get("hits_by_source"))
    total_hosts = _int(row.get("total_hosts"))
    total_creds = _int(row.get("total_credentials"))
    row_candidates = _int(row.get("candidates"))
    meta_candidates = _int(meta.get("candidates"))

    raw = _int(row.get("raw_hits"))
    meta_raw = _int(meta.get("raw_hits") or meta.get("raw_hits_count"))
    if raw <= 0:
        # Prefer meta raw_hits only when > 0 (GitHub scan meta often has 0).
        # hits_by_source is the durable discovery count for credential sources.
        new_raw = meta_raw or hbs or meta_hbs or total_hosts or total_creds
        if new_raw > 0:
            patch["raw_hits"] = new_raw

    unique = _int(row.get("unique_targets"))
    meta_unique = _int(meta.get("unique_targets"))
    if unique <= 0:
        # Unique targets: host canonicalize count, else unique credential totals.
        new_unique = (
            meta_unique
            or total_hosts
            or meta_candidates
            or row_candidates
            or total_creds
            or hbs
            or meta_hbs
            or patch.get("raw_hits", 0)
        )
        if new_unique > 0:
            patch["unique_targets"] = new_unique

    candidates = row_candidates
    if candidates <= 0:
        new_c = meta_candidates or total_creds
        if new_c > 0:
            patch["candidates"] = new_c

    active = _int(row.get("active_requests"))
    if active <= 0:
        new_a = _int(meta.get("active_requests"))
        if new_a > 0:
            patch["active_requests"] = new_a

    final_v = _int(row.get("final_verified"))
    if final_v <= 0:
        new_f = _int(meta.get("final_verified")) or _int(row.get("total_valid")) or valid_n
        if new_f > 0:
            patch["final_verified"] = new_f

    susp = _int(row.get("suspicious"))
    if susp <= 0:
        new_s = _int(meta.get("suspicious")) or susp_n
        if new_s > 0:
            patch["suspicious"] = new_s

    hv = _int(row.get("high_value_final"))
    if hv <= 0:
        new_h = _int(meta.get("high_value_final")) or hv_n
        if new_h > 0:
            patch["high_value_final"] = new_h

    return patch


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill runs funnel metrics (zeros only)")
    parser.add_argument(
        "--results",
        default=None,
        help="results/ root for scan_*.jsonl (default: settings.results_dir)",
    )
    parser.add_argument("--dry-run", action="store_true", help="print plan without UPDATE")
    args = parser.parse_args()

    if not settings.pg_enabled:
        log.error("DATABASE_URL is not set — nothing to backfill.")
        return 1

    results_root = Path(args.results) if args.results else settings.results_path
    ensure_schema()
    pool = get_pool()

    updated = 0
    skipped = 0

    with pool.connection() as conn:
        runs = conn.execute(
            """
            SELECT run_id, total_hosts, total_credentials, total_valid,
                   raw_hits, unique_targets, candidates, active_requests,
                   final_verified, suspicious, high_value_final, hits_by_source
            FROM runs
            ORDER BY run_id
            """
        ).fetchall()
        kind_rows = conn.execute(
            "SELECT run_id, kind, COUNT(*) AS n FROM results GROUP BY run_id, kind"
        ).fetchall()
        hv_rows = conn.execute(
            """
            SELECT run_id, COUNT(*) AS n
            FROM high_value_keys
            WHERE run_id IS NOT NULL
            GROUP BY run_id
            """
        ).fetchall()

        valid_by: dict[str, int] = {}
        susp_by: dict[str, int] = {}
        for r in kind_rows:
            if r["kind"] == "valid":
                valid_by[r["run_id"]] = int(r["n"])
            elif r["kind"] == "suspicious":
                susp_by[r["run_id"]] = int(r["n"])
        hv_by = {r["run_id"]: int(r["n"]) for r in hv_rows}

        for row in runs:
            rid = row["run_id"]
            run_dir = results_root / rid if results_root.is_dir() else None
            meta = _read_scan_meta(run_dir) if run_dir and run_dir.is_dir() else {}
            patch = _plan_updates(
                dict(row),
                meta=meta,
                valid_n=valid_by.get(rid, 0),
                susp_n=susp_by.get(rid, 0),
                hv_n=hv_by.get(rid, 0),
            )
            if not patch:
                skipped += 1
                continue

            log.info(
                "%s%s: %s",
                "[dry-run] " if args.dry_run else "",
                rid,
                ", ".join(f"{k}={v}" for k, v in sorted(patch.items())),
            )
            if args.dry_run:
                updated += 1
                continue

            sets = ", ".join(f"{col} = %s" for col in patch)
            params = list(patch.values()) + [rid]
            conn.execute(f"UPDATE runs SET {sets} WHERE run_id = %s", params)
            updated += 1

        if not args.dry_run:
            conn.commit()

    log.info(
        "%sdone: %d run(s) updated, %d already complete (of %d)",
        "[dry-run] " if args.dry_run else "",
        updated,
        skipped,
        updated + skipped,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
