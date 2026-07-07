#!/usr/bin/env python
"""Backfill historical JSONL/JSON data into PostgreSQL.

One-shot migration helper: reads the existing on-disk data and inserts it into
the PG tables so PG can become the source of truth without losing history.

Sources ingested:
  * results/run_*/                — one run per dir
      scan_*.jsonl (line 1)       -> runs metadata
      valid_*.jsonl               -> results (kind='valid',  seq = line order)
      suspicious_*.jsonl          -> results (kind='suspicious', seq = line order)
      run.log                     -> runs.log
  * results/high_value_keys/keys.jsonl -> high_value_keys (UPSERT by apikey)
  * sources/cve_2026_ai.json           -> cves (UPSERT by id)

Idempotent: each run is UPSERTed and its result rows are replaced, so re-running
the script does not create duplicates. Requires DATABASE_URL to be set.

Usage:
    DATABASE_URL=postgresql://... uv run python scripts/import_jsonl_to_pg.py [--results DIR] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

# Make the package importable when run as a plain script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aipocket.core.config import settings  # noqa: E402
from aipocket.core.db import ensure_schema, get_pool  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("import_jsonl_to_pg")

_RUN_ID_RE = re.compile(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")


def _run_id_to_iso(run_id: str) -> str | None:
    m = re.match(r"^run_(\d{4})_(\d{2})_(\d{2})_(\d{2})-(\d{2})-(\d{2})$", run_id)
    if not m:
        return None
    try:
        return datetime(*(int(g) for g in m.groups())).isoformat()  # type: ignore[arg-type]
    except ValueError:
        return None


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("skip malformed line in %s: %s", path.name, line[:80])
    return out


def _load_kind_files(run: Path, kind: str) -> list[dict]:
    """Read a run's valid/suspicious records in file+line order (skip .bak etc.)."""
    prefix = "valid_" if kind == "valid" else "suspicious_"
    records: list[dict] = []
    # Only exact `<prefix>*.jsonl` files — never `.bak` or other siblings.
    for f in sorted(p for p in run.glob(f"{prefix}*.jsonl") if p.suffix == ".jsonl"):
        records.extend(_read_jsonl(f))
    return records


def _cred_of(rec: dict) -> dict:
    c = rec.get("credential")
    return c if isinstance(c, dict) else {}


def import_run(conn, run: Path, dry_run: bool) -> tuple[int, int]:
    """Import one run dir. Returns (valid_count, suspicious_count)."""
    from psycopg.types.json import Jsonb

    run_id = run.name

    # Metadata from the first line of scan_*.jsonl (if present).
    meta: dict = {}
    scan_files = sorted(run.glob("scan_*.jsonl"))
    if scan_files:
        lines = scan_files[0].read_text(encoding="utf-8").splitlines()
        if lines:
            try:
                meta = json.loads(lines[0])
            except json.JSONDecodeError:
                log.warning("run %s: unreadable scan metadata line", run_id)

    valid = _load_kind_files(run, "valid")
    suspicious = _load_kind_files(run, "suspicious")

    log_text = None
    log_path = run / "run.log"
    if log_path.exists():
        try:
            log_text = log_path.read_text(encoding="utf-8")
        except OSError as e:
            log.warning("run %s: failed reading run.log: %s", run_id, e)

    if dry_run:
        log.info("[dry-run] %s: %d valid, %d suspicious", run_id, len(valid), len(suspicious))
        return len(valid), len(suspicious)

    started = meta.get("started_at") or _run_id_to_iso(run_id)

    with conn.transaction():
        conn.execute(
            """
            INSERT INTO runs (run_id, started_at, finished_at, state, sources,
                              hits_by_source, queries_used, total_hosts,
                              total_credentials, total_valid, log)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id) DO UPDATE SET
                started_at = EXCLUDED.started_at,
                sources = EXCLUDED.sources,
                hits_by_source = EXCLUDED.hits_by_source,
                queries_used = EXCLUDED.queries_used,
                total_hosts = EXCLUDED.total_hosts,
                total_credentials = EXCLUDED.total_credentials,
                total_valid = EXCLUDED.total_valid,
                log = EXCLUDED.log
            """,
            (
                run_id,
                started,
                None,
                "finished",
                Jsonb(meta.get("sources", [])),
                Jsonb(meta.get("hits_by_source", {})),
                Jsonb(meta.get("queries_used", [])),
                meta.get("total_hosts"),
                meta.get("total_credentials"),
                len(valid),
                log_text,
            ),
        )
        conn.execute("DELETE FROM results WHERE run_id = %s", (run_id,))
        rows = []
        for kind, recs in (("valid", valid), ("suspicious", suspicious)):
            for i, rec in enumerate(recs):
                cred = _cred_of(rec)
                rows.append(
                    (
                        run_id,
                        kind,
                        i,
                        cred.get("apikey", ""),
                        cred.get("apiurl", ""),
                        cred.get("host", ""),
                        bool(rec.get("valid")),
                        Jsonb(rec),
                    )
                )
        if rows:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO results (run_id, kind, seq, apikey, apiurl, host, valid, record)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )
    log.info("imported %s: %d valid, %d suspicious", run_id, len(valid), len(suspicious))
    return len(valid), len(suspicious)


def import_high_value(conn, results_root: Path, dry_run: bool) -> int:
    from psycopg.types.json import Jsonb

    hv_path = results_root / "high_value_keys" / "keys.jsonl"
    if not hv_path.exists():
        return 0
    entries = _read_jsonl(hv_path)
    # Dedup by apikey (last write wins), matching the app's load contract.
    by_key: dict[str, dict] = {}
    for e in entries:
        key = e.get("apikey", "")
        if key:
            by_key[key] = e
    if dry_run:
        log.info("[dry-run] high-value keys: %d unique", len(by_key))
        return len(by_key)
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO high_value_keys (apikey, run_id, saved_at, record)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (apikey) DO UPDATE
              SET run_id = EXCLUDED.run_id, saved_at = EXCLUDED.saved_at, record = EXCLUDED.record
            """,
            [
                (e["apikey"], e.get("run_id"), e.get("saved_at"), Jsonb(e))
                for e in by_key.values()
            ],
        )
    conn.commit()
    log.info("imported %d high-value keys", len(by_key))
    return len(by_key)


def import_cves(conn, dry_run: bool) -> int:
    from psycopg.types.json import Jsonb

    cve_path = Path(__file__).resolve().parents[1] / "sources" / "cve_2026_ai.json"
    if not cve_path.exists():
        return 0
    try:
        data = json.loads(cve_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("unreadable CVE file %s", cve_path)
        return 0
    if not isinstance(data, list):
        return 0
    if dry_run:
        log.info("[dry-run] CVEs: %d", len(data))
        return len(data)
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO cves (id, record) VALUES (%s, %s) ON CONFLICT (id) DO UPDATE SET record = EXCLUDED.record",
            [(c["id"], Jsonb(c)) for c in data if c.get("id")],
        )
    conn.commit()
    log.info("imported %d CVEs", len(data))
    return len(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill JSONL/JSON history into PostgreSQL")
    parser.add_argument("--results", default=None, help="results/ root (default: settings.results_dir)")
    parser.add_argument("--dry-run", action="store_true", help="report counts without writing")
    args = parser.parse_args()

    if not settings.pg_enabled:
        log.error("DATABASE_URL is not set — nothing to import into.")
        return 1

    results_root = Path(args.results) if args.results else settings.results_path
    if not results_root.is_dir():
        log.error("results root not found: %s", results_root)
        return 1

    ensure_schema()
    pool = get_pool()

    run_dirs = sorted(
        p for p in results_root.glob("run_*") if p.is_dir() and _RUN_ID_RE.match(p.name)
    )
    log.info("found %d run(s) under %s", len(run_dirs), results_root)

    total_valid = total_susp = 0
    with pool.connection() as conn:
        for run in run_dirs:
            v, s = import_run(conn, run, args.dry_run)
            total_valid += v
            total_susp += s
        hv = import_high_value(conn, results_root, args.dry_run)
        cves = import_cves(conn, args.dry_run)

    log.info(
        "%sdone: %d runs, %d valid, %d suspicious, %d high-value, %d CVEs",
        "[dry-run] " if args.dry_run else "",
        len(run_dirs),
        total_valid,
        total_susp,
        hv,
        cves,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
