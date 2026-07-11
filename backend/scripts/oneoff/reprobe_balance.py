"""Re-probe balance for entries with no balance using the latest balance probes.

Re-probes any credential whose gateway is ``unsupported`` or empty (i.e. no
balance was resolved on the first pass), then rewrites the JSONL in place.

Also supports:

* A single ``valid_*.jsonl`` file
* A ``run_*`` directory (all ``valid_*.jsonl`` inside)
* A results root (all ``run_*/valid_*.jsonl``)
* ``--pg``: update PostgreSQL ``results.record`` directly (when PG is source of truth)

Usage (on VPS after deploying the OpenRouter probe)::

    # One file
    uv run python scripts/oneoff/reprobe_balance.py /data/results/run_2026_07_10_12-00-00/valid_....jsonl

    # Whole results tree
    uv run python scripts/oneoff/reprobe_balance.py /data/results

    # PostgreSQL only
    uv run python scripts/oneoff/reprobe_balance.py --pg

    # JSONL + sync updated rows into PG
    uv run python scripts/oneoff/reprobe_balance.py /data/results --sync-pg
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx

from aipocket.core.models import Credential
from aipocket.services.balance import query_balance

log = logging.getLogger("reprobe_balance")

_UNSAFE = str.maketrans({"\u2028": " ", "\u2029": " "})


def needs_reprobe(entry: dict[str, Any]) -> bool:
    """True when balance was never resolved (or gateway is unsupported)."""
    gw = entry.get("gateway")
    if gw in (None, "", "unsupported"):
        return True
    bal = entry.get("balance")
    return bal in (None, "")


def _apply_balance(entry: dict[str, Any], result: dict[str, Any]) -> bool:
    """Mutate *entry* with a successful probe result. Returns True if applied."""
    if result.get("gateway") in (None, "", "unsupported"):
        return False
    # Accept numeric 0 as a real balance; reject empty string (unknown).
    balance_usd = result.get("balance_usd", "")
    if balance_usd == "" and result.get("source") == "key_no_limit":
        # Mark gateway so we don't thrash, but leave balance blank.
        entry["gateway"] = result["gateway"]
        if isinstance(entry.get("provider_info"), dict):
            entry["provider_info"]["balance_provider"] = result["gateway"]
        return True
    if balance_usd == "":
        return False

    entry["gateway"] = result["gateway"]
    entry["balance"] = str(balance_usd)
    headers = entry.get("rate_limit_headers")
    if not isinstance(headers, dict):
        headers = {}
        entry["rate_limit_headers"] = headers
    raw = result.get("raw", {})
    headers["balance_detail"] = str(
        {
            "gateway": result["gateway"],
            "balance_usd": balance_usd,
            "source": result.get("source", ""),
            "raw": raw if not isinstance(raw, dict) or len(str(raw)) < 500 else "...(truncated)",
        }
    )
    if isinstance(entry.get("provider_info"), dict):
        entry["provider_info"]["balance_provider"] = result["gateway"]
    return True


async def _probe_entry(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    entry: dict[str, Any],
) -> bool:
    cred_data = entry.get("credential") or {}
    if not isinstance(cred_data, dict):
        cred_data = {}
    apikey = cred_data.get("apikey") or entry.get("apikey") or ""
    apiurl = cred_data.get("apiurl") or entry.get("apiurl") or ""
    if not apikey:
        return False
    cred = Credential(apikey=apikey, apiurl=apiurl)
    async with sem:
        try:
            result = await query_balance(client, cred)
        except Exception as e:  # noqa: BLE001 — one-off script, keep going
            log.warning("probe failed for %s…: %s", apikey[:12], e)
            return False
    return _apply_balance(entry, result)


def _collect_jsonl_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.is_dir():
        return []
    # run_* dir
    if target.name.startswith("run_"):
        return sorted(p for p in target.glob("valid_*.jsonl") if p.suffix == ".jsonl")
    # results root
    paths: list[Path] = []
    for run in sorted(target.glob("run_*")):
        if run.is_dir():
            paths.extend(sorted(p for p in run.glob("valid_*.jsonl") if p.suffix == ".jsonl"))
    # also accept a bare valid_*.jsonl dropped at root
    paths.extend(sorted(p for p in target.glob("valid_*.jsonl") if p.suffix == ".jsonl"))
    return paths


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("skip malformed line in %s: %s", path, line[:80])
    return entries


def _write_jsonl(path: Path, entries: list[dict[str, Any]]) -> None:
    lines = [
        json.dumps(e, ensure_ascii=False, default=str).translate(_UNSAFE) + "\n" for e in entries
    ]
    path.write_text("".join(lines), encoding="utf-8")


async def reprobe_jsonl_files(
    paths: list[Path],
    *,
    concurrency: int,
    sync_pg: bool,
) -> int:
    total_updated = 0
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in paths:
            entries = _load_jsonl(path)
            indices = [i for i, e in enumerate(entries) if needs_reprobe(e)]
            print(f"\n{path}: {len(entries)} rows, {len(indices)} need re-probe")
            if not indices:
                continue
            sem = asyncio.Semaphore(concurrency)
            results = await asyncio.gather(
                *[_probe_entry(client, sem, entries[i]) for i in indices]
            )
            updated = sum(1 for ok in results if ok)
            total_updated += updated
            print(f"  updated: {updated}/{len(indices)}")
            if updated:
                _write_jsonl(path, entries)
                print(f"  written: {path}")
                if sync_pg:
                    _sync_entries_to_pg(entries)
    return total_updated


async def reprobe_pg(*, concurrency: int) -> int:
    """Re-probe rows stored in PostgreSQL ``results`` (kind=valid)."""
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        print("PG not enabled (set DATABASE_URL). Aborting --pg mode.")
        return 0

    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, record
            FROM results
            WHERE kind = 'valid'
              AND (
                COALESCE(record->>'gateway', '') IN ('', 'unsupported')
                OR COALESCE(record->>'balance', '') = ''
              )
            ORDER BY id
            """
        ).fetchall()

    print(f"PG rows needing re-probe: {len(rows)}")
    if not rows:
        return 0

    entries: list[dict[str, Any]] = []
    ids: list[int] = []
    for row in rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        entries.append(dict(rec))
        ids.append(row["id"])

    sem = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(15.0)
    updated_ids: list[tuple[int, dict[str, Any]]] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:

        async def one(i: int) -> None:
            ok = await _probe_entry(client, sem, entries[i])
            if ok:
                updated_ids.append((ids[i], entries[i]))

        await asyncio.gather(*[one(i) for i in range(len(entries))])

    if not updated_ids:
        print("No PG rows updated.")
        return 0

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE results SET record = %s WHERE id = %s",
                [(Jsonb(rec), rid) for rid, rec in updated_ids],
            )
        conn.commit()
    print(f"PG updated: {len(updated_ids)}/{len(rows)}")
    return len(updated_ids)


def _sync_entries_to_pg(entries: list[dict[str, Any]]) -> None:
    """Best-effort UPSERT of balance fields into PG by apikey match (valid rows)."""
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        log.warning("--sync-pg requested but DATABASE_URL not set; skipped")
        return

    pool = get_pool()
    updated = 0
    with pool.connection() as conn:
        for entry in entries:
            if needs_reprobe(entry):
                continue
            cred = entry.get("credential") or {}
            apikey = cred.get("apikey") if isinstance(cred, dict) else None
            if not apikey:
                continue
            rows = conn.execute(
                "SELECT id, record FROM results WHERE kind = 'valid' AND apikey = %s",
                (apikey,),
            ).fetchall()
            for row in rows:
                rec = row["record"]
                if isinstance(rec, str):
                    rec = json.loads(rec)
                rec = dict(rec)
                rec["gateway"] = entry.get("gateway", rec.get("gateway"))
                rec["balance"] = entry.get("balance", rec.get("balance"))
                if "rate_limit_headers" in entry:
                    rec["rate_limit_headers"] = entry["rate_limit_headers"]
                if isinstance(entry.get("provider_info"), dict):
                    pi = dict(rec.get("provider_info") or {})
                    pi["balance_provider"] = entry["provider_info"].get(
                        "balance_provider", pi.get("balance_provider")
                    )
                    rec["provider_info"] = pi
                conn.execute(
                    "UPDATE results SET record = %s WHERE id = %s",
                    (Jsonb(rec), row["id"]),
                )
                updated += 1
        conn.commit()
    print(f"  synced to PG: {updated} row(s)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-probe missing balances (e.g. OpenRouter)")
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=None,
        help="valid_*.jsonl file, run_* dir, or results root",
    )
    parser.add_argument(
        "--pg",
        action="store_true",
        help="Re-probe directly from PostgreSQL results table",
    )
    parser.add_argument(
        "--sync-pg",
        action="store_true",
        help="After rewriting JSONL, push updated balance fields into PG",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
        help="Concurrent balance probes (default: 20)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.pg:
        n = asyncio.run(reprobe_pg(concurrency=args.concurrency))
        print(f"\nDone. Total updated: {n}")
        return

    if args.target is None:
        parser.error("provide a path target, or use --pg")

    target = args.target.expanduser().resolve()
    if not target.exists():
        print(f"Not found: {target}")
        sys.exit(1)

    paths = _collect_jsonl_paths(target)
    if not paths:
        print(f"No valid_*.jsonl under {target}")
        sys.exit(1)

    print(f"Files to process: {len(paths)}")
    n = asyncio.run(reprobe_jsonl_files(paths, concurrency=args.concurrency, sync_pg=args.sync_pg))
    print(f"\nDone. Total updated: {n}")


if __name__ == "__main__":
    main()
