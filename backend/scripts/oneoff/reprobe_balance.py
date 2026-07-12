"""Re-probe balance for entries with no balance using the latest balance probes.

Re-probes any credential whose gateway is ``unsupported`` or empty (i.e. no
balance was resolved on the first pass), then rewrites the JSONL in place.

Also supports:

* A single ``valid_*.jsonl`` file
* A ``run_*`` directory (all ``valid_*.jsonl`` inside)
* A results root (all ``run_*/valid_*.jsonl``)
* ``--pg``: update PostgreSQL ``results.record`` (+ ``high_value_keys``) directly
* ``--only-anthropic``: only ``sk-ant-*`` / anthropic.com rows
* ``--force``: re-probe even when gateway/balance already look set

Anthropic notes: ordinary ``sk-ant-api…`` keys have **no** remaining-balance API.
The probe confirms liveness via ``/v1/models`` and stores ``balance=N/A``.
Admin keys may also record 30d spend in ``rate_limit_headers.balance_detail``.

Usage (local)::

    uv run python scripts/oneoff/reprobe_balance.py /data/aipocket/results --sync-pg
    uv run python scripts/oneoff/reprobe_balance.py --pg --only-anthropic

Usage (Docker — after rebuilding backend with the new probe)::

    docker compose build backend && docker compose up -d backend
    docker compose exec backend uv run python scripts/oneoff/reprobe_balance.py --pg
    docker compose exec backend uv run python scripts/oneoff/reprobe_balance.py --pg --only-anthropic
    docker compose exec backend uv run python scripts/oneoff/reprobe_balance.py \\
        /data/aipocket/results --sync-pg
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


# Sources that resolve a row without a numeric remaining balance.
_RESOLVED_NO_NUMERIC = frozenset(
    {
        "key_no_limit",
        "api_key_no_balance",
        "admin_org_alive",
        "admin_cost_report",
        "admin_unauthorized",
        "unauthorized",
        "oauth_org_alive",
    }
)


def needs_reprobe(entry: dict[str, Any], *, force: bool = False) -> bool:
    """True when balance was never resolved (or gateway is unsupported)."""
    if force:
        return True
    gw = entry.get("gateway")
    if gw in (None, "", "unsupported"):
        return True
    bal = entry.get("balance")
    # Non-empty balance (including the Anthropic "N/A" sentinel) is done.
    if bal not in (None, ""):
        return False
    # Gateway already resolved with no monetary figure (e.g. Anthropic API key).
    return False


def _apply_balance(entry: dict[str, Any], result: dict[str, Any]) -> bool:
    """Mutate *entry* with a successful probe result. Returns True if applied."""
    if result.get("gateway") in (None, "", "unsupported"):
        return False
    # Accept numeric 0 as a real balance; reject empty string (unknown)
    # unless the probe explicitly reports a resolved no-balance source.
    balance_usd = result.get("balance_usd", "")
    source = str(result.get("source", ""))
    if balance_usd == "" and source not in _RESOLVED_NO_NUMERIC:
        return False

    entry["gateway"] = result["gateway"]
    if balance_usd != "":
        entry["balance"] = str(balance_usd)
    if result.get("tier"):
        entry["tier"] = str(result["tier"])
    headers = entry.get("rate_limit_headers")
    if not isinstance(headers, dict):
        headers = {}
        entry["rate_limit_headers"] = headers
    raw = result.get("raw", {})
    detail: dict[str, Any] = {
        "gateway": result["gateway"],
        "balance_usd": balance_usd,
        "source": source,
        "credential_kind": result.get("credential_kind", ""),
        "alive": result.get("alive"),
        "spend_usd_30d": result.get("spend_usd_30d"),
        "model_count": result.get("model_count"),
        "organization_id": result.get("organization_id", ""),
        "note": result.get("note", ""),
        "raw": raw if not isinstance(raw, dict) or len(str(raw)) < 500 else "...(truncated)",
    }
    headers["balance_detail"] = str({k: v for k, v in detail.items() if v not in (None, "")})
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
    force: bool,
    only_anthropic: bool,
) -> int:
    total_updated = 0
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in paths:
            entries = _load_jsonl(path)
            indices = [
                i
                for i, e in enumerate(entries)
                if needs_reprobe(e, force=force)
                and _matches_filter(e, only_anthropic=only_anthropic)
            ]
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


def _matches_filter(entry: dict[str, Any], *, only_anthropic: bool) -> bool:
    if not only_anthropic:
        return True
    cred = entry.get("credential") or {}
    apikey = ""
    apiurl = ""
    if isinstance(cred, dict):
        apikey = str(cred.get("apikey") or "")
        apiurl = str(cred.get("apiurl") or "")
    apikey = apikey or str(entry.get("apikey") or "")
    apiurl = apiurl or str(entry.get("apiurl") or "")
    return apikey.startswith("sk-ant-") or "anthropic.com" in apiurl.lower()


def _pg_needs_sql(*, force: bool, only_anthropic: bool) -> tuple[str, tuple[Any, ...]]:
    """Build SELECT for PG re-probe candidates."""
    clauses = ["kind = 'valid'"]
    params: list[Any] = []
    if not force:
        clauses.append(
            """(
                COALESCE(record->>'gateway', '') IN ('', 'unsupported')
                OR COALESCE(record->>'balance', '') = ''
            )"""
        )
    if only_anthropic:
        clauses.append(
            """(
                COALESCE(apikey, '') LIKE 'sk-ant-%%'
                OR COALESCE(record->'credential'->>'apikey', '') LIKE 'sk-ant-%%'
                OR COALESCE(record->'credential'->>'apiurl', '') ILIKE '%%anthropic.com%%'
                OR COALESCE(record->>'apiurl', '') ILIKE '%%anthropic.com%%'
            )"""
        )
    sql = f"""
        SELECT id, record
        FROM results
        WHERE {" AND ".join(clauses)}
        ORDER BY id
    """
    return sql, tuple(params)


async def reprobe_pg(
    *,
    concurrency: int,
    force: bool = False,
    only_anthropic: bool = False,
) -> int:
    """Re-probe rows stored in PostgreSQL ``results`` (kind=valid)."""
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        print("PG not enabled (set DATABASE_URL). Aborting --pg mode.")
        return 0

    pool = get_pool()
    sql, params = _pg_needs_sql(force=force, only_anthropic=only_anthropic)
    with pool.connection() as conn:
        rows = conn.execute(sql, params).fetchall()

    # Secondary filter for force=False empty-balance rows that already resolved
    # to a non-unsupported gateway (e.g. anthropic N/A from a prior pass).
    candidates: list[tuple[int, dict[str, Any]]] = []
    for row in rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        entry = dict(rec)
        if not needs_reprobe(entry, force=force):
            continue
        if not _matches_filter(entry, only_anthropic=only_anthropic):
            continue
        candidates.append((row["id"], entry))

    print(f"PG rows needing re-probe: {len(candidates)} (sql matched {len(rows)})")
    if not candidates:
        return 0

    ids = [c[0] for c in candidates]
    entries = [c[1] for c in candidates]

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
    print(f"PG updated: {len(updated_ids)}/{len(candidates)}")

    # Keep high_value_keys in sync when the same apikey is stored there.
    _sync_high_value_from_entries([rec for _, rec in updated_ids])

    # Also re-probe high_value_keys rows that may not appear in results.
    hv_n = await reprobe_high_value_keys(
        concurrency=concurrency,
        force=force,
        only_anthropic=only_anthropic,
    )
    return len(updated_ids) + hv_n


async def reprobe_high_value_keys(
    *,
    concurrency: int,
    force: bool = False,
    only_anthropic: bool = False,
) -> int:
    """Re-probe high_value_keys table rows missing balance/gateway."""
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        return 0

    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT apikey, record FROM high_value_keys ORDER BY saved_at DESC NULLS LAST"
        ).fetchall()

    candidates: list[tuple[str, dict[str, Any]]] = []
    for row in rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        entry = dict(rec)
        # Ensure apikey is present for probing even if nested oddly.
        if not (entry.get("credential") or {}).get("apikey") and not entry.get("apikey"):
            entry["apikey"] = row["apikey"]
        if not needs_reprobe(entry, force=force):
            continue
        if not _matches_filter(entry, only_anthropic=only_anthropic):
            continue
        candidates.append((row["apikey"], entry))

    print(f"high_value_keys needing re-probe: {len(candidates)}")
    if not candidates:
        return 0

    entries = [c[1] for c in candidates]
    keys = [c[0] for c in candidates]
    sem = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(15.0)
    updated: list[tuple[str, dict[str, Any]]] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:

        async def one(i: int) -> None:
            ok = await _probe_entry(client, sem, entries[i])
            if ok:
                updated.append((keys[i], entries[i]))

        await asyncio.gather(*[one(i) for i in range(len(entries))])

    if not updated:
        print("No high_value_keys updated.")
        return 0

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE high_value_keys SET record = %s WHERE apikey = %s",
                [(Jsonb(rec), apikey) for apikey, rec in updated],
            )
        conn.commit()
    print(f"high_value_keys updated: {len(updated)}/{len(candidates)}")
    return len(updated)


def _sync_high_value_from_entries(entries: list[dict[str, Any]]) -> None:
    """Best-effort update of high_value_keys.record balance/gateway fields."""
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        return
    pool = get_pool()
    updated = 0
    with pool.connection() as conn:
        for entry in entries:
            cred = entry.get("credential") or {}
            apikey = cred.get("apikey") if isinstance(cred, dict) else None
            apikey = apikey or entry.get("apikey")
            if not apikey:
                continue
            rows = conn.execute(
                "SELECT record FROM high_value_keys WHERE apikey = %s",
                (apikey,),
            ).fetchall()
            for row in rows:
                rec = row["record"]
                if isinstance(rec, str):
                    rec = json.loads(rec)
                rec = dict(rec)
                rec["gateway"] = entry.get("gateway", rec.get("gateway"))
                rec["balance"] = entry.get("balance", rec.get("balance"))
                if entry.get("tier"):
                    rec["tier"] = entry["tier"]
                if "rate_limit_headers" in entry:
                    rec["rate_limit_headers"] = entry["rate_limit_headers"]
                if isinstance(entry.get("provider_info"), dict):
                    pi = dict(rec.get("provider_info") or {})
                    pi["balance_provider"] = entry["provider_info"].get(
                        "balance_provider", pi.get("balance_provider")
                    )
                    rec["provider_info"] = pi
                conn.execute(
                    "UPDATE high_value_keys SET record = %s WHERE apikey = %s",
                    (Jsonb(rec), apikey),
                )
                updated += 1
        conn.commit()
    if updated:
        print(f"  high_value_keys synced: {updated} row(s)")


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
    parser = argparse.ArgumentParser(
        description=(
            "Re-probe missing balances (OpenRouter, Anthropic N/A, gateways, …). "
            "Docker example:\n"
            "  docker compose exec backend uv run python "
            "scripts/oneoff/reprobe_balance.py --pg --only-anthropic"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
        "--force",
        action="store_true",
        help="Re-probe even when gateway/balance already look resolved",
    )
    parser.add_argument(
        "--only-anthropic",
        action="store_true",
        help="Only re-probe sk-ant-* / anthropic.com credentials",
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
        n = asyncio.run(
            reprobe_pg(
                concurrency=args.concurrency,
                force=args.force,
                only_anthropic=args.only_anthropic,
            )
        )
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
    n = asyncio.run(
        reprobe_jsonl_files(
            paths,
            concurrency=args.concurrency,
            sync_pg=args.sync_pg,
            force=args.force,
            only_anthropic=args.only_anthropic,
        )
    )
    print(f"\nDone. Total updated: {n}")


if __name__ == "__main__":
    main()
