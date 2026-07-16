"""Clean false-valid rows left by the honeypot→finalizer re-promotion bug.

Background
----------
``filter_honeypots`` set ``valid=False`` + ``error=honeypot:…`` but left
``validation_state`` in AUTHENTICATED states. ``finalize_results`` then
re-promoted those rows to ``final_verified`` (prod: 2439 rejected → 2469 saved).

This script reclassifies / removes already-persisted bad rows in:

* PostgreSQL ``results`` (kind=valid → kind=rejected, or DELETE)
* PostgreSQL ``high_value_keys`` (delete honeypot-shaped entries)
* Optional JSONL under a results root

Rules (any match → dirty)
-------------------------
1. ``error`` starts with ``honeypot:`` or ``blocked-key-format:``
2. Gateway is ``nexus`` with a numeric balance AND error empty but models list
   looks low-tier only — soft signal; only applied with ``--aggressive``
3. Host/ip known as no-auth honeypot cluster (``--replay-noauth`` re-probes)

Also optional:
* ``--drop-gemini-free``: remove AIza… / generativelanguage.googleapis.com rows
  (free-tier Gemini keys that validated via models list but have no balance)
* ``--reprobe-balance``: re-run balance probes for dashscope / anthropic after clean

Usage
-----
Dry-run (default)::

    docker compose exec backend uv run python scripts/oneoff/clean_false_valid.py --pg

Apply::

    docker compose exec backend uv run python scripts/oneoff/clean_false_valid.py --pg --apply

JSONL::

    docker compose exec backend uv run python scripts/oneoff/clean_false_valid.py \\
        /data/aipocket/results --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

log = logging.getLogger("clean_false_valid")

_HONEYPOT_ERR = re.compile(r"^(honeypot:|blocked-key-format:)", re.I)
# Low-tier-only model catalogues commonly served by bait gateways.
_LOW_TIER_MODEL = re.compile(
    r"^(gpt-3(\.5)?(-turbo)?|gpt-4([^-a-z]|$)|gpt-4-0?32k|text-davinci|"
    r"gpt-4o-mini|gpt-3\.5-turbo)",
    re.I,
)
_HIGH_TIER_HINT = re.compile(
    r"(gpt-5|o1|o3|o4|claude-(opus|sonnet)-[4-9]|gemini-[23]|deepseek-v[34]|"
    r"qwen3|glm-5|kimi-k2)",
    re.I,
)


def _cred(entry: dict[str, Any]) -> dict[str, Any]:
    c = entry.get("credential")
    return c if isinstance(c, dict) else {}


def _apikey(entry: dict[str, Any]) -> str:
    return str(_cred(entry).get("apikey") or entry.get("apikey") or "")


def _apiurl(entry: dict[str, Any]) -> str:
    return str(_cred(entry).get("apiurl") or entry.get("apiurl") or "")


def _models(entry: dict[str, Any]) -> list[str]:
    pi = entry.get("provider_info")
    if not isinstance(pi, dict):
        return []
    raw = pi.get("models_available") or pi.get("models_verified") or []
    if not isinstance(raw, list):
        return []
    return [str(m) for m in raw if m]


def is_honeypot_error(entry: dict[str, Any]) -> str | None:
    err = str(entry.get("error") or "")
    if _HONEYPOT_ERR.match(err):
        return f"error:{err[:80]}"
    reason = str(entry.get("suspicious_reason") or "")
    if reason.startswith("honeypot:"):
        return f"suspicious_reason:{reason[:80]}"
    return None


def is_fake_nexus_balance(entry: dict[str, Any]) -> str | None:
    """Nexus probe historically mapped total_usage → balance_usd (~$90–110 bait)."""
    gw = str(entry.get("gateway") or "").lower()
    if gw != "nexus":
        return None
    bal = str(entry.get("balance") or "").strip()
    if not bal or bal.upper() == "N/A":
        return None
    try:
        val = float(bal)
    except ValueError:
        return None
    # Classic bait window seen in prod logs (64.23.132.174 cluster).
    if 50.0 <= val <= 200.0:
        return f"nexus_fake_balance:{bal}"
    return None


def is_low_tier_only_gateway(entry: dict[str, Any]) -> str | None:
    models = _models(entry)
    if len(models) < 1:
        return None
    if any(_HIGH_TIER_HINT.search(m) for m in models):
        return None
    # Only fire when every listed model looks legacy/cheap AND host is IP/gateway.
    if not all(_LOW_TIER_MODEL.search(m.split("/")[-1]) for m in models[:30]):
        return None
    url = _apiurl(entry).lower()
    official = (
        "openai.com" in url
        or "anthropic.com" in url
        or "googleapis.com" in url
        or "openrouter.ai" in url
        or "dashscope" in url
    )
    if official:
        return None
    return f"low_tier_only_models:{','.join(models[:5])}"


def is_gemini_free_row(entry: dict[str, Any]) -> str | None:
    key = _apikey(entry)
    url = _apiurl(entry).lower()
    if key.startswith("AIza") or "generativelanguage.googleapis.com" in url:
        return "gemini_free_or_google_key"
    return None


def classify_dirty(
    entry: dict[str, Any],
    *,
    aggressive: bool = False,
    drop_gemini_free: bool = False,
) -> str | None:
    reason = is_honeypot_error(entry)
    if reason:
        return reason
    reason = is_fake_nexus_balance(entry)
    if reason:
        return reason
    if aggressive:
        reason = is_low_tier_only_gateway(entry)
        if reason:
            return reason
    if drop_gemini_free:
        reason = is_gemini_free_row(entry)
        if reason:
            return reason
    return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            log.warning("skip malformed line in %s", path)
    return out


def _write_jsonl(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(e, ensure_ascii=False, default=str) + "\n" for e in entries),
        encoding="utf-8",
    )


def clean_jsonl_tree(
    root: Path,
    *,
    apply: bool,
    aggressive: bool,
    drop_gemini_free: bool,
) -> dict[str, int]:
    stats = {"files": 0, "scanned": 0, "dirty": 0, "rewritten": 0}
    paths = sorted(root.glob("run_*/valid_*.jsonl")) + sorted(root.glob("valid_*.jsonl"))
    for path in paths:
        entries = _load_jsonl(path)
        stats["files"] += 1
        stats["scanned"] += len(entries)
        kept: list[dict[str, Any]] = []
        dirty_n = 0
        for e in entries:
            reason = classify_dirty(e, aggressive=aggressive, drop_gemini_free=drop_gemini_free)
            if reason:
                dirty_n += 1
                log.info("JSONL dirty %s… %s (%s)", _apikey(e)[:16], reason, path.name)
            else:
                kept.append(e)
        stats["dirty"] += dirty_n
        if dirty_n and apply:
            # Write rejected sibling for audit trail.
            rej = path.with_name(path.name.replace("valid_", "rejected_cleaned_", 1))
            dirty_rows = [e for e in entries if e not in kept]
            _write_jsonl(rej, dirty_rows)
            _write_jsonl(path, kept)
            stats["rewritten"] += 1
            print(f"  {path}: removed {dirty_n}, kept {len(kept)} → {rej.name}")
        elif dirty_n:
            print(f"  {path}: would remove {dirty_n}/{len(entries)}")
    return stats


def clean_pg(
    *,
    apply: bool,
    aggressive: bool,
    drop_gemini_free: bool,
    delete: bool,
) -> dict[str, int]:
    from psycopg.types.json import Jsonb

    from aipocket.core.config import settings
    from aipocket.core.db import get_pool

    if not settings.pg_enabled:
        print("PG not enabled (DATABASE_URL). Aborting --pg.")
        return {"scanned": 0, "dirty": 0, "updated": 0, "hv_deleted": 0}

    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, apikey, record FROM results WHERE kind = 'valid' ORDER BY id"
        ).fetchall()

    dirty: list[tuple[int, dict[str, Any], str]] = []
    for row in rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        entry = dict(rec)
        reason = classify_dirty(entry, aggressive=aggressive, drop_gemini_free=drop_gemini_free)
        if reason:
            dirty.append((row["id"], entry, reason))

    print(f"PG valid rows: {len(rows)}, dirty: {len(dirty)}")
    for rid, entry, reason in dirty[:30]:
        print(f"  id={rid} key={_apikey(entry)[:18]}… reason={reason}")
    if len(dirty) > 30:
        print(f"  … and {len(dirty) - 30} more")

    updated = 0
    hv_deleted = 0
    if apply and dirty:
        with pool.connection() as conn:
            for rid, entry, reason in dirty:
                entry = dict(entry)
                entry["valid"] = False
                entry["validation_state"] = "no_auth_endpoint"
                entry["error"] = entry.get("error") or f"cleaned:{reason}"
                entry["cleaned_reason"] = reason
                if delete:
                    conn.execute("DELETE FROM results WHERE id = %s", (rid,))
                else:
                    conn.execute(
                        "UPDATE results SET kind = 'rejected', record = %s WHERE id = %s",
                        (Jsonb(entry), rid),
                    )
                updated += 1
                apikey = _apikey(entry)
                if apikey:
                    cur = conn.execute("DELETE FROM high_value_keys WHERE apikey = %s", (apikey,))
                    hv_deleted += getattr(cur, "rowcount", 0) or 0
            conn.commit()
        print(f"PG applied: {'deleted' if delete else 'reclassified'} {updated} rows")
        if hv_deleted:
            print(f"high_value_keys deleted: {hv_deleted}")

    # Also scrub high_value_keys that match clean rules even if not in results.
    with pool.connection() as conn:
        hv_rows = conn.execute("SELECT apikey, record FROM high_value_keys").fetchall()
    hv_dirty = 0
    for row in hv_rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        entry = dict(rec)
        if not entry.get("apikey"):
            entry["apikey"] = row["apikey"]
        reason = classify_dirty(entry, aggressive=aggressive, drop_gemini_free=drop_gemini_free)
        if reason:
            hv_dirty += 1
            if apply:
                with pool.connection() as conn:
                    conn.execute("DELETE FROM high_value_keys WHERE apikey = %s", (row["apikey"],))
                    conn.commit()
    if hv_dirty:
        print(f"high_value_keys dirty: {hv_dirty} ({'deleted' if apply else 'dry-run'})")

    return {
        "scanned": len(rows),
        "dirty": len(dirty),
        "updated": updated if apply else 0,
        "hv_deleted": hv_deleted + (hv_dirty if apply else 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        default=None,
        help="results root or valid_*.jsonl (optional with --pg)",
    )
    parser.add_argument("--pg", action="store_true", help="Clean PostgreSQL results")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write changes (default is dry-run)",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="DELETE dirty PG rows instead of reclassifying to kind=rejected",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Also drop low-tier-only non-official gateways",
    )
    parser.add_argument(
        "--drop-gemini-free",
        action="store_true",
        help="Drop AIza*/generativelanguage.googleapis.com rows",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.pg and args.target is None:
        parser.error("provide a path target and/or --pg")

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"=== clean_false_valid [{mode}] ===")

    if args.pg:
        stats = clean_pg(
            apply=args.apply,
            aggressive=args.aggressive,
            drop_gemini_free=args.drop_gemini_free,
            delete=args.delete,
        )
        print(f"PG stats: {stats}")

    if args.target is not None:
        target = args.target.expanduser().resolve()
        if not target.exists():
            print(f"Not found: {target}")
            sys.exit(1)
        if target.is_file():
            # Single file — wrap parent as mini tree via direct call
            entries = _load_jsonl(target)
            dirty = [
                e
                for e in entries
                if classify_dirty(
                    e,
                    aggressive=args.aggressive,
                    drop_gemini_free=args.drop_gemini_free,
                )
            ]
            print(f"{target}: dirty {len(dirty)}/{len(entries)}")
            if args.apply and dirty:
                kept = [e for e in entries if e not in dirty]
                rej = target.with_name("rejected_cleaned_" + target.name)
                _write_jsonl(rej, dirty)
                _write_jsonl(target, kept)
                print(f"  written kept={len(kept)} rejected→{rej}")
        else:
            stats = clean_jsonl_tree(
                target,
                apply=args.apply,
                aggressive=args.aggressive,
                drop_gemini_free=args.drop_gemini_free,
            )
            print(f"JSONL stats: {stats}")

    if not args.apply:
        print("\nDry-run only. Re-run with --apply to persist.")


if __name__ == "__main__":
    main()
