#!/usr/bin/env python
"""Backfill provider=unknown → correct classification for existing records.

Historical results were written when ``resolve_provider`` fell back to
``unknown`` for every unmatched domain+key combo. Third-party OpenAI-compatible
endpoints (NewAPI/OneAPI/self-hosted relays, sites like apinet.cloud, random
VPS hosts) should be labeled ``gateway``.

This script re-runs the current registry logic on stored records and patches:

  * PostgreSQL ``results.record``  (nested ValidationResult: provider_info.provider)
  * PostgreSQL ``high_value_keys.record``  (flat: provider)
  * On-disk JSONL under RESULTS_DIR (valid_*.jsonl, suspicious_*.jsonl, keys.jsonl)

Dry-run by default; pass ``--apply`` to write.

Docker (on VPS)::

    # Dry-run first — show what would change
    docker compose exec backend uv run python scripts/oneoff/backfill_unknown_provider.py

    # Apply
    docker compose exec backend uv run python scripts/oneoff/backfill_unknown_provider.py --apply

    # Or one-shot without attaching to the running container:
    docker compose run --rm backend uv run python scripts/oneoff/backfill_unknown_provider.py --apply

Local::

    cd backend && uv run python scripts/oneoff/backfill_unknown_provider.py --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

# Make the package importable when run as a plain script from various CWDs.
_HERE = Path(__file__).resolve()
_SRC = _HERE.parents[2] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aipocket.core.config import settings  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("backfill_unknown_provider")

# Balance-probe gateway names that map onto the canonical ProviderName set.
_BALANCE_TO_PROVIDER: dict[str, str] = {
    "openai": "openai",
    "openrouter": "openrouter",
    "deepseek": "deepseek",
    "moonshot": "kimi",
    "glm": "glm",
    "siliconflow": "siliconflow",
    # Everything else that successfully identified a gateway product stays "gateway".
    "litellm": "gateway",
    "oneapi": "gateway",
    "newapi": "gateway",
    "newapi_billing": "gateway",
    "nexus": "gateway",
}


def _resolve(apiurl: str, apikey: str) -> tuple[str, str]:
    """Classify via current registry (gateway fallback for unmatched endpoints).

    Import is deferred so the script can still print a useful error when the
    package is missing, and so dry-runs on an older image still work if the
    registry has already been patched.
    """
    from aipocket.services.providers import resolve_provider

    decision = resolve_provider(apiurl=apiurl, apikey=apikey)
    provider = decision.provider
    category = decision.category
    # Defensive: older deploys that still fall back to ``unknown`` for every
    # unmatched endpoint — promote those with a concrete apiurl to gateway.
    if provider == "unknown" and apiurl.strip():
        return "gateway", "gateway"
    return provider, category


def _cred_fields(rec: dict[str, Any]) -> tuple[str, str]:
    """Extract (apikey, apiurl) from either nested ValidationResult or flat HV entry."""
    cred = rec.get("credential")
    if isinstance(cred, dict):
        return str(cred.get("apikey") or ""), str(cred.get("apiurl") or "")
    return str(rec.get("apikey") or ""), str(rec.get("apiurl") or "")


def _current_provider(rec: dict[str, Any]) -> str:
    info = rec.get("provider_info")
    if isinstance(info, dict) and info.get("provider"):
        return str(info["provider"])
    return str(rec.get("provider") or "unknown")


def _balance_hint(rec: dict[str, Any]) -> str:
    """Prefer balance_provider / gateway field when present."""
    info = rec.get("provider_info")
    if isinstance(info, dict):
        bp = str(info.get("balance_provider") or "").strip().lower()
        if bp and bp not in {"", "unsupported", "unknown"}:
            return bp
    gw = str(rec.get("gateway") or "").strip().lower()
    if gw and gw not in {"", "unsupported", "unknown"}:
        return gw
    return ""


def classify_provider(rec: dict[str, Any]) -> tuple[str, str]:
    """Return (provider, category) using registry + optional balance hint.

    Only rewrites when the stored value is empty/unknown (or missing). Known
    official labels are left alone.
    """
    current = _current_provider(rec).strip().lower() or "unknown"
    if current not in {"", "unknown"}:
        return current, _category_for(current)

    apikey, apiurl = _cred_fields(rec)
    provider, category = _resolve(apiurl, apikey)

    # If registry still says unknown/gateway, a successful balance probe for a
    # known official product can refine the label.
    hint = _balance_hint(rec)
    if hint in _BALANCE_TO_PROVIDER and provider in {"unknown", "gateway"}:
        mapped = _BALANCE_TO_PROVIDER[hint]
        if mapped != "gateway" or provider == "unknown":
            provider = mapped
            category = _category_for(provider)

    return provider, category


def _category_for(provider: str) -> str:
    from aipocket.services.providers import provider_registry

    try:
        return provider_registry.get(provider).category  # type: ignore[arg-type]
    except KeyError:
        if provider in {"openrouter", "gateway"}:
            return "gateway"
        if provider in {
            "deepseek",
            "kimi",
            "glm",
            "qwen",
            "siliconflow",
        }:
            return "domestic"
        if provider in {
            "openai",
            "anthropic",
            "google",
            "groq",
            "azure_openai",
            "vertex",
            "gemini",
        }:
            return "international"
        return "unknown"


def patch_record(rec: dict[str, Any]) -> tuple[dict[str, Any], bool, str, str]:
    """Return (patched_rec, changed, old_provider, new_provider)."""
    old = _current_provider(rec)
    new_provider, new_category = classify_provider(rec)
    if old == new_provider:
        return rec, False, old, new_provider

    out = dict(rec)
    # Nested ValidationResult shape (results / valid_*.jsonl)
    info = out.get("provider_info")
    if isinstance(info, dict) or "provider_info" in out or "credential" in out:
        pi = dict(info) if isinstance(info, dict) else {}
        pi["provider"] = new_provider
        pi["category"] = new_category
        out["provider_info"] = pi
    # Flat high-value shape
    if "provider" in out or "credential" not in out:
        out["provider"] = new_provider
    return out, True, old, new_provider


# ---------------------------------------------------------------------------
# JSONL on disk
# ---------------------------------------------------------------------------


def patch_jsonl_file(path: Path, *, apply: bool) -> tuple[int, int]:
    """Patch one JSONL file. Returns (total_records, changed)."""
    if not path.exists():
        return 0, 0
    lines = path.read_text(encoding="utf-8").splitlines()
    total = 0
    changed = 0
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = json.loads(stripped)
        except json.JSONDecodeError:
            out_lines.append(line)
            continue
        if not isinstance(rec, dict):
            out_lines.append(line)
            continue
        # Skip scan metadata headers (no credential / apikey)
        if "credential" not in rec and "apikey" not in rec:
            out_lines.append(line)
            continue
        total += 1
        patched, did, old, new = patch_record(rec)
        if did:
            changed += 1
            log.info("  %s: %s → %s  (%s)", path.name, old, new, _cred_fields(rec)[1][:60])
            out_lines.append(json.dumps(patched, ensure_ascii=False, default=str))
        else:
            out_lines.append(json.dumps(rec, ensure_ascii=False, default=str))

    if apply and changed:
        bak = path.with_suffix(path.suffix + ".bak")
        if not bak.exists():
            shutil.copy2(path, bak)
            log.info("  backup → %s", bak)
        path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return total, changed


def patch_disk_results(*, apply: bool) -> tuple[int, int]:
    root = settings.results_path
    if not root.exists():
        log.warning("RESULTS_DIR does not exist: %s", root)
        return 0, 0
    total = changed = 0
    for pattern in (
        "run_*/valid_*.jsonl",
        "run_*/suspicious_*.jsonl",
        "high_value_keys/keys.jsonl",
    ):
        for path in sorted(root.glob(pattern)):
            # Skip backups
            if path.name.endswith(".bak") or ".bak" in path.suffixes:
                continue
            t, c = patch_jsonl_file(path, apply=apply)
            if t:
                log.info("%s: records=%d changed=%d", path, t, c)
            total += t
            changed += c
    return total, changed


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


def patch_pg(*, apply: bool) -> tuple[int, int]:
    if not settings.pg_enabled:
        log.info("PG disabled (no DATABASE_URL) — skipping DB patch")
        return 0, 0

    from psycopg.types.json import Jsonb

    from aipocket.core.db import ensure_schema, get_pool

    ensure_schema()
    pool = get_pool()
    total = changed = 0

    with pool.connection() as conn:
        # --- results ---
        rows = conn.execute(
            "SELECT id, record FROM results WHERE kind IN ('valid', 'suspicious') ORDER BY id"
        ).fetchall()
        for row in rows:
            rec = row["record"]
            if not isinstance(rec, dict):
                continue
            total += 1
            patched, did, old, new = patch_record(rec)
            if not did:
                continue
            changed += 1
            apiurl = _cred_fields(rec)[1]
            log.info("  results id=%s: %s → %s  (%s)", row["id"], old, new, apiurl[:60])
            if apply:
                conn.execute(
                    "UPDATE results SET record = %s WHERE id = %s",
                    (Jsonb(patched), row["id"]),
                )

        # --- high_value_keys ---
        hv_rows = conn.execute("SELECT apikey, record FROM high_value_keys").fetchall()
        for row in hv_rows:
            rec = row["record"]
            if not isinstance(rec, dict):
                continue
            total += 1
            patched, did, old, new = patch_record(rec)
            if not did:
                continue
            changed += 1
            apiurl = _cred_fields(rec)[1]
            masked = (row["apikey"] or "")[:8] + "…"
            log.info("  high_value %s: %s → %s  (%s)", masked, old, new, apiurl[:60])
            if apply:
                conn.execute(
                    "UPDATE high_value_keys SET record = %s WHERE apikey = %s",
                    (Jsonb(patched), row["apikey"]),
                )

        if apply and changed:
            conn.commit()
            log.info("PG committed %d updates", changed)
        elif not apply:
            conn.rollback()

    return total, changed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill provider=unknown → gateway (or refined) for stored records"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes (default is dry-run)",
    )
    parser.add_argument(
        "--pg-only",
        action="store_true",
        help="Only patch PostgreSQL",
    )
    parser.add_argument(
        "--disk-only",
        action="store_true",
        help="Only patch on-disk JSONL under RESULTS_DIR",
    )
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=== backfill_unknown_provider [%s] ===", mode)
    log.info("RESULTS_DIR=%s  pg_enabled=%s", settings.results_path, settings.pg_enabled)

    grand_total = grand_changed = 0

    if not args.disk_only:
        t, c = patch_pg(apply=args.apply)
        log.info("PG: records=%d changed=%d", t, c)
        grand_total += t
        grand_changed += c

    if not args.pg_only:
        t, c = patch_disk_results(apply=args.apply)
        log.info("Disk: records=%d changed=%d", t, c)
        grand_total += t
        grand_changed += c

    log.info("TOTAL records=%d changed=%d", grand_total, grand_changed)
    if not args.apply and grand_changed:
        log.info("Re-run with --apply to write these changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
