#!/usr/bin/env python
"""Scoped historical fix for misclassified gateway / official hosts.

Targets ONLY these production cases (and their key/evidence fingerprints):

1. ``llm.alem.ai`` — LiteLLM proxy (``/key/info`` budget envelope)
2. ``dashscope-intl.aliyuncs.com`` (+ other DashScope hosts) — Qwen / 百炼
3. ``apinet.cloud`` — NewAPI (billing + /api/status fingerprints)
4. ``142.171.135.205:3000`` — NewAPI self-host
5. ``213.142.134.36`` / ``sk-vxia-*`` — Voxia local OpenAI-compatible proxy

What it does (per matched row only):

* Re-set ``validation_provider`` / ``provider`` / ``credential_issuer`` columns
  and nested ``record.provider_info``
* Normalize ``gateway`` probe name (``newapi_billing`` → provider ``newapi``;
  ``dashscope`` → provider ``qwen``; ``litellm`` → provider ``litellm``)
* Optionally live-reprobe balance/quota for matched rows (``--reprobe``)
* Sync matching ``high_value_keys`` rows the same way

Safety:

* Default is **dry-run** (print counts / samples, no writes)
* ``--apply`` required to write
* Advisory xact lock shared with other data-quality scripts
* SQL WHERE scopes only the host/key patterns above — other rows are never
  scanned for mutation
* Does not delete rows, does not touch candidates / request_ledger / runs

Docker (on locvps)::

    # Inspect first
    docker compose exec backend uv run python scripts/oneoff/fix_gateway_provider_hosts.py

    # Apply classification only (no live HTTP)
    docker compose exec backend uv run python scripts/oneoff/fix_gateway_provider_hosts.py --apply

    # Apply + re-probe balance/quota endpoints for matched hosts
    docker compose exec backend uv run python scripts/oneoff/fix_gateway_provider_hosts.py --apply --reprobe

Local::

    cd backend && uv run python scripts/oneoff/fix_gateway_provider_hosts.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from psycopg.types.json import Jsonb

# Make package importable when run as a plain script.
_HERE = Path(__file__).resolve()
_SRC = _HERE.parents[2] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from _data_quality_common import configure_database, locked_transaction  # noqa: E402

from aipocket.core.models import Credential  # noqa: E402
from aipocket.services.providers import resolve_provider  # noqa: E402

# ---------------------------------------------------------------------------
# Scope: only these patterns. Keep tight so other production data is untouched.
# ---------------------------------------------------------------------------
_HOST_PATTERNS: tuple[tuple[str, str], ...] = (
    # (sql ILIKE fragment, class_hint)
    ("%llm.alem.ai%", "litellm"),
    ("%dashscope-intl.aliyuncs.com%", "qwen"),
    ("%dashscope.aliyuncs.com%", "qwen"),
    ("%dashscope-us.aliyuncs.com%", "qwen"),
    ("%apinet.cloud%", "newapi"),
    ("%142.171.135.205%", "newapi"),
    ("%213.142.134.36%", "voxia"),
)

_KEY_PREFIX_HINTS: tuple[tuple[str, str], ...] = (("sk-vxia-", "voxia"),)

_GATEWAY_TO_PROVIDER: dict[str, str] = {
    "litellm": "litellm",
    "newapi": "newapi",
    "newapi_billing": "newapi",
    "oneapi": "oneapi",
    "dashscope": "qwen",
    "qwen": "qwen",
}

_OFFICIAL_CATEGORY = {
    "qwen": "domestic",
    "litellm": "gateway",
    "newapi": "gateway",
    "oneapi": "gateway",
    "voxia": "gateway",
    "gateway": "gateway",
}


def _hostname(apiurl: str) -> str:
    candidate = (apiurl or "").strip().lower()
    if not candidate:
        return ""
    try:
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    except ValueError:
        return ""
    return (parsed.hostname or "").rstrip(".")


def _sql_scope() -> tuple[str, list[Any]]:
    """Return WHERE clause + params that select only in-scope rows."""
    host_clauses = " OR ".join(["apiurl ILIKE %s"] * len(_HOST_PATTERNS))
    key_clauses = " OR ".join(["apikey LIKE %s"] * len(_KEY_PREFIX_HINTS))
    params: list[Any] = [pat for pat, _ in _HOST_PATTERNS]
    params.extend([f"{pfx}%" for pfx, _ in _KEY_PREFIX_HINTS])
    # Also match keys nested only in record JSON (defensive for flat HV table)
    where = f"({host_clauses} OR {key_clauses})"
    return where, params


def _class_from_url_key(apiurl: str, apikey: str) -> str | None:
    host = _hostname(apiurl)
    lower_url = (apiurl or "").lower()
    for fragment, hint in _HOST_PATTERNS:
        needle = fragment.strip("%").lower()
        if needle and (needle in host or needle in lower_url):
            return hint
    for pfx, hint in _KEY_PREFIX_HINTS:
        if (apikey or "").startswith(pfx):
            return hint
    return None


def _gateway_of(record: dict[str, Any]) -> str:
    gw = str(record.get("gateway") or "").strip().lower()
    if gw:
        return gw
    info = record.get("provider_info")
    if isinstance(info, dict):
        bp = str(info.get("balance_provider") or "").strip().lower()
        if bp:
            return bp
    headers = record.get("rate_limit_headers")
    if isinstance(headers, dict):
        detail = headers.get("balance_detail")
        text = str(detail or "")
        for name in ("newapi_billing", "newapi", "litellm", "dashscope", "oneapi"):
            if name in text:
                return name
    return ""


def _resolve_target_provider(
    apiurl: str,
    apikey: str,
    record: dict[str, Any],
    class_hint: str | None,
) -> tuple[str, str]:
    """Return (provider, reason) using registry + historical gateway evidence."""
    decision = resolve_provider(apiurl=apiurl, apikey=apikey)
    provider = decision.provider
    reason = decision.reason

    # Official domain match wins (e.g. dashscope-intl → qwen after registry fix).
    if provider not in {"gateway", "unknown", "ambiguous", ""}:
        return provider, f"registry:{reason}"

    gw = _gateway_of(record)
    if gw in _GATEWAY_TO_PROVIDER:
        return _GATEWAY_TO_PROVIDER[gw], f"gateway_field:{gw}"

    if class_hint in {"litellm", "newapi", "oneapi", "qwen"}:
        return class_hint, f"host_hint:{class_hint}"
    # Voxia is a product fingerprint, not in ProviderName vocabulary yet.
    # Keep validation_provider=gateway; gateway label is set separately to "voxia".
    if class_hint == "voxia":
        return "gateway", "host_hint:voxia"

    if provider in {"", "unknown", "ambiguous"}:
        return "gateway", "fallback_gateway"
    return provider, f"registry:{reason}"


def _set_provider_fields(
    record: dict[str, Any], provider: str, *, gateway: str | None = None
) -> None:
    info = record.get("provider_info")
    if not isinstance(info, dict):
        info = {}
        record["provider_info"] = info
    info["validation_provider"] = provider
    info["provider"] = provider
    info["category"] = _OFFICIAL_CATEGORY.get(provider, "gateway")
    if info.get("credential_issuer") in {None, "", "unknown", "gateway"} and provider not in {
        "gateway",
        "unknown",
        "ambiguous",
    }:
        info["credential_issuer"] = provider
    if gateway:
        record["gateway"] = gateway
        info["balance_provider"] = (
            gateway if gateway not in {"unsupported", ""} else info.get("balance_provider", "")
        )


def _normalize_gateway_label(
    provider: str, existing_gw: str, *, class_hint: str | None = None
) -> str:
    """Canonical gateway label written back to record.gateway."""
    existing = (existing_gw or "").strip().lower()
    if class_hint == "voxia" or existing == "voxia":
        return "voxia"
    if provider == "qwen":
        return "dashscope" if existing in {"", "unsupported", "gateway", "dashscope"} else existing
    if provider == "newapi":
        # Keep newapi_billing as probe source when that was the hit; else newapi.
        if existing in {"newapi_billing", "newapi"}:
            return existing
        return "newapi"
    if provider == "litellm":
        return "litellm"
    if existing and existing not in {"", "unsupported"}:
        return existing
    return provider if provider not in {"gateway", "unknown"} else existing or "unsupported"


def _patch_record(
    record: dict[str, Any],
    *,
    apiurl: str,
    apikey: str,
    class_hint: str | None,
    balance_patch: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (new_record, change_summary)."""
    old_info = record.get("provider_info") if isinstance(record.get("provider_info"), dict) else {}
    old_provider = str(
        old_info.get("validation_provider")
        or old_info.get("provider")
        or record.get("validation_provider")
        or "unknown"
    )
    old_gw = str(record.get("gateway") or "")
    old_bal = str(record.get("balance") or "")

    provider, reason = _resolve_target_provider(apiurl, apikey, record, class_hint)
    new_gw = _normalize_gateway_label(provider, old_gw, class_hint=class_hint)
    new_record = dict(record)
    _set_provider_fields(new_record, provider, gateway=new_gw)
    # Voxia: no cash/quota API. Mark liveness-only so UI does not look "broken".
    if class_hint == "voxia" and not balance_patch:
        if new_record.get("balance") in (None, ""):
            new_record["balance"] = "N/A"
        headers = new_record.get("rate_limit_headers")
        if not isinstance(headers, dict):
            headers = {}
            new_record["rate_limit_headers"] = headers
        if not headers.get("balance_detail"):
            headers["balance_detail"] = str(
                {
                    "gateway": "voxia",
                    "balance_usd": "N/A",
                    "source": "voxia:no_public_balance",
                    "note": (
                        "Voxia (sk-vxia-*) OpenAI-compatible local proxy; "
                        "only /v1/models found — no billing/quota/usage endpoint"
                    ),
                }
            )

    if balance_patch:
        bal = balance_patch.get("balance_usd", "")
        if bal != "" and bal is not None:
            new_record["balance"] = str(bal)
        if balance_patch.get("tier"):
            new_record["tier"] = str(balance_patch["tier"])
        gw = str(balance_patch.get("gateway") or new_gw)
        new_record["gateway"] = gw
        info = new_record.get("provider_info")
        if isinstance(info, dict):
            info["balance_provider"] = gw
            # Live probe may refine provider (e.g. gateway → litellm/newapi).
            probed_provider = str(balance_patch.get("provider") or "")
            if probed_provider and probed_provider not in {"", "unsupported", "unknown"}:
                info["validation_provider"] = probed_provider
                info["provider"] = probed_provider
                if info.get("credential_issuer") in {None, "", "unknown", "gateway"}:
                    info["credential_issuer"] = probed_provider
                provider = probed_provider
        headers = new_record.get("rate_limit_headers")
        if not isinstance(headers, dict):
            headers = {}
            new_record["rate_limit_headers"] = headers
        detail = {
            "gateway": gw,
            "balance_usd": bal,
            "source": balance_patch.get("source", ""),
            "note": balance_patch.get("note", ""),
            "quota": balance_patch.get("quota"),
            "usage": balance_patch.get("usage"),
        }
        headers["balance_detail"] = str({k: v for k, v in detail.items() if v not in (None, "")})

    summary = {
        "old_provider": old_provider,
        "new_provider": provider,
        "old_gateway": old_gw,
        "new_gateway": new_record.get("gateway", ""),
        "old_balance": old_bal,
        "new_balance": str(new_record.get("balance") or ""),
        "reason": reason,
        "changed": (
            old_provider != provider
            or old_gw != str(new_record.get("gateway") or "")
            or (balance_patch is not None and old_bal != str(new_record.get("balance") or ""))
        ),
    }
    return new_record, summary


async def _reprobe_one(apiurl: str, apikey: str) -> dict[str, Any] | None:
    import httpx

    from aipocket.services.balance import query_balance

    if not apikey or not apiurl:
        return None
    cred = Credential(apikey=apikey, apiurl=apiurl)
    timeout = httpx.Timeout(20.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=False, follow_redirects=True
        ) as client:
            result = await query_balance(client, cred)
    except Exception as exc:  # noqa: BLE001 — one-off; keep going
        return {"error": f"{type(exc).__name__}: {exc}"}
    if not result:
        return None
    # Attach resolved provider from dispatch when present.
    out = dict(result)
    if "provider" not in out and out.get("gateway"):
        gw = str(out["gateway"])
        out["provider"] = _GATEWAY_TO_PROVIDER.get(gw, gw)
    return out


def _extract_cred(row: dict[str, Any]) -> tuple[str, str]:
    apiurl = str(row.get("apiurl") or "")
    apikey = str(row.get("apikey") or "")
    rec = row.get("record")
    if isinstance(rec, str):
        rec = json.loads(rec)
    if isinstance(rec, dict):
        if not apiurl:
            cred = rec.get("credential")
            if isinstance(cred, dict):
                apiurl = str(cred.get("apiurl") or "")
                apikey = apikey or str(cred.get("apikey") or "")
            apiurl = apiurl or str(rec.get("apiurl") or "")
        if not apikey:
            cred = rec.get("credential")
            if isinstance(cred, dict):
                apikey = str(cred.get("apikey") or "")
            apikey = apikey or str(rec.get("apikey") or "")
    return apiurl, apikey


async def _maybe_reprobe_map(
    rows_meta: list[tuple[Any, str, str]],
    *,
    reprobe: bool,
    concurrency: int,
) -> dict[Any, dict[str, Any]]:
    if not reprobe:
        return {}
    sem = asyncio.Semaphore(max(1, concurrency))
    out: dict[Any, dict[str, Any]] = {}

    async def one(rid: Any, apiurl: str, apikey: str) -> None:
        async with sem:
            result = await _reprobe_one(apiurl, apikey)
            if result is not None:
                out[rid] = result

    await asyncio.gather(*[one(rid, u, k) for rid, u, k in rows_meta])
    return out


def run(conn: Any, args: argparse.Namespace) -> dict[str, Any]:
    scope_sql, scope_params = _sql_scope()
    limit_sql = " LIMIT %s" if args.limit > 0 else ""
    params = list(scope_params)
    if args.limit > 0:
        params.append(args.limit)

    results_sql = f"""
        SELECT id, run_id, kind, apiurl, apikey, validation_provider, credential_issuer, record
        FROM results
        WHERE {scope_sql}
        ORDER BY id
        {limit_sql}
    """
    result_rows = [dict(r) for r in conn.execute(results_sql, tuple(params)).fetchall()]

    # high_value_keys: match by apiurl inside record or apikey prefix
    hv_clauses = []
    hv_params: list[Any] = []
    for pat, _ in _HOST_PATTERNS:
        hv_clauses.append("record::text ILIKE %s")
        hv_params.append(pat)
    for pfx, _ in _KEY_PREFIX_HINTS:
        hv_clauses.append("apikey LIKE %s")
        hv_params.append(f"{pfx}%")
    hv_sql = f"""
        SELECT apikey, run_id, record
        FROM high_value_keys
        WHERE {" OR ".join(hv_clauses)}
        ORDER BY apikey
        {limit_sql}
    """
    if args.limit > 0:
        hv_params.append(args.limit)
    hv_rows = [dict(r) for r in conn.execute(hv_sql, tuple(hv_params)).fetchall()]

    # Live re-probe map (optional)
    reprobe_targets: list[tuple[Any, str, str]] = []
    for row in result_rows:
        apiurl, apikey = _extract_cred(row)
        if apiurl and apikey:
            reprobe_targets.append((("results", row["id"]), apiurl, apikey))
    for row in hv_rows:
        apiurl, apikey = _extract_cred(row)
        if apiurl and apikey:
            reprobe_targets.append((("hv", row["apikey"], row["run_id"]), apiurl, apikey))

    balance_map: dict[Any, dict[str, Any]] = {}
    if args.reprobe and reprobe_targets:
        balance_map = asyncio.run(
            _maybe_reprobe_map(
                reprobe_targets,
                reprobe=True,
                concurrency=args.concurrency,
            )
        )

    changed_results = 0
    changed_hv = 0
    samples: list[dict[str, Any]] = []

    for row in result_rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        record = dict(rec) if isinstance(rec, dict) else {}
        apiurl, apikey = _extract_cred(row)
        class_hint = _class_from_url_key(apiurl, apikey)
        bal = balance_map.get(("results", row["id"]))
        new_record, summary = _patch_record(
            record,
            apiurl=apiurl,
            apikey=apikey,
            class_hint=class_hint,
            balance_patch=bal if bal and "error" not in bal else None,
        )
        if not summary["changed"]:
            continue
        changed_results += 1
        if len(samples) < args.samples:
            samples.append(
                {
                    "table": "results",
                    "id": row["id"],
                    "apiurl": apiurl[:80],
                    "kind": row.get("kind"),
                    **summary,
                }
            )
        if args.apply:
            info = (
                new_record.get("provider_info")
                if isinstance(new_record.get("provider_info"), dict)
                else {}
            )
            conn.execute(
                """
                UPDATE results
                SET validation_provider = %s,
                    credential_issuer = %s,
                    record = %s
                WHERE id = %s
                """,
                (
                    str(info.get("validation_provider") or summary["new_provider"]),
                    str(info.get("credential_issuer") or "unknown"),
                    Jsonb(new_record),
                    row["id"],
                ),
            )

    for row in hv_rows:
        rec = row["record"]
        if isinstance(rec, str):
            rec = json.loads(rec)
        record = dict(rec) if isinstance(rec, dict) else {}
        apiurl, apikey = _extract_cred(row)
        class_hint = _class_from_url_key(apiurl, apikey)
        bal = balance_map.get(("hv", row["apikey"], row["run_id"]))
        new_record, summary = _patch_record(
            record,
            apiurl=apiurl,
            apikey=apikey,
            class_hint=class_hint,
            balance_patch=bal if bal and "error" not in bal else None,
        )
        # Flat HV fields
        if "provider" in new_record or isinstance(new_record.get("provider_info"), dict):
            info = new_record.get("provider_info")
            if isinstance(info, dict):
                new_record["provider"] = info.get("provider") or new_record.get("provider")
        if not summary["changed"] and str(record.get("provider") or "") == str(
            new_record.get("provider") or ""
        ):
            # still check flat provider field
            old_flat = str(record.get("provider") or "")
            new_flat = str(new_record.get("provider") or summary["new_provider"])
            if old_flat == new_flat:
                continue
            summary["changed"] = True
        if not summary["changed"]:
            continue
        changed_hv += 1
        if len(samples) < args.samples:
            samples.append(
                {
                    "table": "high_value_keys",
                    "apikey_prefix": (apikey or "")[:12],
                    "apiurl": apiurl[:80],
                    **summary,
                }
            )
        if args.apply:
            conn.execute(
                "UPDATE high_value_keys SET record = %s WHERE apikey = %s AND run_id = %s",
                (Jsonb(new_record), row["apikey"], row["run_id"]),
            )

    return {
        "results_scanned": len(result_rows),
        "results_changed": changed_results,
        "high_value_scanned": len(hv_rows),
        "high_value_changed": changed_hv,
        "reprobe": bool(args.reprobe),
        "reprobe_results": len(
            [k for k in balance_map if isinstance(k, tuple) and k and k[0] == "results"]
        ),
        "samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default="")
    parser.add_argument("--limit", type=int, default=0, help="Max rows per table (0=all scoped)")
    parser.add_argument("--samples", type=int, default=20, help="How many change samples to print")
    parser.add_argument(
        "--reprobe", action="store_true", help="Live re-probe balance for scoped rows"
    )
    parser.add_argument("--concurrency", type=int, default=8)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    configure_database(args.database_url)
    args.apply = bool(args.apply)
    args.dry_run = not args.apply

    with locked_transaction(apply=args.apply) as conn:
        summary = run(conn, args)

    print("mode=apply" if args.apply else "mode=dry-run")
    for key, value in summary.items():
        if key == "samples":
            print(f"samples={len(value)}")
            for item in value:
                print("  -", json.dumps(item, ensure_ascii=False, default=str))
        else:
            print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
