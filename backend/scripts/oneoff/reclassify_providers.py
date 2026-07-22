#!/usr/bin/env python
from __future__ import annotations

from typing import Any

from _data_quality_common import limit_clause, main, rows
from psycopg.types.json import Jsonb

from aipocket.services.providers import resolve_provider

_NEWAPI_FIELDS = {"quota_per_unit", "stripe_unit_price", "self_use_mode_enabled", "system_name", "version"}


def _contains_newapi_contract(value: Any) -> bool:
    if isinstance(value, dict):
        keys = set(value)
        status = len(keys & _NEWAPI_FIELDS) >= 3
        billing = value.get("object") in {"billing_subscription", "list"}
        user = value.get("success") is True and isinstance(value.get("data"), dict) and isinstance(value["data"].get("quota"), int | float)
        signals = sum((status, billing, user))
        return signals >= 2 or any(_contains_newapi_contract(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_newapi_contract(item) for item in value)
    return False


def run(conn: Any, args: Any) -> dict[str, Any]:
    where = " WHERE 1=1"
    params: list[Any] = []
    if args.run_id:
        where += " AND run_id=%s"
        params.append(args.run_id)
    sql = "SELECT id, apiurl, apikey, record FROM results" + where + " ORDER BY id"
    if args.limit > 0:
        sql += limit_clause(args.limit)
        params.append(args.limit)
    changed = 0
    scanned = 0
    for row in rows(conn, sql, tuple(params)):
        scanned += 1
        record = dict(row["record"])
        provider_info = record.get("provider_info")
        if not isinstance(provider_info, dict):
            provider_info = {}
            record["provider_info"] = provider_info
        decision = resolve_provider(apiurl=str(row.get("apiurl") or ""), apikey=str(row.get("apikey") or ""))
        provider = decision.provider
        if provider == "gateway" and _contains_newapi_contract(record):
            provider = "newapi"
        old = str(provider_info.get("validation_provider") or provider_info.get("provider") or "unknown")
        if old == provider:
            continue
        provider_info["validation_provider"] = provider
        provider_info["provider"] = provider
        if provider_info.get("credential_issuer") in {None, "", "unknown", "gateway"} and provider not in {"gateway", "unknown", "ambiguous"}:
            provider_info["credential_issuer"] = provider
        changed += 1
        if args.apply:
            conn.execute(
                "UPDATE results SET validation_provider=%s, credential_issuer=%s, record=%s WHERE id=%s",
                (provider, provider_info.get("credential_issuer") or "unknown", Jsonb(record), row["id"]),
            )
    return {"scanned": scanned, "changed": changed}


if __name__ == "__main__":
    raise SystemExit(main("Reclassify stored providers", run))
