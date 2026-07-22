#!/usr/bin/env python
from __future__ import annotations

from typing import Any

from _data_quality_common import limit_clause, main, rows
from psycopg.types.json import Jsonb

from aipocket.services.providers import resolve_provider
from aipocket.services.providers.endpoints import canonicalize_endpoint


def _credential(record: dict[str, Any]) -> dict[str, Any]:
    nested = record.get("credential")
    return nested if isinstance(nested, dict) else record


def run(conn: Any, args: Any) -> dict[str, Any]:
    tables = (
        ("results", "id", "record"),
        ("high_value_keys", "apikey", "record"),
        ("scan_candidates", "id", "record"),
        ("scan_validation_results", "id", "record"),
    )
    changed = 0
    scanned = 0
    for table, key, record_column in tables:
        clauses: list[str] = []
        params: list[Any] = []
        if getattr(args, "run_id", ""):
            clauses.append("run_id = %s")
            params.append(args.run_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT {key}, {record_column} FROM {table}{where} ORDER BY {key}"
        if args.limit > 0:
            sql += limit_clause(args.limit)
            params.append(args.limit)
        for row in rows(conn, sql, tuple(params)):
            scanned += 1
            record = dict(row[record_column])
            credential = _credential(record)
            apiurl = str(credential.get("apiurl") or "")
            apikey = str(credential.get("apikey") or record.get("apikey") or "")
            provider_info = record.get("provider_info")
            provider = ""
            if isinstance(provider_info, dict):
                provider = str(provider_info.get("validation_provider") or provider_info.get("provider") or "")
            provider = provider or resolve_provider(apiurl=apiurl, apikey=apikey).provider
            endpoint = canonicalize_endpoint(apiurl, provider=provider)
            if not endpoint.api_base or (
                credential.get("apiurl") == endpoint.api_base
                and credential.get("host") == endpoint.origin
            ):
                continue
            credential["apiurl"] = endpoint.api_base
            credential["host"] = endpoint.origin
            changed += 1
            if not args.apply:
                continue
            if table == "results":
                conn.execute(
                    "UPDATE results SET apiurl=%s, host=%s, record=%s WHERE id=%s",
                    (endpoint.api_base, endpoint.origin, Jsonb(record), row[key]),
                )
            elif table == "scan_candidates":
                conn.execute(
                    "UPDATE scan_candidates SET apiurl=%s, host=%s, record=%s WHERE id=%s",
                    (endpoint.api_base, endpoint.origin, Jsonb(record), row[key]),
                )
            else:
                conn.execute(f"UPDATE {table} SET record=%s WHERE {key}=%s", (Jsonb(record), row[key]))
    return {"scanned": scanned, "changed": changed}


if __name__ == "__main__":
    raise SystemExit(main("Canonicalize stored endpoint fields", run))
