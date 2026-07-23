"""Spill full FOFA/Shodan discovery hits to PostgreSQL (memory-bounded path).

Full hit payloads (body/banner/header) must remain available for GPT extract
without retaining O(total_hits) records in process RAM. When ``DATABASE_URL``
is unset, all functions are no-ops / empty returns (in-memory path for tests).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from typing import Any

from aipocket.core.targets import _identity
from aipocket.services.candidate_store import spill_enabled

log = logging.getLogger(__name__)

# PostgreSQL text / jsonb reject U+0000. Shodan/FOFA banners sometimes embed
# raw NUL bytes (e.g. React Flight / binary-ish HTML), which then abort the
# whole discovery source if we spill the hit as-is.
_NUL = "\x00"


def _strip_nul(value: Any) -> Any:
    """Recursively remove NUL bytes so payloads are safe for PG text/jsonb."""
    if isinstance(value, str):
        return value.replace(_NUL, "") if _NUL in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_strip_nul(v) for v in value)
    return value


def entry_id_for_hit(hit: dict[str, Any]) -> str:
    """Stable identity for a host hit (SHA1 of scheme://host:port)."""
    identity = _identity(hit)
    if identity is None:
        # Fallback: hash raw host/ip/port so we still persist the row.
        import hashlib

        raw = (
            f"{hit.get('host') or ''}|{hit.get('ip') or ''}|"
            f"{hit.get('port') or ''}|{hit.get('link') or ''}"
        )
        return hashlib.sha1(raw.encode()).hexdigest()
    return identity.identity_hash


def _row(run_id: str, source: str, hit: dict[str, Any]) -> tuple:
    from psycopg.types.json import Jsonb

    # Sanitize before identity/text columns and jsonb so a single poisoned
    # banner cannot abort an entire FOFA/Shodan spill batch.
    clean = _strip_nul(hit)
    if not isinstance(clean, dict):
        clean = hit
    entry_id = entry_id_for_hit(clean)
    return (
        run_id,
        source or str(clean.get("_source") or ""),
        entry_id,
        str(clean.get("_query_id") or clean.get("query") or ""),
        str(clean.get("host") or clean.get("link") or ""),
        str(clean.get("ip") or ""),
        str(clean.get("port") or ""),
        str(clean.get("protocol") or ""),
        Jsonb(clean),
    )


def upsert_hits(run_id: str, source: str, hits: Sequence[dict[str, Any]]) -> int:
    """Batch-upsert full hit records. Returns number of rows attempted.

    On conflict of ``(run_id, entry_id)`` the stored record is replaced when the
    new payload is larger (more content evidence); provenance tags are merged
    into ``_source`` / ``_query_ids`` when present on either side.
    """
    if not spill_enabled() or not run_id or not hits:
        return 0

    rows = [_row(run_id, source, h) for h in hits if isinstance(h, dict)]
    if not rows:
        return 0

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        # Prefer executemany with a merge that preserves full payload.
        # Read-merge-write per batch would be heavy; use SQL that keeps the
        # larger jsonb and concatenates source/query tags.
        cur.executemany(
            """
            INSERT INTO scan_discovery_hits (
                run_id, source, entry_id, query_id, host, ip, port, protocol, record
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (run_id, entry_id) DO UPDATE SET
                source = CASE
                    WHEN scan_discovery_hits.source = EXCLUDED.source
                    THEN scan_discovery_hits.source
                    ELSE scan_discovery_hits.source || ',' || EXCLUDED.source
                END,
                query_id = COALESCE(NULLIF(EXCLUDED.query_id, ''), scan_discovery_hits.query_id),
                host = COALESCE(NULLIF(EXCLUDED.host, ''), scan_discovery_hits.host),
                ip = COALESCE(NULLIF(EXCLUDED.ip, ''), scan_discovery_hits.ip),
                port = COALESCE(NULLIF(EXCLUDED.port, ''), scan_discovery_hits.port),
                protocol = COALESCE(NULLIF(EXCLUDED.protocol, ''), scan_discovery_hits.protocol),
                record = CASE
                    WHEN length(EXCLUDED.record::text) >= length(scan_discovery_hits.record::text)
                    THEN EXCLUDED.record
                    ELSE scan_discovery_hits.record
                END
            """,
            rows,
        )
    log.info(
        "scan_discovery_hits upsert: run=%s source=%s attempted=%d",
        run_id,
        source,
        len(rows),
    )
    return len(rows)


def iter_hits(
    run_id: str,
    *,
    source: str | None = None,
    batch_size: int = 500,
) -> Iterator[list[dict[str, Any]]]:
    """Page-load full hit records ordered by id (stable)."""
    if not spill_enabled() or not run_id:
        return
    batch_size = max(1, int(batch_size))
    from aipocket.core.db import get_pool

    pool = get_pool()
    last_id = 0
    while True:
        clauses = ["run_id = %s", "id > %s"]
        params: list[Any] = [run_id, last_id]
        if source:
            clauses.append("source = %s")
            params.append(source)
        params.append(batch_size)
        sql = f"""
            SELECT id, record FROM scan_discovery_hits
            WHERE {" AND ".join(clauses)}
            ORDER BY id
            LIMIT %s
        """
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        if not rows:
            break
        page: list[dict[str, Any]] = []
        for row in rows:
            rid = row["id"] if isinstance(row, dict) else row[0]
            record = row["record"] if isinstance(row, dict) else row[1]
            last_id = int(rid)
            if isinstance(record, dict):
                page.append(record)
        if page:
            yield page
        if len(rows) < batch_size:
            break


def count_hits(run_id: str, *, source: str | None = None) -> int:
    if not spill_enabled() or not run_id:
        return 0
    from aipocket.core.db import get_pool

    clauses = ["run_id = %s"]
    params: list[Any] = [run_id]
    if source:
        clauses.append("source = %s")
        params.append(source)
    sql = f"SELECT COUNT(*) AS n FROM scan_discovery_hits WHERE {' AND '.join(clauses)}"
    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    if not row:
        return 0
    return int(row["n"] if isinstance(row, dict) else row[0])


def load_hit(run_id: str, entry_id: str) -> dict[str, Any] | None:
    if not spill_enabled() or not run_id or not entry_id:
        return None
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT record FROM scan_discovery_hits
            WHERE run_id = %s AND entry_id = %s
            """,
            (run_id, entry_id),
        )
        row = cur.fetchone()
    if not row:
        return None
    record = row["record"] if isinstance(row, dict) else row[0]
    return record if isinstance(record, dict) else None


def load_hits_by_entry_ids(run_id: str, entry_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Load full hit records for a set of entry_ids (GPT path)."""
    if not spill_enabled() or not run_id or not entry_ids:
        return {}
    ids = [e for e in entry_ids if e]
    if not ids:
        return {}
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT entry_id, record FROM scan_discovery_hits
            WHERE run_id = %s AND entry_id = ANY(%s)
            """,
            (run_id, list(ids)),
        )
        rows = cur.fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        eid = row["entry_id"] if isinstance(row, dict) else row[0]
        record = row["record"] if isinstance(row, dict) else row[1]
        if isinstance(record, dict):
            out[str(eid)] = record
    return out


def slim_hit_for_target(hit: dict[str, Any]) -> dict[str, Any]:
    """Drop heavy body while keeping signal fields for prober ranking.

    Full body remains in ``scan_discovery_hits`` for GPT (C3).
    """
    keep_keys = {
        "host",
        "ip",
        "port",
        "protocol",
        "link",
        "title",
        "header",
        "banner",
        "cert",
        "server",
        "country",
        "city",
        "product",
        "os",
        "_source",
        "_query_id",
        "_query_ids",
        "_cve",
        "_cves",
        "_product",
        "_product_hints",
        "_requires_content_refetch",
        "_entry_id",
    }
    slim = {k: v for k, v in hit.items() if k in keep_keys}
    # Truncate very large header/banner for in-memory targets (signal only).
    for field in ("header", "banner"):
        val = slim.get(field)
        if isinstance(val, str) and len(val) > 16_384:
            slim[field] = val[:16_384]
    return slim


# Re-export for callers that only import discovery_store
__all__ = [
    "count_hits",
    "entry_id_for_hit",
    "iter_hits",
    "load_hit",
    "load_hits_by_entry_ids",
    "slim_hit_for_target",
    "spill_enabled",
    "upsert_hits",
]
