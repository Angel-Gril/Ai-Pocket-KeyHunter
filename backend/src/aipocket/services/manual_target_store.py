"""Persistent store for user-supplied manual scan targets (relay / gateway URLs).

PostgreSQL-backed. When ``DATABASE_URL`` is unset the list/load paths return
empty results; mutating operations raise :class:`ValueError` so the API can
surface a clear configuration error.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from aipocket.core.config import settings
from aipocket.services.url_sanitize import (
    SanitizedUrl,
    sanitize_target_url,
    sanitize_target_urls,
)

log = logging.getLogger(__name__)

_write_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().isoformat()


def _require_pg() -> bool:
    return bool(settings.pg_enabled)


def _row_to_dict(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    first_seen = row.get("first_seen")
    last_seen = row.get("last_seen")
    return {
        "url": str(row.get("url") or ""),
        "host_key": str(row.get("host_key") or ""),
        "scheme": str(row.get("scheme") or ""),
        "hostname": str(row.get("hostname") or ""),
        "port": int(row.get("port") or 0),
        "enabled": bool(row.get("enabled", True)),
        "notes": str(row.get("notes") or ""),
        "first_seen": first_seen.isoformat()
        if hasattr(first_seen, "isoformat")
        else str(first_seen or ""),
        "last_seen": last_seen.isoformat()
        if hasattr(last_seen, "isoformat")
        else str(last_seen or ""),
    }


def list_targets(
    *,
    enabled_only: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List stored manual targets (newest last_seen first)."""
    if not _require_pg():
        return [], 0
    limit = max(1, min(int(limit), 2000))
    offset = max(0, int(offset))
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with pool.connection() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) AS n FROM manual_targets {where}"  # noqa: S608 — where is fixed
            ).fetchone()
            total = int(total_row["n"]) if total_row else 0
            rows = conn.execute(
                f"""
                SELECT url, host_key, scheme, hostname, port, enabled, notes,
                       first_seen, last_seen
                FROM manual_targets
                {where}
                ORDER BY last_seen DESC, url ASC
                LIMIT %s OFFSET %s
                """,  # noqa: S608
                (limit, offset),
            ).fetchall()
        return [d for r in rows if (d := _row_to_dict(r))], total
    except Exception as e:  # noqa: BLE001 — list must not crash the API
        log.warning("manual_targets list failed: %s", e)
        return [], 0


def load_enabled_urls() -> list[str]:
    """Return enabled target URLs for discovery (empty when PG off / error)."""
    rows, _ = list_targets(enabled_only=True, limit=2000, offset=0)
    return [r["url"] for r in rows if r.get("url")]


def count_enabled() -> int:
    if not _require_pg():
        return 0
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM manual_targets WHERE enabled = TRUE"
            ).fetchone()
        return int(row["n"]) if row else 0
    except Exception as e:  # noqa: BLE001
        log.warning("manual_targets count failed: %s", e)
        return 0


def add_targets(
    raw_lines: list[str] | str,
    *,
    notes: str = "",
) -> dict[str, Any]:
    """Sanitize and UPSERT a batch of targets.

    Returns ``{added, updated, rejected, targets}``.
    Raises ValueError when PG is disabled or every line is rejected/empty.
    """
    if not _require_pg():
        raise ValueError("自定义狩猎需要 PostgreSQL（请配置 DATABASE_URL）")

    accepted, rejected = sanitize_target_urls(raw_lines)
    if not accepted and not rejected:
        raise ValueError("请至少填写一个地址")
    if not accepted:
        raise ValueError(f"没有有效地址（已拒绝 {len(rejected)} 行）")

    from psycopg.types.json import Jsonb

    from aipocket.core.db import get_pool

    added = 0
    updated = 0
    saved: list[dict[str, Any]] = []
    note = (notes or "").strip()
    now = _now()

    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            for item in accepted:
                record = {
                    "url": item.url,
                    "host_key": item.host_key,
                    "scheme": item.scheme,
                    "hostname": item.hostname,
                    "port": item.port,
                    "notes": note,
                    "saved_at": _now_iso(),
                }
                row = conn.execute(
                    """
                    INSERT INTO manual_targets
                        (url, host_key, scheme, hostname, port, enabled, notes,
                         first_seen, last_seen, record)
                    VALUES (%s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s)
                    ON CONFLICT (url) DO UPDATE SET
                        enabled   = TRUE,
                        notes     = CASE
                                      WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes
                                      ELSE manual_targets.notes
                                    END,
                        last_seen = EXCLUDED.last_seen,
                        record    = EXCLUDED.record
                    RETURNING url, host_key, scheme, hostname, port, enabled, notes,
                              first_seen, last_seen,
                              (xmax = 0) AS inserted
                    """,
                    (
                        item.url,
                        item.host_key,
                        item.scheme,
                        item.hostname,
                        item.port,
                        note,
                        now,
                        now,
                        Jsonb(record),
                    ),
                ).fetchone()
                if row:
                    if row.get("inserted"):
                        added += 1
                    else:
                        updated += 1
                    d = _row_to_dict(row)
                    if d:
                        saved.append(d)
            conn.commit()

    return {
        "added": added,
        "updated": updated,
        "rejected": rejected,
        "targets": saved,
    }


def replace_targets(raw_lines: list[str] | str, *, notes: str = "") -> dict[str, Any]:
    """Replace the entire enabled set with the sanitized input (destructive).

    Disabled rows are left alone. Existing enabled URLs not in the new list
    are deleted. Raises ValueError when PG is off or input is all invalid.
    """
    if not _require_pg():
        raise ValueError("自定义狩猎需要 PostgreSQL（请配置 DATABASE_URL）")

    accepted, rejected = sanitize_target_urls(raw_lines)
    if not accepted and rejected:
        raise ValueError(f"没有有效地址（已拒绝 {len(rejected)} 行）")

    from psycopg.types.json import Jsonb

    from aipocket.core.db import get_pool

    note = (notes or "").strip()
    now = _now()
    keep_urls = {item.url for item in accepted}
    saved: list[dict[str, Any]] = []

    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            if keep_urls:
                conn.execute(
                    "DELETE FROM manual_targets WHERE enabled = TRUE AND NOT (url = ANY(%s))",
                    (list(keep_urls),),
                )
            else:
                conn.execute("DELETE FROM manual_targets WHERE enabled = TRUE")

            for item in accepted:
                record = {
                    "url": item.url,
                    "host_key": item.host_key,
                    "scheme": item.scheme,
                    "hostname": item.hostname,
                    "port": item.port,
                    "notes": note,
                    "saved_at": _now_iso(),
                }
                row = conn.execute(
                    """
                    INSERT INTO manual_targets
                        (url, host_key, scheme, hostname, port, enabled, notes,
                         first_seen, last_seen, record)
                    VALUES (%s, %s, %s, %s, %s, TRUE, %s, %s, %s, %s)
                    ON CONFLICT (url) DO UPDATE SET
                        enabled   = TRUE,
                        notes     = CASE
                                      WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes
                                      ELSE manual_targets.notes
                                    END,
                        last_seen = EXCLUDED.last_seen,
                        record    = EXCLUDED.record
                    RETURNING url, host_key, scheme, hostname, port, enabled, notes,
                              first_seen, last_seen
                    """,
                    (
                        item.url,
                        item.host_key,
                        item.scheme,
                        item.hostname,
                        item.port,
                        note,
                        now,
                        now,
                        Jsonb(record),
                    ),
                ).fetchone()
                if row:
                    d = _row_to_dict(row)
                    if d:
                        saved.append(d)
            conn.commit()

    return {
        "added": len(saved),
        "updated": 0,
        "rejected": rejected,
        "targets": saved,
    }


def delete_target(url: str) -> bool:
    """Delete one target by its stored canonical URL. Returns True if removed."""
    if not _require_pg():
        raise ValueError("自定义狩猎需要 PostgreSQL（请配置 DATABASE_URL）")
    cleaned = sanitize_target_url(url)
    key = cleaned.url if cleaned else (url or "").strip()
    if not key:
        raise ValueError("无效地址")

    from aipocket.core.db import get_pool

    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            cur = conn.execute("DELETE FROM manual_targets WHERE url = %s", (key,))
            conn.commit()
            return cur.rowcount > 0


def delete_targets(urls: list[str]) -> int:
    """Bulk delete by canonical or raw URL. Returns number of rows removed."""
    if not _require_pg():
        raise ValueError("自定义狩猎需要 PostgreSQL（请配置 DATABASE_URL）")
    keys: list[str] = []
    for u in urls:
        cleaned = sanitize_target_url(u)
        keys.append(cleaned.url if cleaned else (u or "").strip())
    keys = [k for k in keys if k]
    if not keys:
        return 0

    from aipocket.core.db import get_pool

    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            cur = conn.execute(
                "DELETE FROM manual_targets WHERE url = ANY(%s)",
                (keys,),
            )
            conn.commit()
            return int(cur.rowcount or 0)


def set_enabled(url: str, enabled: bool) -> dict[str, Any] | None:
    """Enable/disable one target. Returns updated row or None if missing."""
    if not _require_pg():
        raise ValueError("自定义狩猎需要 PostgreSQL（请配置 DATABASE_URL）")
    cleaned = sanitize_target_url(url)
    key = cleaned.url if cleaned else (url or "").strip()
    if not key:
        raise ValueError("无效地址")

    from aipocket.core.db import get_pool

    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE manual_targets
                SET enabled = %s, last_seen = %s
                WHERE url = %s
                RETURNING url, host_key, scheme, hostname, port, enabled, notes,
                          first_seen, last_seen
                """,
                (bool(enabled), _now(), key),
            ).fetchone()
            conn.commit()
    return _row_to_dict(row)


def to_sanitized(url: str) -> SanitizedUrl | None:
    """Public re-export helper for callers that need the SanitizedUrl type."""
    return sanitize_target_url(url)
