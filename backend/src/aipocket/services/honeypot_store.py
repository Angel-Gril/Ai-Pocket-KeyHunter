"""Persistent honeypot site cache (PostgreSQL).

After discovery, the scanner loads known honeypot ``host_key`` values and skips
probe / GPT / validate work for those sites. When honeypot detection confirms a
host (no-auth, steganography, response-cluster, …), the host is UPSERTed here
so subsequent runs skip it without re-probing.

No-op when ``DATABASE_URL`` is unset (``settings.pg_enabled`` is False).
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import threading
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult
from aipocket.core.targets import DiscoveryTarget

log = logging.getLogger(__name__)

# Host-level honeypot signals — these mean the *endpoint* is bad, not just one key.
# Key-format / cross-host key dedup are NOT host-level and must not poison the cache.
_HOST_LEVEL_REASON_PREFIXES: tuple[str, ...] = (
    "honeypot:no-auth-host",
    "honeypot:steganography",
    "honeypot:prompt-injection",
    "honeypot:response-cluster",
    "honeypot:429-indiscriminate",
    "honeypot:model-mismatch",
)

_write_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().isoformat()


def normalize_site_key(raw: str) -> str:
    """Normalize host / URL to ``hostname:port`` (scheme-agnostic).

    Empty / unparseable input returns ``""``. Scheme is ignored so the same
    honeypot on http vs https (or discovery without scheme) maps to one key.
    """
    text = (raw or "").strip()
    if not text:
        return ""

    scheme_hint = ""
    if "://" in text:
        parsed = urlsplit(text)
        host_part = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            return ""
        scheme_hint = parsed.scheme.lower()
        # apiurl path may include /v1 — ignore path for host identity
    else:
        # host:port or bare host (optionally with path noise)
        host_part = text.split("/")[0].split("?")[0]
        port = None
        if host_part.startswith("[") and "]" in host_part:
            # IPv6 [addr]:port
            bracket_end = host_part.index("]")
            addr = host_part[1:bracket_end]
            rest = host_part[bracket_end + 1 :]
            host_part = addr
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
        elif host_part.count(":") == 1:
            left, right = host_part.rsplit(":", 1)
            if right.isdigit():
                host_part, port = left, int(right)

    hostname = (host_part or "").rstrip(".").lower()
    if not hostname:
        return ""
    with contextlib.suppress(ValueError):
        hostname = ipaddress.ip_address(hostname).compressed

    if port is None:
        port = 443 if scheme_hint == "https" else 80

    # IPv6 display: [addr]:port
    if ":" in hostname:
        return f"[{hostname}]:{port}"
    return f"{hostname}:{port}"


def site_key_from_target(target: DiscoveryTarget) -> str:
    ident = target.identity
    host = ident.hostname
    if ":" in host:
        return f"[{host}]:{ident.port}"
    return f"{host}:{ident.port}"


def site_key_from_credential(cred: Credential) -> str:
    # Prefer host (often identity.url after canonicalize); fall back to apiurl.
    return normalize_site_key(cred.host or cred.apiurl or cred.leak_host or "")


def site_key_from_result(result: ValidationResult) -> str:
    return site_key_from_credential(result.credential)


def is_host_level_honeypot_error(error: str | None) -> bool:
    err = (error or "").strip().lower()
    if not err.startswith("honeypot:"):
        return False
    return any(err.startswith(prefix) for prefix in _HOST_LEVEL_REASON_PREFIXES)


def extract_reason_label(error: str | None) -> str:
    """Short stable reason tag, e.g. ``honeypot:no-auth-host``."""
    err = (error or "").strip()
    if not err:
        return "honeypot:unknown"
    # Drop parenthetical detail: "honeypot:foo (detail)" → "honeypot:foo"
    base = err.split("(", 1)[0].strip()
    return base or "honeypot:unknown"


# ---------------------------------------------------------------------------
# PG helpers
# ---------------------------------------------------------------------------


def _require_pg() -> bool:
    return bool(settings.pg_enabled)


def load_known_host_keys() -> set[str]:
    """All cached honeypot site keys. Empty when PG is off or on read failure."""
    if not _require_pg():
        return set()
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            rows = conn.execute("SELECT host_key FROM honeypot_sites").fetchall()
        return {str(r["host_key"]) for r in rows if r.get("host_key")}
    except Exception as e:  # noqa: BLE001 — cache miss must never block a scan
        log.warning("honeypot cache load failed: %s", e)
        return set()


def filter_targets(
    targets: list[DiscoveryTarget], known: set[str] | None = None
) -> tuple[list[DiscoveryTarget], int]:
    """Drop discovery targets whose site key is in the honeypot cache.

    Returns ``(kept_targets, skipped_count)``.
    """
    keys = known if known is not None else load_known_host_keys()
    if not keys:
        return targets, 0
    kept: list[DiscoveryTarget] = []
    skipped = 0
    for target in targets:
        if site_key_from_target(target) in keys:
            skipped += 1
            continue
        kept.append(target)
    return kept, skipped


def filter_credentials(
    creds: list[Credential], known: set[str] | None = None
) -> tuple[list[Credential], int]:
    """Drop credentials bound to known honeypot hosts."""
    keys = known if known is not None else load_known_host_keys()
    if not keys:
        return creds, 0
    kept: list[Credential] = []
    skipped = 0
    for cred in creds:
        sk = site_key_from_credential(cred)
        if sk and sk in keys:
            skipped += 1
            continue
        kept.append(cred)
    return kept, skipped


def record_site(
    host: str,
    *,
    reason: str = "honeypot:manual",
    source: str = "auto",
    run_id: str | None = None,
    notes: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """UPSERT one honeypot site. Returns the row dict, or None if PG off / bad host."""
    host_key = normalize_site_key(host)
    if not host_key:
        return None
    if not _require_pg():
        return {
            "host_key": host_key,
            "host": host_key,
            "reason": reason,
            "source": source,
            "run_id": run_id,
            "notes": notes,
            "hit_count": 1,
            "first_seen": _now_iso(),
            "last_seen": _now_iso(),
        }

    from psycopg.types.json import Jsonb

    from aipocket.core.db import get_pool

    record = {
        "host_key": host_key,
        "host": host_key,
        "reason": reason,
        "source": source,
        "run_id": run_id,
        "notes": notes,
        "extra": extra or {},
        "saved_at": _now_iso(),
    }
    now = _now()
    with _write_lock:
        pool = get_pool()
        with pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO honeypot_sites
                    (host_key, host, reason, source, first_seen, last_seen,
                     hit_count, run_id, notes, record)
                VALUES (%s, %s, %s, %s, %s, %s, 1, %s, %s, %s)
                ON CONFLICT (host_key) DO UPDATE SET
                    reason     = CASE
                                   WHEN honeypot_sites.source = 'manual'
                                        AND EXCLUDED.source = 'auto'
                                   THEN honeypot_sites.reason
                                   ELSE EXCLUDED.reason
                                 END,
                    source     = CASE
                                   WHEN honeypot_sites.source = 'manual'
                                   THEN honeypot_sites.source
                                   ELSE EXCLUDED.source
                                 END,
                    last_seen  = EXCLUDED.last_seen,
                    hit_count  = honeypot_sites.hit_count + 1,
                    run_id     = COALESCE(EXCLUDED.run_id, honeypot_sites.run_id),
                    notes      = CASE
                                   WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes
                                   ELSE honeypot_sites.notes
                                 END,
                    record     = EXCLUDED.record
                RETURNING host_key, host, reason, source, first_seen, last_seen,
                          hit_count, run_id, notes, record
                """,
                (
                    host_key,
                    host_key,
                    reason,
                    source,
                    now,
                    now,
                    run_id,
                    notes,
                    Jsonb(record),
                ),
            ).fetchone()
            conn.commit()
    return _row_to_dict(row) if row else None


def record_from_results(
    results: list[ValidationResult],
    *,
    run_id: str | None = None,
    no_auth_hosts: set[str] | None = None,
) -> int:
    """Persist host-level honeypot verdicts from a validation batch.

    Also records every host in ``no_auth_hosts`` (forged-key probe confirmed)
    even if the matching result rows were already mutated.

    Returns number of distinct hosts written (attempted).
    """
    if not _require_pg():
        return 0

    to_save: dict[str, str] = {}  # host_key → reason

    for result in results:
        if result.valid and not is_host_level_honeypot_error(result.error):
            # Still-valid rows are not honeypots; skip.
            # Note: honeypot filter sets valid=False before we see them.
            continue
        if not is_host_level_honeypot_error(result.error):
            continue
        key = site_key_from_result(result)
        if not key:
            continue
        to_save[key] = extract_reason_label(result.error)

    for host in no_auth_hosts or ():
        key = normalize_site_key(host)
        if key:
            to_save.setdefault(key, "honeypot:no-auth-host")

    if not to_save:
        return 0

    written = 0
    failed = 0
    for host_key, reason in to_save.items():
        try:
            if record_site(host_key, reason=reason, source="auto", run_id=run_id) is not None:
                written += 1
        except Exception as e:  # noqa: BLE001 — never fail the scan for cache write
            log.warning("honeypot cache write failed for %s: %s", host_key, e)
            failed += 1
    log.info(
        "Honeypot cache: eligible_hosts=%d written_hosts=%d failed_hosts=%d run_id=%s",
        len(to_save),
        written,
        failed,
        run_id or "-",
    )
    return written


# ---------------------------------------------------------------------------
# CRUD for the web UI
# ---------------------------------------------------------------------------


def _row_to_dict(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {}
    first = row.get("first_seen")
    last = row.get("last_seen")
    return {
        "host_key": row.get("host_key") or "",
        "host": row.get("host") or row.get("host_key") or "",
        "reason": row.get("reason") or "",
        "source": row.get("source") or "auto",
        "first_seen": first.isoformat() if hasattr(first, "isoformat") else (first or ""),
        "last_seen": last.isoformat() if hasattr(last, "isoformat") else (last or ""),
        "hit_count": int(row.get("hit_count") or 1),
        "run_id": row.get("run_id") or "",
        "notes": row.get("notes") or "",
    }


def list_sites(
    *,
    q: str = "",
    source: str = "",
    limit: int = 500,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List honeypot sites (newest last_seen first). Returns ``(rows, total)``."""
    if not _require_pg():
        return [], 0

    from aipocket.core.db import get_pool

    limit = max(1, min(int(limit), 2000))
    offset = max(0, int(offset))
    clauses: list[str] = []
    params: list[Any] = []
    if q.strip():
        clauses.append("(host_key ILIKE %s OR host ILIKE %s OR reason ILIKE %s OR notes ILIKE %s)")
        like = f"%{q.strip()}%"
        params.extend([like, like, like, like])
    if source.strip() in {"auto", "manual"}:
        clauses.append("source = %s")
        params.append(source.strip())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    pool = get_pool()
    with pool.connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM honeypot_sites {where}",
            params,
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT host_key, host, reason, source, first_seen, last_seen,
                   hit_count, run_id, notes
            FROM honeypot_sites
            {where}
            ORDER BY last_seen DESC NULLS LAST, host_key
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    return [_row_to_dict(r) for r in rows], int(total)


def get_site(host_key: str) -> dict[str, Any] | None:
    key = normalize_site_key(host_key) or host_key.strip()
    if not key or not _require_pg():
        return None
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            SELECT host_key, host, reason, source, first_seen, last_seen,
                   hit_count, run_id, notes
            FROM honeypot_sites WHERE host_key = %s
            """,
            (key,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def create_site(
    host: str,
    *,
    reason: str = "honeypot:manual",
    notes: str = "",
) -> dict[str, Any]:
    """Manually add a honeypot site. Raises ValueError on bad input."""
    host_key = normalize_site_key(host)
    if not host_key:
        raise ValueError("无效的主机地址，示例: 1.2.3.4:8080 或 https://host:443")
    if not _require_pg():
        raise ValueError("PostgreSQL 未配置，无法保存蜜罐站点")
    reason = (reason or "honeypot:manual").strip() or "honeypot:manual"
    if not reason.startswith("honeypot:"):
        reason = f"honeypot:{reason}"
    row = record_site(host_key, reason=reason, source="manual", notes=notes.strip())
    if row is None:
        raise ValueError("保存失败")
    return row


def update_site(
    host_key: str,
    *,
    reason: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    key = normalize_site_key(host_key) or host_key.strip()
    if not key:
        raise ValueError("无效的 host_key")
    if not _require_pg():
        raise ValueError("PostgreSQL 未配置")
    existing = get_site(key)
    if existing is None:
        raise KeyError(key)

    new_reason = existing["reason"]
    if reason is not None and reason.strip():
        new_reason = reason.strip()
        if not new_reason.startswith("honeypot:"):
            new_reason = f"honeypot:{new_reason}"
    new_notes = existing["notes"] if notes is None else notes

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            UPDATE honeypot_sites
               SET reason = %s,
                   notes = %s,
                   last_seen = %s
             WHERE host_key = %s
         RETURNING host_key, host, reason, source, first_seen, last_seen,
                   hit_count, run_id, notes
            """,
            (new_reason, new_notes, _now(), key),
        ).fetchone()
        conn.commit()
    if not row:
        raise KeyError(key)
    return _row_to_dict(row)


def delete_site(host_key: str) -> bool:
    """Delete one site. Returns True if a row was removed."""
    key = normalize_site_key(host_key) or host_key.strip()
    if not key or not _require_pg():
        return False
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        cur = conn.execute("DELETE FROM honeypot_sites WHERE host_key = %s", (key,))
        conn.commit()
        return (cur.rowcount or 0) > 0


def delete_sites(host_keys: list[str]) -> int:
    """Bulk delete. Returns number of rows removed."""
    keys = [normalize_site_key(k) or k.strip() for k in host_keys]
    keys = [k for k in keys if k]
    if not keys or not _require_pg():
        return 0
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        cur = conn.execute(
            "DELETE FROM honeypot_sites WHERE host_key = ANY(%s)",
            (keys,),
        )
        conn.commit()
        return int(cur.rowcount or 0)


__all__ = [
    "create_site",
    "delete_site",
    "delete_sites",
    "extract_reason_label",
    "filter_credentials",
    "filter_targets",
    "get_site",
    "is_host_level_honeypot_error",
    "list_sites",
    "load_known_host_keys",
    "normalize_site_key",
    "record_from_results",
    "record_site",
    "site_key_from_credential",
    "site_key_from_result",
    "site_key_from_target",
    "update_site",
]
