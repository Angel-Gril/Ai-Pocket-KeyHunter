"""Load/save ``source_checkpoints`` rows (PostgreSQL).

Checkpoint advance must be atomic with work-row upserts — callers should pass
an open connection / transaction so both succeed or both roll back.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aipocket.core.config import settings
from aipocket.discovery.base import CheckpointUpdate

log = logging.getLogger(__name__)

SOURCE = "github"

_UPSERT_SQL = """
INSERT INTO source_checkpoints (
    source, lane, pack_id, shard_id, watermark, cursor_state, etag, status, updated_at
) VALUES (
    %(source)s, %(lane)s, %(pack_id)s, %(shard_id)s, %(watermark)s,
    %(cursor_state)s::jsonb, %(etag)s, %(status)s, NOW()
)
ON CONFLICT (source, lane, pack_id, shard_id) DO UPDATE SET
    watermark = EXCLUDED.watermark,
    cursor_state = EXCLUDED.cursor_state,
    etag = EXCLUDED.etag,
    status = EXCLUDED.status,
    updated_at = NOW()
"""

_SELECT_SQL = """
SELECT source, lane, pack_id, shard_id, watermark, cursor_state, etag, status, updated_at
FROM source_checkpoints
WHERE source = %(source)s AND lane = %(lane)s AND pack_id = %(pack_id)s AND shard_id = %(shard_id)s
"""

_SELECT_LANE_SQL = """
SELECT source, lane, pack_id, shard_id, watermark, cursor_state, etag, status, updated_at
FROM source_checkpoints
WHERE source = %(source)s AND lane = %(lane)s AND pack_id = %(pack_id)s
"""


@dataclass(slots=True)
class CheckpointRow:
    source: str
    lane: str
    pack_id: str
    shard_id: str
    watermark: str = ""
    cursor_state: dict[str, Any] = field(default_factory=dict)
    etag: str = ""
    status: str = "ok"
    updated_at: datetime | None = None

    def to_update(self) -> CheckpointUpdate:
        return CheckpointUpdate(
            source=self.source,
            lane=self.lane,
            pack_id=self.pack_id,
            shard_id=self.shard_id,
            watermark=self.watermark,
            cursor_state=dict(self.cursor_state),
            etag=self.etag,
            status=self.status,
        )


def load_checkpoint(
    *,
    lane: str,
    pack_id: str,
    shard_id: str,
    source: str = SOURCE,
    conn: Any | None = None,
) -> CheckpointRow | None:
    """Load one checkpoint row, or None if missing / PG disabled."""
    if conn is None:
        if not settings.pg_enabled:
            return None
        from aipocket.core.db import get_pool

        with get_pool().connection() as c:
            return load_checkpoint(
                lane=lane, pack_id=pack_id, shard_id=shard_id, source=source, conn=c
            )

    cur = conn.execute(
        _SELECT_SQL,
        {"source": source, "lane": lane, "pack_id": pack_id, "shard_id": shard_id},
    )
    row = cur.fetchone()
    if not row:
        return None
    return _row_to_checkpoint(row)


def load_lane_checkpoints(
    *,
    lane: str,
    pack_id: str,
    source: str = SOURCE,
    conn: Any | None = None,
) -> list[CheckpointRow]:
    if conn is None:
        if not settings.pg_enabled:
            return []
        from aipocket.core.db import get_pool

        with get_pool().connection() as c:
            return load_lane_checkpoints(lane=lane, pack_id=pack_id, source=source, conn=c)

    cur = conn.execute(
        _SELECT_LANE_SQL,
        {"source": source, "lane": lane, "pack_id": pack_id},
    )
    rows = cur.fetchall() or []
    return [_row_to_checkpoint(r) for r in rows]


def save_checkpoint(
    row: CheckpointRow | CheckpointUpdate,
    *,
    conn: Any | None = None,
) -> None:
    """Upsert a checkpoint. Pass *conn* to participate in a caller's transaction."""
    payload = _to_params(row)
    if conn is not None:
        conn.execute(_UPSERT_SQL, payload)
        return

    if not settings.pg_enabled:
        log.debug(
            "PG disabled — checkpoint not persisted (%s/%s)", payload["lane"], payload["shard_id"]
        )
        return

    from aipocket.core.db import get_pool

    with get_pool().connection() as c, c.transaction():
        c.execute(_UPSERT_SQL, payload)


def advance_checkpoint_with_work(
    *,
    checkpoint: CheckpointRow | CheckpointUpdate,
    work_rows: list[dict[str, Any]],
    upsert_work_fn: Any,
    conn: Any | None = None,
) -> None:
    """Atomically upsert work rows then advance checkpoint in one transaction.

    Crash between the two must roll back both — never advance watermark without
    durable work rows.
    """
    if conn is not None:
        upsert_work_fn(work_rows, conn=conn)
        save_checkpoint(checkpoint, conn=conn)
        return

    if not settings.pg_enabled:
        # In-memory / no-PG path: still call upsert for side effects if any.
        upsert_work_fn(work_rows, conn=None)
        save_checkpoint(checkpoint, conn=None)
        return

    from aipocket.core.db import get_pool

    with get_pool().connection() as c, c.transaction():
        upsert_work_fn(work_rows, conn=c)
        save_checkpoint(checkpoint, conn=c)


def _to_params(row: CheckpointRow | CheckpointUpdate) -> dict[str, Any]:
    if isinstance(row, CheckpointUpdate):
        cursor = row.cursor_state
        return {
            "source": row.source,
            "lane": row.lane,
            "pack_id": row.pack_id,
            "shard_id": row.shard_id,
            "watermark": row.watermark,
            "cursor_state": json.dumps(cursor or {}),
            "etag": row.etag or "",
            "status": row.status or "ok",
        }
    return {
        "source": row.source,
        "lane": row.lane,
        "pack_id": row.pack_id,
        "shard_id": row.shard_id,
        "watermark": row.watermark,
        "cursor_state": json.dumps(row.cursor_state or {}),
        "etag": row.etag or "",
        "status": row.status or "ok",
    }


def _row_to_checkpoint(row: dict[str, Any]) -> CheckpointRow:
    cursor = row.get("cursor_state") or {}
    if isinstance(cursor, str):
        try:
            cursor = json.loads(cursor)
        except json.JSONDecodeError:
            cursor = {}
    if not isinstance(cursor, dict):
        cursor = {}
    updated = row.get("updated_at")
    if isinstance(updated, str):
        try:
            updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        except ValueError:
            updated = None
    return CheckpointRow(
        source=str(row.get("source") or SOURCE),
        lane=str(row.get("lane") or ""),
        pack_id=str(row.get("pack_id") or ""),
        shard_id=str(row.get("shard_id") or ""),
        watermark=str(row.get("watermark") or ""),
        cursor_state=cursor,
        etag=str(row.get("etag") or ""),
        status=str(row.get("status") or "ok"),
        updated_at=updated if isinstance(updated, datetime) else None,
    )


def watermark_now() -> str:
    return datetime.now(UTC).isoformat()
