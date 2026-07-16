"""GitHub artifact work-queue status machine (no plaintext secrets).

Status flow::

    fetch_pending → extract_pending → validation_pending → terminal
                         ↘ transient (retry with backoff)
                         ↘ source_gone (data-loss metric)

Also terminal-like outcomes: ``artifact_too_large``, ``budget_exhausted``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from aipocket.core.config import settings

log = logging.getLogger(__name__)

WorkStatus = Literal[
    "fetch_pending",
    "extract_pending",
    "validation_pending",
    "terminal",
    "transient",
    "source_gone",
    "artifact_too_large",
    "budget_exhausted",
]

# Statuses that are done and should not be reclaimed for processing.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        "terminal",
        "source_gone",
        "artifact_too_large",
        "budget_exhausted",
    }
)

# Statuses that should be claimed before starting new search shards.
CLAIMABLE_STATUSES: frozenset[str] = frozenset(
    {
        "fetch_pending",
        "extract_pending",
        "validation_pending",
        "transient",
    }
)

_DEFAULT_MAX_ATTEMPTS = 5

_UPSERT_SQL = """
INSERT INTO github_artifacts (
    repo_id, repository_full_name, commit_sha, file_path, object_sha,
    source_kind, etag, work_status, attempts, last_error_class, current_stage,
    next_retry_at, run_id, query_id, pack_id, lane, coverage_mode,
    first_seen_at, last_seen_at
) VALUES (
    %(repo_id)s, %(repository_full_name)s, %(commit_sha)s, %(file_path)s, %(object_sha)s,
    %(source_kind)s, %(etag)s, %(work_status)s, %(attempts)s, %(last_error_class)s,
    %(current_stage)s, %(next_retry_at)s, %(run_id)s, %(query_id)s, %(pack_id)s,
    %(lane)s, %(coverage_mode)s, NOW(), NOW()
)
ON CONFLICT (repo_id, commit_sha, file_path, source_kind, object_sha) DO UPDATE SET
    repository_full_name = EXCLUDED.repository_full_name,
    etag = COALESCE(NULLIF(EXCLUDED.etag, ''), github_artifacts.etag),
    -- Do not demote terminal work back to pending on re-observe.
    work_status = CASE
        WHEN github_artifacts.work_status IN (
            'terminal', 'source_gone', 'artifact_too_large', 'budget_exhausted'
        ) THEN github_artifacts.work_status
        ELSE EXCLUDED.work_status
    END,
    last_seen_at = NOW(),
    run_id = CASE WHEN EXCLUDED.run_id <> '' THEN EXCLUDED.run_id ELSE github_artifacts.run_id END,
    query_id = CASE WHEN EXCLUDED.query_id <> '' THEN EXCLUDED.query_id ELSE github_artifacts.query_id END,
    pack_id = CASE WHEN EXCLUDED.pack_id <> '' THEN EXCLUDED.pack_id ELSE github_artifacts.pack_id END,
    lane = CASE WHEN EXCLUDED.lane <> '' THEN EXCLUDED.lane ELSE github_artifacts.lane END,
    coverage_mode = EXCLUDED.coverage_mode
"""

_CLAIM_SQL = """
SELECT repo_id, repository_full_name, commit_sha, file_path, object_sha,
       source_kind, etag, work_status, attempts, last_error_class, current_stage,
       next_retry_at, run_id, query_id, pack_id, lane, coverage_mode,
       first_seen_at, last_seen_at
FROM github_artifacts
WHERE work_status = ANY(%(statuses)s)
  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
ORDER BY last_seen_at ASC
LIMIT %(limit)s
"""

_UPDATE_STATUS_SQL = """
UPDATE github_artifacts
SET work_status = %(work_status)s,
    current_stage = %(current_stage)s,
    attempts = %(attempts)s,
    last_error_class = %(last_error_class)s,
    next_retry_at = %(next_retry_at)s,
    last_seen_at = NOW()
WHERE repo_id = %(repo_id)s
  AND commit_sha = %(commit_sha)s
  AND file_path = %(file_path)s
  AND source_kind = %(source_kind)s
  AND object_sha = %(object_sha)s
"""


@dataclass(slots=True)
class ArtifactWorkItem:
    repo_id: str
    repository_full_name: str
    commit_sha: str
    file_path: str = ""
    object_sha: str = ""
    source_kind: str = "commit_message"  # commit_message|patch|blob
    etag: str = ""
    work_status: WorkStatus = "fetch_pending"
    attempts: int = 0
    last_error_class: str = ""
    current_stage: str = "fetch_pending"
    next_retry_at: datetime | None = None
    run_id: str = ""
    query_id: str = ""
    pack_id: str = ""
    lane: str = ""
    coverage_mode: str = "complete"

    @property
    def locator_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.repo_id,
            self.commit_sha,
            self.file_path,
            self.source_kind,
            self.object_sha,
        )

    def to_row(self) -> dict[str, Any]:
        return {
            "repo_id": self.repo_id,
            "repository_full_name": self.repository_full_name,
            "commit_sha": self.commit_sha,
            "file_path": self.file_path or "",
            "object_sha": self.object_sha or "",
            "source_kind": self.source_kind,
            "etag": self.etag or "",
            "work_status": self.work_status,
            "attempts": self.attempts,
            "last_error_class": self.last_error_class or "",
            "current_stage": self.current_stage or self.work_status,
            "next_retry_at": self.next_retry_at,
            "run_id": self.run_id or "",
            "query_id": self.query_id or "",
            "pack_id": self.pack_id or "",
            "lane": self.lane or "",
            "coverage_mode": self.coverage_mode or "complete",
        }


@dataclass(slots=True)
class WorkQueueStats:
    claimed: int = 0
    terminal: int = 0
    transient: int = 0
    source_gone: int = 0
    data_loss: int = 0  # exceeded retries → source_gone


# In-memory fallback for unit tests / PG-disabled dry runs.
_memory_store: dict[tuple[str, str, str, str, str], ArtifactWorkItem] = {}


def reset_memory_store() -> None:
    """Test helper — clear the in-process work queue."""
    _memory_store.clear()


def upsert_work_rows(
    rows: list[ArtifactWorkItem | dict[str, Any]],
    *,
    conn: Any | None = None,
) -> int:
    """Insert or refresh work rows. Never stores secrets or raw patch/blob."""
    items = [_coerce_item(r) for r in rows]
    if not items:
        return 0

    if conn is not None:
        for item in items:
            conn.execute(_UPSERT_SQL, item.to_row())
        return len(items)

    if not settings.pg_enabled:
        for item in items:
            key = item.locator_key
            existing = _memory_store.get(key)
            if existing and existing.work_status in TERMINAL_STATUSES:
                # Overlap reprocess must not demote terminal work.
                existing.repository_full_name = (
                    item.repository_full_name or existing.repository_full_name
                )
                _memory_store[key] = existing
                continue
            _memory_store[key] = item
        return len(items)

    from aipocket.core.db import get_pool

    with get_pool().connection() as c, c.transaction():
        for item in items:
            c.execute(_UPSERT_SQL, item.to_row())
    return len(items)


def claim_pending(
    *,
    limit: int = 100,
    statuses: frozenset[str] | None = None,
    conn: Any | None = None,
) -> list[ArtifactWorkItem]:
    """Claim claimable work ordered by last_seen (oldest first)."""
    want = list(statuses or CLAIMABLE_STATUSES)

    if conn is not None:
        cur = conn.execute(_CLAIM_SQL, {"statuses": want, "limit": limit})
        return [_row_to_item(r) for r in (cur.fetchall() or [])]

    if not settings.pg_enabled:
        now = datetime.now(UTC)
        items = [
            it
            for it in _memory_store.values()
            if it.work_status in want and (it.next_retry_at is None or it.next_retry_at <= now)
        ]
        items.sort(key=lambda x: x.commit_sha)
        return items[:limit]

    from aipocket.core.db import get_pool

    with get_pool().connection() as c:
        cur = c.execute(_CLAIM_SQL, {"statuses": want, "limit": limit})
        return [_row_to_item(r) for r in (cur.fetchall() or [])]


def transition(
    item: ArtifactWorkItem,
    new_status: WorkStatus,
    *,
    error_class: str = "",
    backoff_seconds: float | None = None,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    conn: Any | None = None,
) -> ArtifactWorkItem:
    """Advance work-item status; enforce retry ceiling → source_gone."""
    item.attempts = int(item.attempts or 0)
    if new_status == "transient":
        item.attempts += 1
        if item.attempts >= max_attempts:
            new_status = "source_gone"
            # Preserve original class as prefix, always mark the ceiling.
            error_class = (
                f"max_attempts_exceeded:{error_class}" if error_class else "max_attempts_exceeded"
            )
            log.warning(
                "artifact %s@%s exceeded retries → source_gone",
                item.repository_full_name,
                item.commit_sha[:8] if item.commit_sha else "?",
            )
        else:
            delay = backoff_seconds if backoff_seconds is not None else min(300.0, 2**item.attempts)
            item.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay)

    item.work_status = new_status
    item.current_stage = new_status
    item.last_error_class = error_class or (
        "" if new_status not in ("transient", "source_gone") else item.last_error_class
    )
    if new_status in TERMINAL_STATUSES and new_status != "transient":
        item.next_retry_at = None

    _persist_status(item, conn=conn)
    return item


def mark_fetch_done(item: ArtifactWorkItem, *, conn: Any | None = None) -> ArtifactWorkItem:
    return transition(item, "extract_pending", conn=conn)


def mark_extract_done(item: ArtifactWorkItem, *, conn: Any | None = None) -> ArtifactWorkItem:
    return transition(item, "validation_pending", conn=conn)


def mark_terminal(item: ArtifactWorkItem, *, conn: Any | None = None) -> ArtifactWorkItem:
    return transition(item, "terminal", conn=conn)


def mark_source_gone(
    item: ArtifactWorkItem,
    *,
    error_class: str = "source_gone",
    conn: Any | None = None,
) -> ArtifactWorkItem:
    return transition(item, "source_gone", error_class=error_class, conn=conn)


def mark_transient(
    item: ArtifactWorkItem,
    *,
    error_class: str = "transient",
    backoff_seconds: float | None = None,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    conn: Any | None = None,
) -> ArtifactWorkItem:
    return transition(
        item,
        "transient",
        error_class=error_class,
        backoff_seconds=backoff_seconds,
        max_attempts=max_attempts,
        conn=conn,
    )


def next_status_after_fetch(source_kind: str) -> WorkStatus:
    """Map successful fetch of a given kind to the next stage."""
    return "extract_pending"


def _persist_status(item: ArtifactWorkItem, *, conn: Any | None) -> None:
    row = item.to_row()
    if conn is not None:
        conn.execute(_UPDATE_STATUS_SQL, row)
        return
    if not settings.pg_enabled:
        _memory_store[item.locator_key] = item
        return
    from aipocket.core.db import get_pool

    with get_pool().connection() as c, c.transaction():
        c.execute(_UPDATE_STATUS_SQL, row)


def _coerce_item(raw: ArtifactWorkItem | dict[str, Any]) -> ArtifactWorkItem:
    if isinstance(raw, ArtifactWorkItem):
        return raw
    return ArtifactWorkItem(
        repo_id=str(raw.get("repo_id") or ""),
        repository_full_name=str(raw.get("repository_full_name") or ""),
        commit_sha=str(raw.get("commit_sha") or ""),
        file_path=str(raw.get("file_path") or ""),
        object_sha=str(raw.get("object_sha") or ""),
        source_kind=str(raw.get("source_kind") or "commit_message"),
        etag=str(raw.get("etag") or ""),
        work_status=raw.get("work_status") or "fetch_pending",  # type: ignore[arg-type]
        attempts=int(raw.get("attempts") or 0),
        last_error_class=str(raw.get("last_error_class") or ""),
        current_stage=str(raw.get("current_stage") or "fetch_pending"),
        next_retry_at=raw.get("next_retry_at"),
        run_id=str(raw.get("run_id") or ""),
        query_id=str(raw.get("query_id") or ""),
        pack_id=str(raw.get("pack_id") or ""),
        lane=str(raw.get("lane") or ""),
        coverage_mode=str(raw.get("coverage_mode") or "complete"),
    )


def _row_to_item(row: dict[str, Any]) -> ArtifactWorkItem:
    return _coerce_item(row)


def work_from_search_item(
    item: dict[str, Any],
    *,
    source_kind: str,
    run_id: str,
    query_id: str,
    pack_id: str,
    lane: str,
    coverage_mode: str = "complete",
    file_path: str = "",
    object_sha: str = "",
) -> ArtifactWorkItem | None:
    """Build a work row from a GitHub search/commit payload (no secrets)."""
    repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
    if not repo and "full_name" not in item:
        # Commit list items may only have url / sha.
        pass
    full_name = str(
        repo.get("full_name") or item.get("repository_full_name") or item.get("full_name") or ""
    )
    repo_id = str(repo.get("id") or item.get("repo_id") or full_name or "")
    sha = str(item.get("sha") or item.get("commit_sha") or "")
    if not sha:
        return None
    if not repo_id and full_name:
        repo_id = full_name
    if not repo_id:
        return None
    return ArtifactWorkItem(
        repo_id=repo_id,
        repository_full_name=full_name or str(repo_id),
        commit_sha=sha,
        file_path=file_path or str(item.get("path") or item.get("file_path") or ""),
        object_sha=object_sha or str(item.get("object_sha") or ""),
        source_kind=source_kind,
        work_status="fetch_pending",
        current_stage="fetch_pending",
        run_id=run_id,
        query_id=query_id,
        pack_id=pack_id,
        lane=lane,
        coverage_mode=coverage_mode,
    )
