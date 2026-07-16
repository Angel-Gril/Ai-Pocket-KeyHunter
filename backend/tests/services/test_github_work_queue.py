"""Tests for github artifact work-queue status machine (memory + fake PG)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aipocket.services.github_checkpoint import (
    CheckpointRow,
    advance_checkpoint_with_work,
)
from aipocket.services.github_work_queue import (
    TERMINAL_STATUSES,
    ArtifactWorkItem,
    claim_pending,
    mark_source_gone,
    mark_terminal,
    mark_transient,
    reset_memory_store,
    transition,
    upsert_work_rows,
    work_from_search_item,
)


@pytest.fixture(autouse=True)
def _clear_memory():
    reset_memory_store()
    yield
    reset_memory_store()


def _item(**kwargs) -> ArtifactWorkItem:
    base = dict(
        repo_id="424242",
        repository_full_name="canary-org/canary-repo",
        commit_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        file_path=".env",
        object_sha="",
        source_kind="commit_message",
        work_status="fetch_pending",
        run_id="run_1",
        query_id="q1",
        pack_id="glm",
        lane="commit_message",
    )
    base.update(kwargs)
    return ArtifactWorkItem(**base)


def test_status_machine_happy_path():
    item = _item()
    upsert_work_rows([item])
    claimed = claim_pending()
    assert len(claimed) == 1
    assert claimed[0].work_status == "fetch_pending"

    transition(item, "extract_pending")
    assert item.work_status == "extract_pending"
    transition(item, "validation_pending")
    mark_terminal(item)
    assert item.work_status == "terminal"
    assert item.work_status in TERMINAL_STATUSES
    # Terminal not reclaimable.
    assert claim_pending() == []


def test_transient_backoff_then_source_gone():
    item = _item()
    for i in range(5):
        mark_transient(item, error_class="network", max_attempts=5)
        if i < 4:
            assert item.work_status == "transient"
            assert item.next_retry_at is not None
        else:
            assert item.work_status == "source_gone"
            assert "max_attempts_exceeded" in item.last_error_class


def test_overlap_reprocess_does_not_duplicate_terminal():
    item = _item()
    upsert_work_rows([item])
    mark_terminal(item)
    # Re-observe same locator as fetch_pending — must stay terminal.
    again = _item(work_status="fetch_pending", repository_full_name="canary-org/renamed")
    upsert_work_rows([again])
    claimed = claim_pending()
    assert claimed == []
    # Display name can update, but status stays terminal (in-memory store).
    from aipocket.services import github_work_queue as gq

    stored = gq._memory_store[item.locator_key]
    assert stored.work_status == "terminal"
    assert stored.repository_full_name == "canary-org/renamed"


def test_repo_id_stable_full_name_display_only():
    item = work_from_search_item(
        {
            "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "repository": {"id": 99, "full_name": "old/name"},
        },
        source_kind="patch",
        run_id="r",
        query_id="q",
        pack_id="glm",
        lane="commit_message",
    )
    assert item is not None
    assert item.repo_id == "99"
    item.repository_full_name = "new/name"
    assert item.repo_id == "99"
    assert item.locator_key[0] == "99"


def test_source_gone_transition():
    item = _item()
    mark_source_gone(item, error_class="http_404")
    assert item.work_status == "source_gone"
    assert item.last_error_class == "http_404"


def test_checkpoint_work_atomicity_with_fake_conn():
    """Simulate mid-page crash: transaction rollback drops both work + checkpoint."""

    class Boom(Exception):
        pass

    class FakeConn:
        def __init__(self):
            self.ops: list[str] = []
            self.fail_on: str | None = None

        def execute(self, sql: str, params: Any = None):
            self.ops.append(sql.strip().split()[0].upper())
            if self.fail_on and self.fail_on in sql:
                raise Boom("crash")
            return self

        def fetchone(self):
            return None

        def fetchall(self):
            return []

    conn = FakeConn()
    items = [_item()]
    cp = CheckpointRow(
        source="github",
        lane="commit_message",
        pack_id="glm",
        shard_id="s1",
        watermark="2026-07-16T00:00:00+00:00",
        cursor_state={"page": 2},
    )

    def upsert(rows, conn=None):
        for r in rows:
            if conn is not None:
                conn.execute(
                    "INSERT INTO github_artifacts ...",
                    r.to_row() if hasattr(r, "to_row") else r,
                )

    advance_checkpoint_with_work(
        checkpoint=cp,
        work_rows=items,
        upsert_work_fn=upsert,
        conn=conn,
    )
    assert any("INSERT" in o or o == "INSERT" for o in conn.ops)

    # Failure during checkpoint after work would be rolled back by real PG;
    # with fail_on we prove both share the same conn path.
    conn2 = FakeConn()
    conn2.fail_on = "source_checkpoints"

    with pytest.raises(Boom):
        advance_checkpoint_with_work(
            checkpoint=cp,
            work_rows=items,
            upsert_work_fn=upsert,
            conn=conn2,
        )


def test_claim_respects_next_retry_at():
    item = _item(work_status="transient")
    item.next_retry_at = datetime.now(UTC) + timedelta(hours=1)
    upsert_work_rows([item])
    assert claim_pending() == []
    item.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
    upsert_work_rows([item])
    # Memory upsert of terminal-guarded path — status still transient.
    from aipocket.services import github_work_queue as gq

    gq._memory_store[item.locator_key] = item
    claimed = claim_pending()
    assert len(claimed) == 1
