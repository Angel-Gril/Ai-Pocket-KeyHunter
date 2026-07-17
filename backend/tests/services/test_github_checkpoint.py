"""Unit tests for source_checkpoints load/save (fake PG connection)."""

from __future__ import annotations

from typing import Any

from aipocket.discovery.base import CheckpointUpdate
from aipocket.services.github_checkpoint import (
    CheckpointRow,
    advance_checkpoint_with_work,
    load_checkpoint,
    load_lane_checkpoints,
    save_checkpoint,
    watermark_now,
)
from aipocket.services.github_work_queue import ArtifactWorkItem, reset_memory_store


class _FakeCursor:
    def __init__(self, rows: list[dict] | None = None):
        self._rows = rows or []
        self.executed: list[tuple[str, Any]] = []

    def execute(self, sql: str, params: Any = None):
        self.executed.append((sql, params))
        return self

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeConn:
    def __init__(self, rows: list[dict] | None = None):
        self.cur = _FakeCursor(rows)

    def execute(self, sql: str, params: Any = None):
        return self.cur.execute(sql, params)


def test_watermark_now_iso():
    w = watermark_now()
    assert "T" in w


def test_checkpoint_row_to_update():
    row = CheckpointRow(
        source="github",
        lane="commit_message",
        pack_id="glm",
        shard_id="s1",
        watermark="2026-01-01T00:00:00+00:00",
        cursor_state={"page": 2},
        etag="etag1",
        status="ok",
    )
    upd = row.to_update()
    assert upd.shard_id == "s1"
    assert upd.cursor_state["page"] == 2


def test_load_checkpoint_none_when_pg_disabled(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert load_checkpoint(lane="commit_message", pack_id="glm", shard_id="x") is None


def test_load_checkpoint_with_conn():
    conn = _FakeConn(
        [
            {
                "source": "github",
                "lane": "commit_message",
                "pack_id": "glm",
                "shard_id": "s1",
                "watermark": "w1",
                "cursor_state": {"page": 1},
                "etag": "e",
                "status": "ok",
                "updated_at": None,
            }
        ]
    )
    row = load_checkpoint(lane="commit_message", pack_id="glm", shard_id="s1", conn=conn)
    assert row is not None
    assert row.watermark == "w1"
    assert row.cursor_state["page"] == 1


def test_load_checkpoint_missing_row():
    conn = _FakeConn([])
    assert load_checkpoint(lane="x", pack_id="y", shard_id="z", conn=conn) is None


def test_load_lane_checkpoints():
    conn = _FakeConn(
        [
            {
                "source": "github",
                "lane": "code_snapshot",
                "pack_id": "glm",
                "shard_id": "a",
                "watermark": "w",
                "cursor_state": {},
                "etag": "",
                "status": "truncated",
                "updated_at": None,
            }
        ]
    )
    rows = load_lane_checkpoints(lane="code_snapshot", pack_id="glm", conn=conn)
    assert len(rows) == 1
    assert rows[0].status == "truncated"


def test_save_checkpoint_with_conn():
    conn = _FakeConn()
    update = CheckpointUpdate(
        source="github",
        lane="commit_message",
        pack_id="glm",
        shard_id="s1",
        watermark="wm",
        cursor_state={"page": 3},
        etag="et",
        status="ok",
    )
    save_checkpoint(update, conn=conn)
    assert conn.cur.executed
    assert "source_checkpoints" in conn.cur.executed[0][0]


def test_advance_checkpoint_with_work_memory(monkeypatch):
    reset_memory_store()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_work_queue.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_checkpoint.settings.database_url", "")

    from aipocket.services.github_work_queue import claim_pending, upsert_work_rows

    update = CheckpointUpdate(
        source="github",
        lane="commit_message",
        pack_id="glm",
        shard_id="s1",
        watermark="wm2",
        cursor_state={"page": 1},
    )
    item = ArtifactWorkItem(
        repo_id="1",
        repository_full_name="o/r",
        commit_sha="abc",
        file_path="",
        object_sha="",
        source_kind="commit_message",
        work_status="fetch_pending",
        run_id="run1",
        query_id="q1",
        pack_id="glm",
        lane="commit_message",
    )
    # Without PG, advance should still upsert memory work rows + accept update.
    advance_checkpoint_with_work(
        checkpoint=update,
        work_rows=[item.to_row()],
        upsert_work_fn=upsert_work_rows,
    )
    claimed = claim_pending(limit=10)
    assert any(i.commit_sha == "abc" for i in claimed)
