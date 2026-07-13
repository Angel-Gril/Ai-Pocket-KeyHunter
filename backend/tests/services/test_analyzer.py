from __future__ import annotations

import asyncio

import httpx
import pytest

from aipocket.services import analyzer


def _hit(entry_id: str, host: str) -> dict[str, str]:
    return {
        "_entry_id": entry_id,
        "host": host,
        "banner": "OPENAI_API_KEY=sk-proj-" + "a" * 24,
    }


@pytest.mark.asyncio
async def test_extract_batch_reports_successful_entries_even_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = [_hit("entry-a", "https://a.example"), _hit("entry-b", "https://b.example")]

    async def empty_response(*args, **kwargs):
        return "[]"

    monkeypatch.setattr(analyzer, "_chat", empty_response)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert report.credentials == ()
    assert report.successful_entry_ids == frozenset({"entry-a", "entry-b"})
    assert report.failed_entry_ids == frozenset()


@pytest.mark.asyncio
async def test_extract_batch_reports_all_entries_failed_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = [_hit("entry-a", "https://a.example"), _hit("entry-b", "https://b.example")]

    async def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(analyzer, "_chat", timeout)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert report.credentials == ()
    assert report.successful_entry_ids == frozenset()
    assert report.failed_entry_ids == frozenset({"entry-a", "entry-b"})
