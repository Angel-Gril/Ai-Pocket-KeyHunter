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


@pytest.mark.asyncio
async def test_extract_batch_attributes_credentials_by_entry_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = [_hit("entry-a", "https://a.example"), _hit("entry-b", "https://b.example")]

    async def reversed_response(*args, **kwargs):
        return """[
            {"entry_id":"entry-b","apikey":"sk-proj-bbbbbbbbbbbbbbbbbbbbbbbb","apiurl":"","type":"openai"},
            {"entry_id":"entry-a","apikey":"sk-proj-aaaaaaaaaaaaaaaaaaaaaaaa","apiurl":"","type":"openai"}
        ]"""

    monkeypatch.setattr(analyzer, "_chat", reversed_response)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert [(cred.apikey, cred.host) for cred in report.credentials] == [
        ("sk-proj-bbbbbbbbbbbbbbbbbbbbbbbb", "https://b.example"),
        ("sk-proj-aaaaaaaaaaaaaaaaaaaaaaaa", "https://a.example"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_id", [None, "entry-unknown"])
async def test_extract_batch_rejects_missing_or_unknown_entry_id(
    monkeypatch: pytest.MonkeyPatch,
    entry_id: str | None,
) -> None:
    batch = [_hit("entry-a", "https://a.example")]

    async def invalid_attribution(*args, **kwargs):
        item = {
            "apikey": "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaa",
            "apiurl": "",
            "type": "openai",
        }
        if entry_id is not None:
            item["entry_id"] = entry_id
        import json

        return json.dumps([item])

    monkeypatch.setattr(analyzer, "_chat", invalid_attribution)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert report.credentials == ()
