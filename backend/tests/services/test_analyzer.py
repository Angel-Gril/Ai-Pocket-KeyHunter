from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from aipocket.core.config import settings
from aipocket.services import analyzer


def _hit(entry_id: str, host: str) -> dict[str, str]:
    return {
        "_entry_id": entry_id,
        "host": host,
        "banner": "OPENAI_API_KEY=sk-proj-" + "a" * 24,
    }


def test_parse_json_array_handles_none_and_empty() -> None:
    assert analyzer._parse_json_array(None) is None
    assert analyzer._parse_json_array("") is None
    assert analyzer._parse_json_array("   ") is None
    assert analyzer._extract_json_array(None) == []
    assert analyzer._extract_json_object(None) == {}


def test_blob_to_credential_handles_null_fields() -> None:
    targets = {"e1": {"host": "https://a.example", "_entry_id": "e1"}}
    assert (
        analyzer._blob_to_credential(
            {"entry_id": "e1", "apikey": None, "apiurl": None, "type": "openai"},
            targets,
        )
        is None
    )
    assert (
        analyzer._blob_to_credential(
            {"entry_id": "e1", "apikey": 12345, "apiurl": [], "type": "openai"},
            targets,
        )
        is None
    )


@pytest.mark.asyncio
@respx.mock
async def test_chat_null_content_returns_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "gpt_base_url", "https://gpt.example/v1")
    monkeypatch.setattr(settings, "gpt_key", "test-key")
    monkeypatch.setattr(settings, "gpt_model", "test-model")
    monkeypatch.setattr(settings, "gpt_reasoning_effort", "")

    respx.post("https://gpt.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"role": "assistant", "content": None},
                        "finish_reason": "stop",
                    }
                ]
            },
        )
    )
    async with analyzer._make_client() as client:
        result = await analyzer._chat(client, "sys", "user")
    assert result == ""


@pytest.mark.asyncio
async def test_extract_batch_survives_null_chat_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200 with content=null must not crash the whole scan gather."""
    batch = [_hit("entry-a", "https://a.example")]

    async def null_content(*args, **kwargs):
        return None  # type: ignore[return-value]

    monkeypatch.setattr(analyzer, "_chat", null_content)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert report.credentials == ()
    assert report.successful_entry_ids == frozenset()
    assert report.failed_entry_ids == frozenset({"entry-a"})


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
