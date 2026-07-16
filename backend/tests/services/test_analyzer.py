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
@respx.mock
@pytest.mark.parametrize(
    "body",
    [
        {"choices": []},
        {"choices": [{"finish_reason": "stop", "message": None}]},
        {"choices": None},
        {},
        ["not", "a", "dict"],
    ],
)
async def test_chat_malformed_success_bodies(
    monkeypatch: pytest.MonkeyPatch,
    body: object,
) -> None:
    """Empty choices / null message must raise ValueError (caught by extract), not IndexError."""
    monkeypatch.setattr(settings, "gpt_base_url", "https://gpt.example/v1")
    monkeypatch.setattr(settings, "gpt_key", "test-key")
    monkeypatch.setattr(settings, "gpt_model", "test-model")
    monkeypatch.setattr(settings, "gpt_reasoning_effort", "")

    respx.post("https://gpt.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=body),
    )
    async with analyzer._make_client() as client:
        if isinstance(body, dict) and body.get("choices") == [
            {"finish_reason": "stop", "message": None}
        ]:
            assert await analyzer._chat(client, "sys", "user") == ""
        else:
            with pytest.raises(ValueError):
                await analyzer._chat(client, "sys", "user")


def test_content_from_chat_response_helpers() -> None:
    assert (
        analyzer._content_from_chat_response(
            {"choices": [{"message": None, "finish_reason": "length"}]}
        )
        == ""
    )
    assert (
        analyzer._content_from_chat_response(
            {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]}
        )
        == ""
    )
    assert (
        analyzer._content_from_chat_response(
            {"choices": [{"message": {"content": "[]"}, "finish_reason": "stop"}]}
        )
        == "[]"
    )
    with pytest.raises(ValueError):
        analyzer._content_from_chat_response({"choices": []})
    with pytest.raises(ValueError):
        analyzer._content_from_chat_response("nope")
    with pytest.raises(ValueError, match="expected dict"):
        analyzer._content_from_chat_response({"choices": ["not-an-object"]})
    with pytest.raises(ValueError, match="expected dict"):
        analyzer._content_from_chat_response(
            {"choices": [{"message": "string-message", "finish_reason": "stop"}]}
        )
    with pytest.raises(ValueError, match="expected str"):
        analyzer._content_from_chat_response(
            {"choices": [{"message": {"content": ["parts"]}, "finish_reason": "stop"}]}
        )


@pytest.mark.asyncio
@respx.mock
async def test_chat_invalid_json_body_raises_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "gpt_base_url", "https://gpt.example/v1")
    monkeypatch.setattr(settings, "gpt_key", "test-key")
    monkeypatch.setattr(settings, "gpt_model", "test-model")
    monkeypatch.setattr(settings, "gpt_reasoning_effort", "")

    respx.post("https://gpt.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, content=b"not-json{{{"),
    )
    async with analyzer._make_client() as client:
        with pytest.raises(ValueError, match="not valid JSON"):
            await analyzer._chat(client, "sys", "user")


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
async def test_extract_batch_survives_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = [_hit("entry-a", "https://a.example")]

    async def boom(*args, **kwargs):
        raise RuntimeError("unexpected gateway bug")

    monkeypatch.setattr(analyzer, "_chat", boom)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert report.credentials == ()
    assert report.failed_entry_ids == frozenset({"entry-a"})


@pytest.mark.asyncio
async def test_extract_with_gpt_isolates_batch_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One exploding batch must not prevent sibling batches from contributing creds."""
    monkeypatch.setattr(settings, "gpt_base_url", "https://gpt.example/v1")
    monkeypatch.setattr(settings, "gpt_key", "test-key")
    monkeypatch.setattr(settings, "gpt_fast", True)
    monkeypatch.setattr(analyzer, "_batch_size", lambda: 1)
    monkeypatch.setattr(analyzer, "_concurrency", lambda: 2)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)

    calls = {"n": 0}

    async def flaky_chat(client, system, user_content, max_tokens=1000):
        calls["n"] += 1
        if "entry-bad" in user_content:
            raise RuntimeError("kaboom")
        return (
            '[{"entry_id":"entry-good","apikey":"sk-proj-aaaaaaaaaaaaaaaaaaaaaaaa",'
            '"apiurl":"","type":"openai"}]'
        )

    monkeypatch.setattr(analyzer, "_chat", flaky_chat)

    hits = [
        _hit("entry-bad", "https://bad.example"),
        _hit("entry-good", "https://good.example"),
    ]
    report = await analyzer.extract_with_gpt(hits)
    assert len(report.credentials) == 1
    assert report.credentials[0].apikey.startswith("sk-proj-a")
    assert "entry-good" in report.successful_entry_ids
    assert "entry-bad" in report.failed_entry_ids


@pytest.mark.asyncio
async def test_extract_with_gpt_gather_survives_batch_coroutine_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense-in-depth: even if _extract_batch itself raises, gather continues."""
    monkeypatch.setattr(settings, "gpt_base_url", "https://gpt.example/v1")
    monkeypatch.setattr(settings, "gpt_key", "test-key")
    monkeypatch.setattr(analyzer, "_batch_size", lambda: 1)
    monkeypatch.setattr(analyzer, "_concurrency", lambda: 2)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)

    real_extract = analyzer._extract_batch

    async def flaky_extract(client, sem, batch, batch_idx, total_batches):
        if any(h.get("_entry_id") == "entry-bad" for h in batch):
            raise RuntimeError("coroutine crashed before wrapper")
        return await real_extract(client, sem, batch, batch_idx, total_batches)

    async def ok_chat(*args, **kwargs):
        return (
            '[{"entry_id":"entry-good","apikey":"sk-proj-aaaaaaaaaaaaaaaaaaaaaaaa",'
            '"apiurl":"","type":"openai"}]'
        )

    monkeypatch.setattr(analyzer, "_extract_batch", flaky_extract)
    monkeypatch.setattr(analyzer, "_chat", ok_chat)

    report = await analyzer.extract_with_gpt(
        [_hit("entry-bad", "https://bad.example"), _hit("entry-good", "https://good.example")]
    )
    assert len(report.credentials) == 1
    assert "entry-good" in report.successful_entry_ids
    assert "entry-bad" in report.failed_entry_ids


@pytest.mark.asyncio
async def test_extract_batch_survives_malformed_chat_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ValueError from empty choices must become a failed batch, not a crash."""
    batch = [_hit("entry-a", "https://a.example")]

    async def empty_choices(*args, **kwargs):
        raise ValueError("GPT response missing non-empty choices")

    monkeypatch.setattr(analyzer, "_chat", empty_choices)
    monkeypatch.setattr(analyzer, "_dump_failed_batch", lambda *args: None)
    async with httpx.AsyncClient() as client:
        report = await analyzer._extract_batch(client, asyncio.Semaphore(1), batch, 1, 1)
    assert report.failed_entry_ids == frozenset({"entry-a"})
    assert report.credentials == ()


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


def _valid_result(host: str = "https://a.example"):
    from aipocket.core.models import Credential, ValidationResult

    return ValidationResult(
        credential=Credential(apikey="sk-proj-" + "a" * 24, apiurl=host, host=host),
        valid=True,
        status_code=200,
        response_snippet='{"choices":[{"message":{"content":"hi"}}]}',
    )


@pytest.mark.asyncio
async def test_recheck_batch_rejects_invalid_and_skips_bad_idx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = [_valid_result("https://a.example"), _valid_result("https://b.example")]

    async def verdict_response(*args, **kwargs):
        # _parse_json_array requires a pure list-of-dicts; bad idx values are skipped.
        return """[
            {"idx": 0, "valid": false, "reason": "html page", "gateway": "unknown"},
            {"idx": "not-a-number", "valid": false, "reason": "ignore"},
            {"idx": null, "valid": false, "reason": "ignore"},
            {"idx": 1, "valid": true, "reason": "ok", "gateway": "litellm"}
        ]"""

    monkeypatch.setattr(analyzer, "_chat", verdict_response)
    async with httpx.AsyncClient() as client:
        out, ok = await analyzer._recheck_batch(client, asyncio.Semaphore(1), batch, 1, 1)

    assert ok is True
    assert out[0].valid is False
    assert "gpt-rejected" in out[0].error
    assert out[1].valid is True
    assert out[1].gateway == "litellm"


@pytest.mark.asyncio
async def test_recheck_batch_survives_chat_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    batch = [_valid_result()]

    async def boom(*args, **kwargs):
        raise httpx.ReadError("peer closed")

    monkeypatch.setattr(analyzer, "_chat", boom)
    async with httpx.AsyncClient() as client:
        out, ok = await analyzer._recheck_batch(client, asyncio.Semaphore(1), batch, 1, 1)
    assert ok is False
    assert out[0].valid is True  # unchanged on failure


@pytest.mark.asyncio
async def test_run_recheck_wave_isolates_batch_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = [_valid_result("https://good.example")]
    bad = [_valid_result("https://bad.example")]

    async def flaky_recheck(client, sem, batch, batch_idx, total_batches, attribution=None):
        if batch is bad:
            raise RuntimeError("recheck coroutine exploded")
        return batch, True

    monkeypatch.setattr(analyzer, "_recheck_batch", flaky_recheck)
    async with httpx.AsyncClient() as client:
        failed = await analyzer._run_recheck_wave(client, [good, bad], concurrency=2, label="wave1")
    assert failed == [bad]
