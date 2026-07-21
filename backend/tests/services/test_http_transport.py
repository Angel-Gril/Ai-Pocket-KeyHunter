"""Instrumented transport: attempt rows, redaction, endpoint templates."""

from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.request_ledger import RequestLedger, current_ledger
from aipocket.services.http_transport import (
    InstrumentedTransport,
    LedgerContext,
    is_http_header_value_safe,
    normalize_endpoint_class,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", True),
        ("sk-proj-abcdef0123456789", True),
        ("Bearer sk-abc", True),
        ("proj_123", True),
        ("org-ASCII-only", True),
        ("key with spaces and\ttab", True),  # still ASCII
        ("sk-中文密钥", False),
        ("org-组织", False),
        ("emoji-🔑", False),
        ("café", False),
        ("sk-abc\u200bdef", False),  # zero-width space
    ],
)
def test_is_http_header_value_safe(value: str, expected: bool) -> None:
    assert is_http_header_value_safe(value) is expected


def test_is_http_header_value_safe_rejects_non_str() -> None:
    assert is_http_header_value_safe(None) is False  # type: ignore[arg-type]
    assert is_http_header_value_safe(123) is False  # type: ignore[arg-type]


def test_endpoint_class_never_contains_token():
    url = "https://api.github.com/search/commits?q=glm&access_token=SECRETTOKEN1234567890"
    ep = normalize_endpoint_class(url)
    assert "SECRET" not in ep
    assert "access_token" not in ep
    assert "token=" not in ep.lower() or "{redacted}" in ep

    explicit = "/search/commits?token=abc123secret"
    ep2 = normalize_endpoint_class("https://x", explicit)
    assert "abc123" not in ep2


def test_github_path_templating():
    ep = normalize_endpoint_class(
        "https://api.github.com/repos/octo/hello/commits/abcdef0123456789abcdef01"
    )
    assert "{owner}" in ep
    assert "{repo}" in ep
    assert "{sha}" in ep
    assert "abcdef" not in ep


@pytest.mark.asyncio
@respx.mock
async def test_retry_after_429_creates_two_ledger_rows():
    ledger = RequestLedger(run_id="run_http")
    token = current_ledger.set(ledger)
    try:
        route = respx.get("https://example.test/v1/models").mock(
            side_effect=[
                httpx.Response(429, json={"error": "rate"}),
                httpx.Response(200, json={"data": []}),
            ]
        )
        async with httpx.AsyncClient() as client:
            transport = InstrumentedTransport(
                ledger=ledger,
                defaults=LedgerContext(stage="validation", source="validator"),
                client=client,
            )
            r1 = await transport.request("GET", "https://example.test/v1/models", attempt=1)
            assert r1.status_code == 429
            r2 = await transport.request("GET", "https://example.test/v1/models", attempt=2)
            assert r2.status_code == 200
        assert route.call_count == 2
        rows = ledger.drain()
        assert len(rows) == 2
        assert rows[0].attempt == 1 and rows[0].status_code == 429
        assert rows[1].attempt == 2 and rows[1].status_code == 200
        assert all("token" not in (r.endpoint_class or "").lower() for r in rows)
    finally:
        current_ledger.reset(token)


@pytest.mark.asyncio
@respx.mock
async def test_network_error_records_error_class():
    ledger = RequestLedger(run_id="run_err")
    async with httpx.AsyncClient() as client:
        transport = InstrumentedTransport(
            ledger=ledger,
            defaults=LedgerContext(stage="gpt", source="gpt"),
            client=client,
        )
        respx.get("https://example.test/boom").mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(httpx.ConnectError):
            await transport.request("GET", "https://example.test/boom")
    rows = ledger.drain()
    assert len(rows) == 1
    assert rows[0].error_class == "network"
    assert rows[0].status_class == "error"
