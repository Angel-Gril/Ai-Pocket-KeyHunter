"""Sync transport path + redaction edge cases."""

from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.request_ledger import RequestLedger, current_ledger
from aipocket.services.http_transport import (
    InstrumentedTransport,
    LedgerContext,
    normalize_endpoint_class,
    record_sync_attempt,
)


def test_normalize_explicit_bearer_redacted():
    ep = normalize_endpoint_class("https://x", "/v1/models Authorization: Bearer secrettokenvalue")
    assert "secrettokenvalue" not in ep


@respx.mock
def test_request_sync_records_ledger():
    ledger = RequestLedger(run_id="run_sync")
    respx.get("https://example.test/shodan/host/search").mock(
        return_value=httpx.Response(200, json={"matches": []})
    )
    with httpx.Client() as client:
        transport = InstrumentedTransport(
            ledger=ledger,
            defaults=LedgerContext(stage="discovery", source="shodan"),
            sync_client=client,
        )
        r = transport.request_sync(
            "GET",
            "https://example.test/shodan/host/search",
            endpoint_class="/shodan/host/search",
            attempt=1,
        )
        assert r.status_code == 200
    rows = ledger.drain()
    assert len(rows) == 1
    assert rows[0].source == "shodan"
    assert rows[0].endpoint_class == "/shodan/host/search"


@respx.mock
def test_request_sync_timeout_error_class():
    ledger = RequestLedger(run_id="run_sync_to")
    respx.get("https://example.test/slow").mock(side_effect=httpx.TimeoutException("t"))
    with httpx.Client() as client:
        transport = InstrumentedTransport(
            ledger=ledger,
            defaults=LedgerContext(stage="discovery", source="fofa"),
            sync_client=client,
        )
        with pytest.raises(httpx.TimeoutException):
            transport.request_sync("GET", "https://example.test/slow")
    rows = ledger.drain()
    assert rows[0].error_class == "timeout"


def test_record_sync_attempt_uses_context_var():
    ledger = RequestLedger(run_id="run_ctx")
    token = current_ledger.set(ledger)
    try:
        record_sync_attempt(
            method="GET",
            url="https://fofoapi.com/api/v1/search/all?key=SECRETKEY123",
            stage="discovery",
            source="fofa",
            status_code=200,
            attempt=1,
            endpoint_class="/api/v1/search/all",
        )
        rows = ledger.drain()
        assert len(rows) == 1
        assert "SECRET" not in rows[0].endpoint_class
    finally:
        current_ledger.reset(token)


@pytest.mark.asyncio
async def test_transport_requires_client():
    t = InstrumentedTransport(defaults=LedgerContext(stage="gpt", source="gpt"))
    with pytest.raises(RuntimeError):
        await t.request("GET", "https://example.test/")


def test_with_defaults_returns_new_instance():
    ledger = RequestLedger(run_id="r")
    t = InstrumentedTransport(
        ledger=ledger, defaults=LedgerContext(stage="validation", source="validator")
    )
    t2 = t.with_defaults(provider="glm", pack_id="glm")
    assert t2.defaults.provider == "glm"
    assert t2.defaults.pack_id == "glm"
    assert t2.defaults.stage == "validation"
