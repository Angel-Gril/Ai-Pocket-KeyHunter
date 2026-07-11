"""Unit tests for balance probes (OpenRouter + dispatch)."""

from __future__ import annotations

import httpx
import respx

from aipocket.core.models import Credential
from aipocket.services.balance import query_balance

OR_BASE = "https://openrouter.ai/api/v1"
OR_KEY = "sk-or-v1-" + "a" * 64


def _or_cred(*, apiurl: str = OR_BASE) -> Credential:
    return Credential(apikey=OR_KEY, apiurl=apiurl)


@respx.mock
async def test_openrouter_uses_limit_remaining() -> None:
    respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "label": "test",
                    "usage": 1.5,
                    "limit": 10,
                    "limit_remaining": 8.5,
                    "is_free_tier": False,
                }
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _or_cred())

    assert result["gateway"] == "openrouter"
    assert result["balance_usd"] == 8.5
    assert result["source"] == "key"
    # Should not call /credits when limit_remaining is present.
    assert not any(c.request.url.path.endswith("/credits") for c in respx.calls)


@respx.mock
async def test_openrouter_derives_balance_from_limit_minus_usage() -> None:
    respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "usage": 3.0,
                    "limit": 10.0,
                    "limit_remaining": None,
                    "is_free_tier": False,
                }
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _or_cred())

    assert result["gateway"] == "openrouter"
    assert result["balance_usd"] == 7.0


@respx.mock
async def test_openrouter_falls_back_to_credits_when_unlimited() -> None:
    respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "usage": 12.5,
                    "limit": None,
                    "limit_remaining": None,
                    "is_free_tier": False,
                }
            },
        )
    )
    respx.get("https://openrouter.ai/api/v1/credits").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"total_credits": 50.0, "total_usage": 12.5}},
        )
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _or_cred())

    assert result["gateway"] == "openrouter"
    assert result["balance_usd"] == 37.5
    assert result["source"] == "credits"
    assert result["total_credits"] == 50.0


@respx.mock
async def test_openrouter_free_tier_without_limit_is_zero() -> None:
    respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "usage": 0,
                    "limit": None,
                    "limit_remaining": None,
                    "is_free_tier": True,
                }
            },
        )
    )
    respx.get("https://openrouter.ai/api/v1/credits").mock(
        return_value=httpx.Response(401, json={"error": {"message": "denied"}})
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _or_cred())

    assert result["gateway"] == "openrouter"
    assert result["balance_usd"] == 0.0
    assert result["source"] == "free_tier"


@respx.mock
async def test_openrouter_prefix_forces_official_host() -> None:
    """sk-or-v1 keys should hit openrouter.ai even if credential.apiurl is a proxy."""
    auth = respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "usage": 0,
                    "limit": 5,
                    "limit_remaining": 5,
                    "is_free_tier": False,
                }
            },
        )
    )
    # Proxy host must not be contacted for balance.
    respx.get("https://evil-proxy.example/v1/auth/key").mock(
        return_value=httpx.Response(200, json={"data": {"limit_remaining": 999}})
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(
            client,
            _or_cred(apiurl="https://evil-proxy.example/v1"),
        )

    assert result["gateway"] == "openrouter"
    assert result["balance_usd"] == 5.0
    assert auth.called


@respx.mock
async def test_openrouter_auth_failure_falls_through_to_unsupported() -> None:
    respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(401, json={"error": {"message": "User not found."}})
    )
    # Other probes also miss.
    respx.route(method="GET").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _or_cred())

    assert result == {"gateway": "unsupported", "balance_usd": ""}


@respx.mock
async def test_non_openrouter_key_skips_openrouter_probe() -> None:
    """Ordinary sk- keys on a random host must not hit openrouter.ai."""
    or_route = respx.get("https://openrouter.ai/api/v1/auth/key").mock(
        return_value=httpx.Response(200, json={"data": {"limit_remaining": 99}})
    )
    respx.route(method="GET").mock(return_value=httpx.Response(404))

    cred = Credential(apikey="sk-" + "b" * 48, apiurl="https://gateway.example/v1")
    async with httpx.AsyncClient() as client:
        result = await query_balance(client, cred)

    assert result["gateway"] == "unsupported"
    assert not or_route.called
