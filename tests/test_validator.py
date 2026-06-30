from __future__ import annotations

import httpx
import respx

from aipocket.models import Credential
from aipocket.validator import (
    _extract_rate_headers,
    _infer_tier,
    _normalize_apiurl,
    _probe,
    validate_all,
)

BASE = "https://api.example.com"
VALID_KEY = "sk-proj-validkey1234567890abcdefghijklm"
CHAT_URL = f"{BASE}/v1/chat/completions"


def _make_headers(rate_limit: int | None = None, extra: dict[str, str] | None = None):
    h: dict[str, str] = {"content-type": "application/json"}
    if rate_limit is not None:
        h["x-ratelimit-limit-requests"] = str(rate_limit)
    if extra:
        h.update(extra)
    return h


@respx.mock
async def test_probe_success_200():
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Hi there"}}]},
            headers=_make_headers(rate_limit=10000),
        )
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is True
    assert r.status_code == 200
    assert r.tier == "tier5"
    assert r.model_available == "gpt-3.5-turbo"
    assert "Hi there" in r.response_snippet


@respx.mock
async def test_probe_rate_limited_429_counts_valid():
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(429, json={"error": "rate limited"}, headers=_make_headers(rate_limit=5000))
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is True
    assert r.tier == "tier4"
    assert "rate-limited" in r.error


@respx.mock
async def test_probe_401_then_404_no_valid():
    route = respx.post(CHAT_URL)
    route.side_effect = [
        httpx.Response(401, json={"error": "unauthorized"}),
    ] + [httpx.Response(404, json={"error": "model not found"}) for _ in range(10)]
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False


@respx.mock
async def test_probe_connect_error():
    respx.post(CHAT_URL).mock(side_effect=httpx.ConnectError("refused"))
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False
    assert "connect" in r.error


@respx.mock
async def test_probe_timeout():
    respx.post(CHAT_URL).mock(side_effect=httpx.ReadTimeout("slow"))
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False
    assert r.error == "timeout"


@respx.mock
async def test_probe_server_error_500():
    respx.post(CHAT_URL).mock(return_value=httpx.Response(503, text="unavailable"))
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False


def test_normalize_apiurl_adds_v1_chat_completions():
    assert _normalize_apiurl("api.example.com") == "https://api.example.com/v1/chat/completions"


def test_normalize_apiurl_keeps_existing_path():
    url = "https://api.example.com/v1/chat/completions"
    assert _normalize_apiurl(url) == url


def test_normalize_apiurl_appends_to_v1():
    assert _normalize_apiurl("https://api.example.com/v1") == "https://api.example.com/v1/chat/completions"


def test_normalize_apiurl_replaces_v1_subpath():
    assert _normalize_apiurl("https://api.example.com/v1/models") == "https://api.example.com/v1/chat/completions"


def test_normalize_apiurl_empty():
    assert _normalize_apiurl("") == ""


def test_infer_tier_tier5():
    headers = {"x-ratelimit-limit-requests": "10000"}
    assert _infer_tier({"x-ratelimit-limit-requests": "10000"}, headers) == "tier5"


def test_infer_tier_tier4():
    assert _infer_tier({"x-ratelimit-limit-requests": "5000"}, {}) == "tier4"


def test_infer_tier_tier3():
    assert _infer_tier({"x-ratelimit-limit-requests": "2500"}, {}) == "tier3"


def test_infer_tier_low_limit():
    assert _infer_tier({"x-ratelimit-limit-requests": "100"}, {}) == "limit:100"


def test_infer_tier_from_header():
    assert _infer_tier({}, {"tier": "tier5"}) == "tier5"


def test_infer_tier_empty():
    assert _infer_tier({}, {}) == ""


def test_extract_rate_headers_finds_known():
    raw_headers = {
        "x-ratelimit-limit-requests": "10000",
        "x-ratelimit-remaining-requests": "9999",
        "openai-organization": "org-abc",
        "content-type": "application/json",
    }
    h = httpx.Headers(raw_headers)
    extracted = _extract_rate_headers(h)
    assert "x-ratelimit-limit-requests" in extracted
    assert extracted["x-ratelimit-limit-requests"] == "10000"
    assert "openai-organization" in extracted
    assert "content-type" not in extracted


def test_extract_rate_headers_case_insensitive():
    h = httpx.Headers({"X-RateLimit-Limit-Requests": "5000"})
    extracted = _extract_rate_headers(h)
    assert extracted["x-ratelimit-limit-requests"] == "5000"


@respx.mock
async def test_validate_all_runs_concurrently():
    respx.post("https://a.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    respx.post("https://b.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    creds = [
        Credential(apikey="sk-proj-keyA1234567890abcdefghijklmno", apiurl="https://a.com"),
        Credential(apikey="sk-proj-keyB1234567890abcdefghijklmno", apiurl="https://b.com"),
    ]
    results = await validate_all(creds)
    assert len(results) == 2
    assert all(r.valid for r in results)
