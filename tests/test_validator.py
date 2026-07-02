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

BASE = "https://api.openai.com"
VALID_KEY = "sk-proj-validkey1234567890abcdefghijklmno"
CHAT_URL = f"{BASE}/v1/chat/completions"
MODELS_URL = f"{BASE}/v1/models"


def _mock_models_empty():
    respx.get(MODELS_URL).mock(return_value=httpx.Response(404))


def _make_headers(rate_limit: int | None = None, extra: dict[str, str] | None = None):
    h: dict[str, str] = {"content-type": "application/json"}
    if rate_limit is not None:
        h["x-ratelimit-limit-requests"] = str(rate_limit)
    if extra:
        h.update(extra)
    return h


@respx.mock
async def test_probe_success_200():
    _mock_models_empty()
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
    assert r.model_available == "gpt-5.5"
    assert "Hi there" in r.response_snippet


@respx.mock
async def test_probe_rate_limited_429_counts_valid():
    _mock_models_empty()
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
    _mock_models_empty()
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
    _mock_models_empty()
    respx.post(CHAT_URL).mock(side_effect=httpx.ConnectError("refused"))
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False
    assert "connect" in r.error


@respx.mock
async def test_probe_timeout():
    _mock_models_empty()
    respx.post(CHAT_URL).mock(side_effect=httpx.ReadTimeout("slow"))
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False
    assert r.error == "timeout"


@respx.mock
async def test_probe_server_error_500():
    _mock_models_empty()
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
    respx.get("https://api.openai.com/v1/models").mock(return_value=httpx.Response(404))
    respx.get("https://api.anthropic.com/v1/models").mock(return_value=httpx.Response(404))
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"content": [{"text": "hi"}], "type": "message"})
    )
    creds = [
        Credential(apikey="sk-proj-keyA1234567890abcdefghijklmno", apiurl="https://api.openai.com"),
        Credential(apikey="sk-ant-api03-keyB1234567890abcdefghijklmnop", apiurl="https://api.anthropic.com"),
    ]
    results = await validate_all(creds)
    assert len(results) == 2
    assert all(r.valid for r in results)


@respx.mock
async def test_probe_rejects_spa_html_200():
    """Regression: Flowise/OpenWebUI SPA returns 200 HTML for any path."""
    _mock_models_empty()
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(
            200,
            text="<!DOCTYPE html><html><head><title>Flowise</title></head></html>",
            headers={"content-type": "text/html"},
        )
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False
    assert "not chat completion" in r.error


@respx.mock
async def test_probe_rejects_welcome_page_json_200():
    """Regression: some gateways return 200 with non-completion JSON."""
    _mock_models_empty()
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(200, json={"status": "ok", "service": "proxy"})
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False


@respx.mock
async def test_probe_rejects_html_429():
    """Regression: WAF 429 HTML page must not count as valid."""
    _mock_models_empty()
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(429, text="<html><body>Blocked</body></html>")
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE)
    async with httpx.AsyncClient() as client:
        r = await _probe(client, cred)
    assert r.valid is False


@respx.mock
async def test_probe_follows_redirect():
    """Regression: HTTP->HTTPS 301 must be followed."""
    respx.get("http://api.example.com/v1/models").mock(return_value=httpx.Response(404))
    https_url = "https://api.example.com/v1/chat/completions"
    respx.post("http://api.example.com/v1/chat/completions").mock(
        return_value=httpx.Response(301, headers={"location": https_url})
    )
    respx.get(https_url).mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    cred = Credential(apikey="generickey_no_sk_prefix_1234567890", apiurl="http://api.example.com")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        r = await _probe(client, cred)
    assert r.valid is True
