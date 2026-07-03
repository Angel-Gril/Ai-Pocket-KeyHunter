from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.models import Credential, ValidationResult
from aipocket.validator import (
    _extract_rate_headers,
    _infer_tier,
    _is_severe_model_mismatch,
    _model_family_and_gen,
    _normalize_apiurl,
    _probe,
    validate_all,
    verify_no_auth,
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


# ---------------------------------------------------------------------------
# Model-mismatch severity — distinguishes a legitimate within-family downgrade
# (gpt-5.5 → gpt-5.4) from a honeypot cross-generation/family swap
# (gpt-5.5 → gpt-4o-mini / claude).
# ---------------------------------------------------------------------------


class TestModelFamilyAndGen:
    def test_gpt_with_version(self):
        assert _model_family_and_gen("gpt-5.5") == ("gpt", "5")
        assert _model_family_and_gen("gpt-5.4-pro") == ("gpt", "5")

    def test_gpt_4o_extracts_gen_4(self):
        # gpt-4o-mini → family gpt, generation 4 (the 'o' is skipped, '4' is gen)
        fam, gen = _model_family_and_gen("gpt-4o-mini")
        assert fam == "gpt"
        assert gen == "4"

    def test_gpt_35_extracts_gen_3(self):
        fam, gen = _model_family_and_gen("gpt-3.5-turbo")
        assert fam == "gpt"
        assert gen == "3"

    def test_claude_family(self):
        assert _model_family_and_gen("claude-sonnet-4-6") == ("claude", "4")
        assert _model_family_and_gen("claude-opus-4-8") == ("claude", "4")

    def test_deepseek_family(self):
        assert _model_family_and_gen("deepseek-v4-flash") == ("deepseek", "4")

    def test_glm_family(self):
        assert _model_family_and_gen("glm-5.1") == ("glm", "5")


class TestIsSevereModelMismatch:
    @pytest.mark.parametrize("requested,actual", [
        ("gpt-5.5", "gpt-5.4"),            # same gen, mild downgrade
        ("claude-opus-4-8", "claude-sonnet-4-6"),  # same claude gen
        ("deepseek-v4-pro", "deepseek-v4-flash"),  # same ds gen
        ("glm-5.1", "glm-5.2"),            # same glm gen
    ])
    def test_mild_within_family_is_not_severe(self, requested, actual):
        assert _is_severe_model_mismatch(requested, actual) is False

    @pytest.mark.parametrize("requested,actual", [
        ("gpt-5.5", "gpt-4o-mini"),        # cross-generation gpt5→gpt4
        ("gpt-5.5", "gpt-3.5-turbo"),      # cross-generation gpt5→gpt3
        ("gpt-5.5", "claude-sonnet-4-6"),  # cross-family gpt→claude
        ("gpt-5.5", "deepseek-v4-flash"),  # cross-family gpt→deepseek
        ("claude-opus-4-8", "gpt-4o-mini"),  # cross-family+gen
        ("glm-5.1", "gpt-4o-mini"),        # cross-family glm→gpt
    ])
    def test_cross_gen_or_family_is_severe(self, requested, actual):
        assert _is_severe_model_mismatch(requested, actual) is True

    def test_identical_model_not_severe(self):
        assert _is_severe_model_mismatch("gpt-5.5", "gpt-5.5") is False


# ---------------------------------------------------------------------------
# verify_no_auth — forged-key probe. Mocked so no real network.
# ---------------------------------------------------------------------------


def _vr(host: str, apiurl: str, valid: bool = True) -> ValidationResult:
    return ValidationResult(
        credential=Credential(
            apikey="sk-realkey1234567890abcdef", apiurl=apiurl, host=host,
            source="test", source_type="fingerprint",
        ),
        valid=valid,
        status_code=200,
        model_available="gpt-5.5",
    )


@respx.mock
async def test_verify_no_auth_detects_noauth_host():
    """A host where the FORGED key also returns a chat completion is flagged."""
    url = "http://honeypot.example:8139/v1/chat/completions"
    # Forged key gets 200 + completion → no-auth
    respx.post(url).mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"content": "hi"}}], "model": "gpt-5.5"}
        )
    )
    results = [_vr("honeypot.example:8139", "http://honeypot.example:8139")]
    no_auth, suspicious = await verify_no_auth(results)
    assert "honeypot.example:8139" in no_auth
    assert suspicious == set()


@respx.mock
async def test_verify_no_auth_passes_real_gateway():
    """A real gateway rejects the forged key (401) → not flagged."""
    url = "http://real.example.com/v1/chat/completions"
    respx.post(url).mock(return_value=httpx.Response(401, json={"error": "invalid key"}))
    results = [_vr("real.example.com", "http://real.example.com")]
    no_auth, suspicious = await verify_no_auth(results)
    assert no_auth == set()
    assert suspicious == set()


@respx.mock
async def test_verify_no_auth_429_marks_suspicious():
    """Forged key getting 429 = open-proxy signal (real gateways return 401, never 429)."""
    url = "http://openproxy.example/v1/chat/completions"
    respx.post(url).mock(return_value=httpx.Response(429, json={"error": "rate limited"}))
    results = [_vr("openproxy.example", "http://openproxy.example")]
    no_auth, suspicious = await verify_no_auth(results)
    assert no_auth == set()
    assert "openproxy.example" in suspicious


@respx.mock
async def test_verify_no_auth_200_but_not_completion_marks_suspicious():
    """200 returning non-completion on every retry → host is not a real gateway."""
    url = "http://weird.example/v1/chat/completions"
    respx.post(url).mock(
        return_value=httpx.Response(200, json={"stok": "abc", "saved": True})
    )
    results = [_vr("weird.example", "http://weird.example")]
    no_auth, suspicious = await verify_no_auth(results)
    assert no_auth == set()
    assert "weird.example" in suspicious


@respx.mock
async def test_verify_no_auth_one_host_probed_once():
    """Multiple keys on the SAME host → only ONE forged probe (per-host, not per-key)."""
    url = "http://multi.example/v1/chat/completions"
    route = respx.post(url).mock(return_value=httpx.Response(401))
    host = "multi.example"
    results = [
        _vr(host, "http://multi.example", valid=True),
        _vr(host, "http://multi.example", valid=True),
        _vr(host, "http://multi.example", valid=True),
    ]
    await verify_no_auth(results)
    assert route.call_count == 1  # dedup by host


async def test_verify_no_auth_empty_results():
    """No valid results → no probes, empty sets."""
    assert await verify_no_auth([]) == (set(), set())


# ---------------------------------------------------------------------------
# Routing override persistence — a key scraped from a non-gateway host (leak
# blog / Shodan banner) is validated against the official provider endpoint;
# the override is written back to cred.apiurl/host and leak_host preserves the
# original source.
# ---------------------------------------------------------------------------

LEAK_URL = "http://161.97.182.228:8788"  # a leaking blog, not an OpenAI gateway


@respx.mock
async def test_probe_persists_routing_override_to_official():
    """sk-proj- key scraped from a blog → validated against api.openai.com;
    cred.apiurl/host updated, leak_host preserves the blog URL."""
    _mock_models_empty()
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(429, json={"error": "rate limited"})
    )
    cred = Credential(apikey=VALID_KEY, apiurl=LEAK_URL, host="161.97.182.228:8788")
    async with httpx.AsyncClient() as client:
        await _probe(client, cred)
    assert cred.routed_to_official is True
    assert cred.apiurl == "https://api.openai.com/v1"
    assert cred.host == "api.openai.com"
    assert cred.leak_host == LEAK_URL
    # ip/port described the leak host, not the official gateway → cleared
    assert cred.ip == ""
    assert cred.port == ""


@respx.mock
async def test_probe_no_override_when_apiurl_is_already_gateway():
    """If apiurl is already a known provider gateway, no override happens."""
    _mock_models_empty()
    respx.post(CHAT_URL).mock(
        return_value=httpx.Response(429, json={"error": "rate limited"})
    )
    cred = Credential(apikey=VALID_KEY, apiurl=BASE, host="api.openai.com")
    async with httpx.AsyncClient() as client:
        await _probe(client, cred)
    assert cred.routed_to_official is False
    assert cred.leak_host == ""
    assert cred.apiurl == BASE


@respx.mock
async def test_verify_no_auth_probes_post_routing_apiurl():
    """For a routed key, the forged probe targets the OFFICIAL endpoint
    (api.openai.com), not the leak blog. The blog URL is never hit."""
    _mock_models_empty()
    official_url = "https://api.openai.com/v1/chat/completions"
    # Only the official endpoint is mocked; the leak blog URL is left
    # unregistered so any request to it would raise AllMockedAssertionError.
    official_route = respx.post(official_url).mock(
        return_value=httpx.Response(401, json={"error": "invalid key"})
    )
    cred = Credential(
        apikey=VALID_KEY, apiurl=LEAK_URL, host="161.97.182.228:8788",
    )
    # Simulate the post-_probe state: routing already persisted.
    cred.leak_host = LEAK_URL
    cred.apiurl = "https://api.openai.com/v1"
    cred.host = "api.openai.com"
    cred.routed_to_official = True
    result = ValidationResult(credential=cred, valid=True, model_available="gpt-5.5")
    no_auth, suspicious = await verify_no_auth([result])
    assert official_route.call_count == 1   # probed the official endpoint
    assert no_auth == set()                  # 401 → real gateway
    assert suspicious == set()
