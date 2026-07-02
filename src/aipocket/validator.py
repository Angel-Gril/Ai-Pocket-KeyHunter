from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import settings
from .models import Credential, ProviderInfo, ValidationResult

log = logging.getLogger(__name__)

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
    "x-requestid",
    "openai-organization",
    "openai-processing-ms",
    "x-openai-version",
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-tokens-limit",
    "x-tier",
    "tier",
]

# Domain-fingerprint → (provider, category, probe models in priority order).
# High-value models FIRST for honeypot resistance; cheap fallbacks after.
DOMAIN_ROUTING: list[tuple[str, str, str, list[str]]] = [
    ("openai.com", "openai", "international", [
        "gpt-5.5", "gpt-5.4", "gpt-4o-mini", "gpt-3.5-turbo",
    ]),
    ("oaiusercontent", "openai", "international", [
        "gpt-5.5", "gpt-5.4", "gpt-4o-mini",
    ]),
    ("anthropic.com", "anthropic", "international", [
        # sonnet-4-6 first: most widely available high-value model on proxies.
        # fable-5/opus-4-8 are rare; falling through 404s to sonnet is fine.
        "claude-sonnet-4-6", "claude-sonnet-5",
        "claude-opus-4-8", "claude-opus-4-7",
        "claude-haiku-4-5-20251001",
    ]),
    ("deepseek.com", "deepseek", "domestic", [
        "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat",
    ]),
    ("moonshot.cn", "kimi", "domestic", [
        "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "moonshot-v1-8k",
    ]),
    ("bigmodel.cn", "glm", "domestic", [
        "glm-5.2", "glm-5.1", "glm-5", "glm-4-flash",
    ]),
    ("zhipuai", "glm", "domestic", [
        "glm-5.2", "glm-5.1", "glm-5", "glm-4-flash",
    ]),
    ("siliconflow.cn", "siliconflow", "domestic", [
        "deepseek-ai/DeepSeek-V3", "Qwen/Qwen2.5-7B-Instruct",
    ]),
    ("dashscope.aliyuncs.com", "qwen", "domestic", [
        "qwen3.7-max", "qwen3-max", "qwen-turbo",
    ]),
    ("baidu.com", "qwen", "domestic", ["ernie-bot-turbo", "ernie-4.0-8k"]),
    ("googleapis.com", "google", "international", [
        "gemini-3.5-flash", "gemini-3.1-pro-preview", "gemini-1.5-flash",
    ]),
]

# Fallback model list used when the provider is unknown (e.g. a bare IP gateway).
# High-value first — if a random proxy serves gpt-5.5, we want to know.
FALLBACK_MODELS = ["gpt-5.5", "gpt-5.4", "deepseek-v4-flash", "gpt-4o-mini", "gpt-3.5-turbo"]

# High-value models — the core targets. When any of these appear in /v1/models,
# we probe with them FIRST (not as a secondary pass). This avoids honeypot false
# positives: faking gpt-3.5-turbo is trivial, faking gpt-5.5 is not.
# Order: most valuable first. Model IDs sourced from lobehub/model-bank (canary).
HIGH_VALUE_MODELS = [
    # OpenAI frontier
    "gpt-5.5-pro", "gpt-5.5",
    "gpt-5.4-pro", "gpt-5.4",
    # Anthropic — official IDs + common proxy aliases (anthropic/ prefix, dot versions, -latest)
    "claude-sonnet-4-6", "claude-sonnet-5",
    "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
    "claude-fable-5",
    # Proxy variants (OpenRouter/ZenMux style)
    "anthropic/claude-sonnet-4", "anthropic/claude-opus-4",
    "anthropic/claude-opus-4.1", "anthropic/claude-sonnet-4.5",
    # Legacy naming still seen on some proxies
    "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest",
    # Google Gemini (3.5-flash > 3.1-pro > gemini-pro-latest)
    "gemini-3.5-flash",
    "gemini-3.1-pro-preview", "gemini-pro-latest",
    # DeepSeek V4
    "deepseek-v4-pro", "deepseek-v4-flash",
    # Kimi / Moonshot
    "kimi-k2.7-code", "kimi-k2.7-code-highspeed",
    "kimi-k2.6", "kimi-k2.5",
    # Zhipu / GLM
    "glm-5.2", "glm-5.1", "glm-5v-turbo", "glm-5-turbo", "glm-5",
    # Qwen / Alibaba Cloud DashScope
    "qwen3.7-max", "qwen3.6-max-preview", "qwen3-max",
    "qwen3-coder-next", "qwen3-coder-plus",
    "qwen3.7-plus", "qwen3.6-plus", "qwen3.5-plus",
]

# Providers whose native API is NOT /v1/chat/completions.
ANTHROPIC_PROVIDERS = {"anthropic"}

# Key-prefix → (official_api_url, provider_name).
# When a credential's key matches one of these prefixes but its apiurl points to an
# unrelated leaked host (e.g. a PHP blog that exposed the key in response headers),
# we override the apiurl with the official endpoint so the key is actually testable.
KEY_PREFIX_ROUTING: list[tuple[str, str, str]] = [
    ("sk-proj", "https://api.openai.com/v1", "openai"),
    ("sk-ant-api", "https://api.anthropic.com/v1", "anthropic"),
    ("sk-ant-oat", "https://api.anthropic.com/v1", "anthropic"),
    ("sk-ant-sid", "https://api.anthropic.com/v1", "anthropic"),
    ("AIza", "https://generativelanguage.googleapis.com/v1beta", "google"),
]


async def validate_all(credentials: list[Credential]) -> list[ValidationResult]:
    sem = asyncio.Semaphore(settings.validate_concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)
    limits = httpx.Limits(max_connections=settings.validate_concurrency * 2)

    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
        tasks = [_probe_one(client, sem, c) for c in credentials]
        return await asyncio.gather(*tasks)


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    cred: Credential,
) -> ValidationResult:
    async with sem:
        return await _probe(client, cred)


def _route_provider(apiurl: str) -> tuple[str, str, list[str]]:
    """Return (provider, category, probe_models) based on the apiurl domain."""
    host = urlparse(apiurl).hostname or apiurl
    host_lower = host.lower()
    for fingerprint, provider, category, models in DOMAIN_ROUTING:
        if fingerprint in host_lower:
            return provider, category, models
    return "unknown", "unknown", FALLBACK_MODELS


async def _probe(client: httpx.AsyncClient, cred: Credential) -> ValidationResult:
    result = ValidationResult(credential=cred, validated_at=datetime.now(UTC).isoformat())

    effective_url = cred.apiurl

    for prefix, official_url, _provider_name in KEY_PREFIX_ROUTING:
        if cred.apikey.startswith(prefix):
            host = (urlparse(cred.apiurl).hostname or "").lower()
            is_known_gateway = any(
                fingerprint in host for fingerprint, _, _, _ in DOMAIN_ROUTING
            )
            if not is_known_gateway:
                effective_url = official_url
                log.debug(
                    "Key %s… matches prefix '%s' but apiurl '%s' is not a known "
                    "provider gateway → overriding to %s",
                    cred.apikey[:12], prefix, cred.apiurl, official_url,
                )
            break

    api_url = _normalize_apiurl(effective_url)
    if not api_url:
        result.error = "no apiurl"
        return result

    provider, category, probe_models = _route_provider(effective_url)
    result.provider_info = ProviderInfo.model_validate(
        {"provider": provider, "category": category}
    )
    # Best-effort: query /v1/models to enrich models_available for OpenAI-compatible gateways.
    available_models = await _fetch_models_list(client, cred, api_url)
    if available_models:
        result.provider_info.models_available = available_models

        # STRATEGY: Probe with HIGH-VALUE MODELS FIRST if they exist in the list.
        # This serves two purposes:
        # 1. Directly validates access to what we actually want.
        # 2. Honeypot resistance — faking gpt-5.5 quality responses is much harder
        #    than faking gpt-3.5-turbo. If a "gpt-5.5" response reads like gpt-3.5,
        #    something is wrong.
        hv_available = [m for m in HIGH_VALUE_MODELS if m in available_models]
        if hv_available:
            # Put high-value models at the front of probe list
            probe_models = hv_available + probe_models
        else:
            # No high-value models → fall back to cheap probing
            _CHEAP_PROBE_MODELS = [
                "gpt-4o-mini", "gpt-3.5-turbo", "gpt-4.1-nano", "deepseek-chat",
                "qwen-turbo", "moonshot-v1-8k", "glm-4-flash",
            ]
            cheap_available = [m for m in _CHEAP_PROBE_MODELS if m in available_models]
            if cheap_available:
                probe_models = cheap_available[:2] + probe_models
            else:
                for m in probe_models:
                    if m in available_models:
                        probe_models = [m] + [x for x in probe_models if x != m]
                        break
                else:
                    probe_models = available_models[:5] + probe_models

    if provider in ANTHROPIC_PROVIDERS:
        result = await _probe_anthropic(client, cred, api_url, result, probe_models)
    else:
        result = await _probe_chat_completions(client, cred, api_url, result, probe_models)

    return result


async def _fetch_models_list(
    client: httpx.AsyncClient, cred: Credential, chat_url: str
) -> list[str]:
    base = chat_url.replace("/chat/completions", "")
    models_url = base + "/models"
    headers = {"Authorization": f"Bearer {cred.apikey}"}
    try:
        r = await client.get(models_url, headers=headers)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        body = r.json()
    except (ValueError, httpx.DecodingError):
        return []
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list):
        return []
    out: list[str] = []
    for item in data:
        if isinstance(item, dict) and item.get("id"):
            out.append(str(item["id"]))
        elif isinstance(item, str):
            out.append(item)
    return out


async def _probe_anthropic(
    client: httpx.AsyncClient,
    cred: Credential,
    chat_url: str,
    result: ValidationResult,
    probe_models: list[str],
) -> ValidationResult:
    # Anthropic uses /v1/messages with x-api-key header, not /v1/chat/completions.
    messages_url = chat_url.replace("/chat/completions", "/messages")
    for model in probe_models:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
        }
        headers = {
            "x-api-key": cred.apikey,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        try:
            r = await client.post(messages_url, headers=headers, json=payload)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as e:
            result.error = f"{type(e).__name__.lower()}: {e}"
            return result

        result.status_code = r.status_code
        result.rate_limit_headers = _extract_rate_headers(r.headers)

        if r.status_code in (401, 403):
            result.error = f"unauthorized ({r.status_code})"
            return result
        if r.status_code == 404:
            continue
        if r.status_code >= 500:
            result.error = f"server {r.status_code}"
            continue

        if r.status_code == 200:
            body = _parse_json_body(r)
            if body and ("content" in body or "id" in body and body.get("type") == "message"):
                result.valid = True
                result.tier = _infer_tier(result.rate_limit_headers, r.headers)
                result.model_available = model
                result.response_snippet = _snippet(body)
                result.provider_info.models_verified.append(model)
                return result

        if r.status_code == 429:
            body = _parse_json_body(r)
            if body and _looks_like_api_error(body):
                result.valid = True
                result.tier = _infer_tier(result.rate_limit_headers, r.headers)
                result.model_available = model
                result.error = "rate-limited but key is valid"
                # 429 = key is valid but no actual completion — do NOT add to models_verified.
                # models_verified should only contain models that returned a real response.
                return result

        result.error = f"unexpected {r.status_code}: {r.text[:120]}"

    return result


async def _probe_chat_completions(
    client: httpx.AsyncClient,
    cred: Credential,
    api_url: str,
    result: ValidationResult,
    probe_models: list[str],
) -> ValidationResult:
    for model in probe_models:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
            "stream": False,
        }
        headers = {
            "Authorization": f"Bearer {cred.apikey}",
            "Content-Type": "application/json",
        }

        try:
            r = await client.post(api_url, headers=headers, json=payload)
        except httpx.ConnectError as e:
            result.error = f"connect: {e}"
            return result
        except httpx.TimeoutException:
            result.error = "timeout"
            return result
        except httpx.HTTPError as e:
            result.error = f"http: {e}"
            return result

        result.status_code = r.status_code
        result.rate_limit_headers = _extract_rate_headers(r.headers)

        if r.status_code in (401, 403):
            result.error = f"unauthorized ({r.status_code})"
            return result
        if r.status_code == 404:
            continue
        if r.status_code >= 500:
            result.error = f"server {r.status_code}"
            continue

        if r.status_code == 200:
            body = _parse_json_body(r)
            if body is None or not _looks_like_chat_completion(body):
                result.error = f"status 200 but not chat completion (body: {r.text[:120]})"
                return result

            # Model-mismatch detection: if we asked for gpt-5.5 but the response
            # says model=gpt-3.5-turbo, this is a proxy/honeypot that accepts any
            # model name but routes to a cheaper backend.
            actual_model = body.get("model", "")
            if actual_model and model in HIGH_VALUE_MODELS:
                # Check if the response model is significantly different from requested
                requested_family = model.split("-")[0:2]  # e.g. ["gpt", "5.5"]
                actual_family = actual_model.split("-")[0:2]
                if requested_family != actual_family and actual_model != model:
                    log.warning(
                        "Model mismatch: requested %s but got %s for key %s…",
                        model, actual_model, cred.apikey[:12],
                    )
                    # Still mark valid but record the mismatch — don't add to models_verified
                    result.valid = True
                    result.tier = _infer_tier(result.rate_limit_headers, r.headers)
                    result.model_available = actual_model
                    result.response_snippet = _snippet(body)
                    result.error = f"model-mismatch: requested {model}, got {actual_model}"
                    result.provider_info.models_verified.append(actual_model)
                    return result

            result.valid = True
            result.tier = _infer_tier(result.rate_limit_headers, r.headers)
            result.model_available = model
            result.response_snippet = _snippet(body)
            result.provider_info.models_verified.append(model)
            return result

        if r.status_code == 429:
            body = _parse_json_body(r)
            if body is None:
                result.error = f"status 429 non-json (body: {r.text[:120]})"
                return result
            if not _looks_like_api_error(body):
                result.error = f"status 429 but body not api error (body: {r.text[:120]})"
                return result
            result.valid = True
            result.tier = _infer_tier(result.rate_limit_headers, r.headers)
            result.model_available = model
            result.error = "rate-limited but key is valid"
            # 429 = key recognized but no actual completion — do NOT add to models_verified.
            # models_verified should only contain models that returned a real 200 response.
            return result

        # 400 with "model not found" / "model not exist" → try next model, don't fail the key.
        try:
            body_text = r.text[:300]
        except Exception:
            body_text = ""
        low = body_text.lower()
        if r.status_code == 400 and any(kw in low for kw in ("model", "not found", "not exist", "does not exist")):
            continue
        if "model" in low and ("not found" in low or "not exist" in low):
            continue
        result.error = f"unexpected {r.status_code}: {body_text[:120]}"

    return result


def _normalize_apiurl(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith("http"):
        url = "https://" + url
    if "/chat/completions" in url:
        return url
    if url.endswith("/v1"):
        return url + "/chat/completions"
    if "/v1/" in url:
        base = url.split("/v1/")[0]
        return base + "/v1/chat/completions"
    return url.rstrip("/") + "/v1/chat/completions"


def _extract_rate_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    lower_map = {k.lower(): k for k in headers}
    for name in RATE_LIMIT_HEADERS:
        real = lower_map.get(name.lower())
        if real:
            val = headers[real]
            if val:
                out[name] = val
    return out


def _infer_tier(rate_headers: dict[str, str], all_headers: Any) -> str:
    limit_req = rate_headers.get("x-ratelimit-limit-requests")
    if limit_req:
        try:
            n = int(limit_req)
            if n >= 10000:
                return "tier5"
            if n >= 5000:
                return "tier4"
            if n >= 2500:
                return "tier3"
            return f"limit:{n}"
        except ValueError:
            pass

    lower_map = {k.lower(): v for k, v in all_headers.items()}
    if "tier" in lower_map:
        return str(lower_map["tier"])

    return ""


def _snippet(body: dict) -> str:
    try:
        choices = body.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "")
            return str(content)[:200]
        return str(body)[:200]
    except Exception:
        return str(body)[:200]


def _parse_json_body(r: httpx.Response) -> dict | None:
    try:
        body = r.json()
    except (ValueError, httpx.DecodingError):
        return None
    return body if isinstance(body, dict) else None


def _looks_like_chat_completion(body: dict) -> bool:
    if "choices" in body and isinstance(body["choices"], list):
        return True
    obj = str(body.get("object", "")).lower()
    if "chat.completion" in obj:
        return True
    if "error" in body and "choices" not in body:
        return False
    return False


def _looks_like_api_error(body: dict) -> bool:
    if "error" in body:
        return True
    msg = str(body.get("message", "")).lower()
    detail = str(body.get("detail", "")).lower()
    return bool(any(kw in msg or kw in detail for kw in ("rate", "limit", "quota", "exceeded", "unauthorized")))
