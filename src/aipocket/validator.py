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
# First model that returns a real chat completion (or a rate-limit error) wins.
DOMAIN_ROUTING: list[tuple[str, str, str, list[str]]] = [
    ("openai.com", "openai", "international", ["gpt-4o-mini", "gpt-3.5-turbo", "gpt-4o"]),
    ("oaiusercontent", "openai", "international", ["gpt-4o-mini", "gpt-3.5-turbo"]),
    ("anthropic.com", "anthropic", "international", ["claude-3-5-haiku-20241022", "claude-3-haiku-20240307"]),
    ("deepseek.com", "deepseek", "domestic", ["deepseek-chat", "deepseek-coder"]),
    ("moonshot.cn", "kimi", "domestic", ["moonshot-v1-8k", "moonshot-v1-32k", "kimi-k2-0905-preview"]),
    ("bigmodel.cn", "glm", "domestic", ["glm-4-flash", "glm-4-air", "glm-4-flashx"]),
    ("zhipuai", "glm", "domestic", ["glm-4-flash", "glm-4-air"]),
    ("siliconflow.cn", "siliconflow", "domestic", ["Qwen/Qwen2.5-7B-Instruct", "deepseek-ai/DeepSeek-V3"]),
    ("dashscope.aliyuncs.com", "qwen", "domestic", ["qwen-turbo", "qwen-plus"]),
    ("baidu.com", "qwen", "domestic", ["ernie-bot-turbo", "ernie-4.0-8k"]),
    ("googleapis.com", "google", "international", ["gemini-1.5-flash"]),
]

# Fallback model list used when the provider is unknown (e.g. a bare IP gateway).
FALLBACK_MODELS = ["gpt-3.5-turbo", "gpt-4o-mini", "deepseek-chat", "qwen-turbo"]

# Providers whose native API is NOT /v1/chat/completions.
ANTHROPIC_PROVIDERS = {"anthropic"}


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

    api_url = _normalize_apiurl(cred.apiurl)
    if not api_url:
        result.error = "no apiurl"
        return result

    provider, category, probe_models = _route_provider(cred.apiurl)
    result.provider_info = ProviderInfo.model_validate(
        {"provider": provider, "category": category}
    )
    # Best-effort: query /v1/models to enrich models_available for OpenAI-compatible gateways.
    available_models = await _fetch_models_list(client, cred, api_url)
    if available_models:
        result.provider_info.models_available = available_models
        # Prefer to probe with a model we know the gateway actually serves.
        for m in probe_models:
            if m in available_models:
                probe_models = [m] + [x for x in probe_models if x != m] + available_models[:3]
                break
        else:
            # None of our routed models are in the list — use the gateway's own list.
            probe_models = available_models[:5] + probe_models

    if provider in ANTHROPIC_PROVIDERS:
        return await _probe_anthropic(client, cred, api_url, result, probe_models)

    return await _probe_chat_completions(client, cred, api_url, result, probe_models)


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
                result.provider_info.models_verified.append(model)
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
            result.provider_info.models_verified.append(model)
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
