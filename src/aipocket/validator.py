from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from .config import settings
from .models import Credential, ValidationResult

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

PROBE_MODELS = ["gpt-3.5-turbo", "gpt-4o-mini", "gpt-4-mini", "claude-3-5-haiku-20241022"]


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


async def _probe(client: httpx.AsyncClient, cred: Credential) -> ValidationResult:
    result = ValidationResult(credential=cred, validated_at=datetime.now(UTC).isoformat())

    api_url = _normalize_apiurl(cred.apiurl)
    if not api_url:
        result.error = "no apiurl"
        return result

    for model in PROBE_MODELS:
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
            return result

        try:
            body_text = r.text[:300]
        except Exception:
            body_text = ""
        if "model" in body_text.lower() and "not found" in body_text.lower():
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
