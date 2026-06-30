from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from .config import settings
from .models import Credential, ValidationResult

log = logging.getLogger(__name__)

EXTRACT_SYSTEM = (
    "You are a security credential extraction tool. Extract leaked API keys and their "
    "corresponding API URLs/base URLs from the given text. Return ONLY a JSON array, "
    'no explanation. Each element: {"host": "...", "apikey": "...", "apiurl": "...", "type": "openai|anthropic|generic"}. '
    "Skip HTTP header field names, MIME types, and non-key strings. An apiurl must be a real http(s) URL. "
    "If no credentials found, return []."
)

RECHECK_SYSTEM = (
    "You are a security validation tool. Given a chat completion API probe's HTTP status code and response body, "
    "determine if the API key is genuinely valid for LLM inference. Return JSON: "
    '{"valid": true/false, "reason": "...", "gateway": "litellm|oneapi|openai|unknown"}. '
    "valid=true ONLY if the response is a real chat completion JSON or a rate-limit error from an LLM gateway. "
    "valid=false if it's HTML, a welcome page, a WAF block, or an unrelated service."
)

GPT_CONCURRENCY = 3
EXTRACT_BATCH_SIZE = 15


def _concurrency() -> int:
    return 5 if settings.gpt_fast else GPT_CONCURRENCY


def _batch_size() -> int:
    return 30 if settings.gpt_fast else EXTRACT_BATCH_SIZE


def _make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=60.0,
        headers={
            "Authorization": f"Bearer {settings.gpt_key}",
            "Content-Type": "application/json",
        },
        limits=httpx.Limits(max_connections=_concurrency() * 2),
    )


async def _chat(client: httpx.AsyncClient, system: str, user_content: str, max_tokens: int = 1000) -> str:
    base = settings.gpt_base_url.rstrip("/")
    if base.endswith("/v1/chat/completions"):
        pass
    elif base.endswith("/v1"):
        base = base + "/chat/completions"
    else:
        base = base + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": settings.gpt_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content[:8000]},
        ],
        "max_tokens": max_tokens,
        "temperature": 0,
        "stream": False,
    }
    if settings.gpt_fast:
        body["reasoning_effort"] = "medium"
    r = await client.post(base, json=body)
    if not r.is_success:
        log.warning(
            "GPT _chat non-200: status=%s url=%s body[:500]=%r",
            r.status_code, base, r.text[:500],
        )
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"]


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    text = text.strip().strip("`")
    if text.startswith("json"):
        text = text[4:].strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        parsed = json.loads(text[start : end + 1])
        return parsed if isinstance(parsed, list) else []
    except (ValueError, json.JSONDecodeError):
        return []


def _extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip().strip("`")
    if text.startswith("json"):
        text = text[4:].strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        return {}
    try:
        parsed = json.loads(text[start : end + 1])
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, json.JSONDecodeError):
        return {}


def _hit_to_blob(hit: dict[str, Any]) -> str:
    header = hit.get("header", "") or ""
    banner = hit.get("banner", "") or ""
    cert = hit.get("cert", "") or ""
    title = hit.get("title", "") or ""
    return (
        f"host: {hit.get('host', '')}\n"
        f"title: {title}\n"
        f"header:\n{header[:800]}\n"
        f"banner:\n{banner[:400]}\n"
        f"cert:\n{cert[:200]}"
    )


def _blob_to_credential(item: dict[str, Any], fallback_host: str) -> Credential | None:
    apikey = item.get("apikey", "").strip()
    apiurl = item.get("apiurl", "").strip()
    if not apikey or len(apikey) < 15:
        return None
    low = apikey.lower()
    if low.startswith(("access-control", "content-", "application/", "accept-", "cache-")):
        return None
    host = item.get("host", "") or fallback_host
    return Credential(
        apikey=apikey,
        apiurl=apiurl,
        source=f"gpt:{item.get('type', 'generic')}",
        source_type="header",
        host=host,
        raw_context="",
    )


async def _extract_batch(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    batch: list[dict[str, Any]],
    batch_idx: int,
    total_batches: int,
) -> list[Credential]:
    payload_parts = []
    for i, hit in enumerate(batch):
        blob = _hit_to_blob(hit)
        if len(blob) < 30:
            continue
        payload_parts.append(f"--- ENTRY {i} ---\n{blob}")
    if not payload_parts:
        return []
    payload = "\n\n".join(payload_parts)
    async with sem:
        try:
            resp = await _chat(client, EXTRACT_SYSTEM, payload, max_tokens=2000)
        except httpx.TimeoutException as e:
            log.warning(
                "GPT extract batch %d/%d TIMEOUT (%s): url=%s payload_len=%d",
                batch_idx, total_batches, type(e).__name__, settings.gpt_base_url, len(payload),
            )
            return []
        except httpx.HTTPStatusError as e:
            log.warning(
                "GPT extract batch %d/%d HTTP %s: body[:300]=%r",
                batch_idx, total_batches, e.response.status_code, e.response.text[:300],
            )
            return []
        except httpx.HTTPError as e:
            log.warning(
                "GPT extract batch %d/%d failed (%s): %s",
                batch_idx, total_batches, type(e).__name__, e,
            )
            return []
        except (KeyError, ValueError) as e:
            log.warning(
                "GPT extract batch %d/%d malformed response (%s): %s",
                batch_idx, total_batches, type(e).__name__, e,
            )
            return []
    creds: list[Credential] = []
    for item in _extract_json_array(resp):
        cred = _blob_to_credential(item, batch[0].get("host", ""))
        if cred:
            creds.append(cred)
    log.info("GPT extract batch %d/%d: +%d creds", batch_idx, total_batches, len(creds))
    return creds


async def extract_with_gpt(raw_hits: list[dict[str, Any]]) -> list[Credential]:
    if not settings.gpt_key or not settings.gpt_base_url:
        return []
    hits = [h for h in raw_hits if (h.get("header") or h.get("banner") or h.get("cert"))]
    if not hits:
        return []

    batches = [hits[i : i + _batch_size()] for i in range(0, len(hits), _batch_size())]
    total = len(batches)
    log.info("GPT extract: %d hits → %d batches (batch_size=%d, concurrency=%d)",
             len(hits), total, _batch_size(), _concurrency())

    sem = asyncio.Semaphore(_concurrency())
    seen: set[tuple[str, str]] = set()
    all_creds: list[Credential] = []

    async with _make_client() as client:
        tasks = [_extract_batch(client, sem, b, idx + 1, total) for idx, b in enumerate(batches)]
        results = await asyncio.gather(*tasks)

    for batch_creds in results:
        for cred in batch_creds:
            key = (cred.apikey, cred.apiurl)
            if key not in seen:
                seen.add(key)
                all_creds.append(cred)

    log.info("GPT extracted %d additional credentials", len(all_creds))
    return all_creds


async def _recheck_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    result: ValidationResult,
) -> ValidationResult:
    if not result.valid:
        return result
    host = result.credential.apiurl
    snippet = (result.response_snippet or "")[:300]
    payload = (
        f"URL: {host}\nStatus: {result.status_code}\n"
        f"Rate headers: {json.dumps(result.rate_limit_headers)}\n"
        f"Response body (first 300 chars): {snippet}"
    )
    async with sem:
        try:
            resp = await _chat(client, RECHECK_SYSTEM, payload, max_tokens=200)
        except httpx.TimeoutException as e:
            log.warning("GPT recheck TIMEOUT for %s (%s)", host, type(e).__name__)
            return result
        except httpx.HTTPStatusError as e:
            log.warning("GPT recheck HTTP %s for %s: body[:300]=%r", e.response.status_code, host, e.response.text[:300])
            return result
        except httpx.HTTPError as e:
            log.warning("GPT recheck failed for %s (%s): %s", host, type(e).__name__, e)
            return result
        except (KeyError, ValueError) as e:
            log.warning("GPT recheck malformed response for %s (%s): %s", host, type(e).__name__, e)
            return result
    verdict = _extract_json_object(resp)
    if not verdict:
        return result
    if verdict.get("valid") is False:
        result.valid = False
        result.error = f"gpt-rejected: {verdict.get('reason', 'unknown')}"
    gateway = verdict.get("gateway", "")
    if gateway and gateway != "unknown":
        result.gateway = gateway
    return result


async def recheck_all_with_gpt(results: list[ValidationResult]) -> list[ValidationResult]:
    if not settings.gpt_key or not settings.gpt_base_url:
        return results
    valid_count = sum(1 for r in results if r.valid)
    if valid_count == 0:
        return results
    log.info("GPT re-checking %d valid results (concurrency=%d)...", valid_count, _concurrency())
    sem = asyncio.Semaphore(_concurrency())
    async with _make_client() as client:
        return await asyncio.gather(*[_recheck_one(client, sem, r) for r in results])


async def recheck_with_gpt(result: ValidationResult) -> ValidationResult:
    results = await recheck_all_with_gpt([result])
    return results[0] if results else result
