from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from .config import settings
from .models import Credential, ValidationResult

log = logging.getLogger(__name__)

EXTRACT_SYSTEM = (
    "You are a security credential extraction tool. Extract leaked API keys and their "
    "corresponding API URLs/base URLs from the given text. Return ONLY a JSON array, "
    'no explanation. Each element: {"host": "...", "apikey": "...", "apiurl": "...", "type": "openai|anthropic|google|deepseek|kimi|glm|qwen|siliconflow|generic"}. '
    "The apikey may be an OpenAI key (sk-proj-.../sk-...), Anthropic key (sk-ant-...), "
    "Google key (AIza...), DeepSeek key, Moonshot/Kimi key, GLM/Zhipu key, or a generic bearer token. "
    "Skip HTTP header field names, MIME types, and non-key strings. "
    "An apiurl must be a real http(s) URL; if no explicit URL is present in the text, "
    'set "apiurl" to "" — the host field will be used to derive it. '
    "Minimum key length is 12 characters. If no credentials found, return []."
)

RECHECK_SYSTEM = (
    "You are a security validation tool. Given a chat completion API probe's HTTP status code and response body, "
    "determine if the API key is genuinely valid for LLM inference. Return JSON: "
    '{"valid": true/false, "reason": "...", "gateway": "litellm|oneapi|openai|unknown"}. '
    "valid=true ONLY if the response is a real chat completion JSON or a rate-limit error from an LLM gateway. "
    "valid=false if it's HTML, a welcome page, a WAF block, or an unrelated service."
)

GPT_CONCURRENCY = 3
EXTRACT_BATCH_SIZE = 10

# HTTP status codes that indicate transient overload → retry with backoff.
RETRY_STATUS = {429, 500, 502, 503, 529}
MAX_RETRIES = 3


def _concurrency() -> int:
    return 5 if settings.gpt_fast else GPT_CONCURRENCY


def _batch_size() -> int:
    return 10 if settings.gpt_fast else EXTRACT_BATCH_SIZE


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
            {"role": "user", "content": user_content[:16000]},
        ],
        "max_tokens": max_tokens,
        "temperature": 0,
        "stream": False,
    }
    if settings.gpt_fast:
        body["reasoning_effort"] = "medium"

    last_status = 0
    last_body = ""
    for attempt in range(MAX_RETRIES + 1):
        r = await client.post(base, json=body)
        if r.is_success:
            data = r.json()
            return data["choices"][0]["message"]["content"]
        last_status = r.status_code
        last_body = r.text[:500]
        if r.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
            wait = 2 ** attempt  # 1s, 2s, 4s
            log.warning(
                "GPT _chat transient %d (attempt %d/%d), retrying in %ds",
                r.status_code, attempt + 1, MAX_RETRIES, wait,
            )
            await asyncio.sleep(wait)
            continue
        break

    log.warning(
        "GPT _chat non-200: status=%s url=%s body[:500]=%r",
        last_status, base, last_body,
    )
    raise httpx.HTTPStatusError(
        f"HTTP {last_status}", request=httpx.Request("POST", base), response=httpx.Response(last_status),
    )


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


KEY_CONTEXT_PATTERNS = re.compile(
    r"(?:sk-proj|sk-ant|sk-[A-Za-z0-9]|AIza|api[_-]?key|apikey|bearer|authorization|OPENAI_API_KEY|ANTHROPIC_API_KEY|x-api-key)",
    re.I,
)


def _extract_key_contexts(text: str, window: int = 300, max_snippets: int = 5) -> str:
    if not text:
        return ""
    if len(text) <= 800:
        return text
    snippets: list[str] = []
    for m in KEY_CONTEXT_PATTERNS.finditer(text):
        start = max(0, m.start() - window)
        end = min(len(text), m.end() + window)
        snippets.append(text[start:end])
        if len(snippets) >= max_snippets:
            break
    return "\n...\n".join(snippets) if snippets else text[:800]


def _hit_to_blob(hit: dict[str, Any]) -> str:
    header = hit.get("header", "") or ""
    banner = hit.get("banner", "") or ""
    cert = hit.get("cert", "") or ""
    title = hit.get("title", "") or ""
    body = hit.get("body", "") or ""
    banner_ctx = _extract_key_contexts(banner)
    body_ctx = _extract_key_contexts(body)
    return (
        f"host: {hit.get('host', '')}\n"
        f"title: {title}\n"
        f"header:\n{header[:800]}\n"
        f"banner:\n{banner_ctx}\n"
        f"body:\n{body_ctx}\n"
        f"cert:\n{cert[:300]}"
    )


def _blob_to_credential(item: dict[str, Any], fallback_host: str) -> Credential | None:
    apikey = item.get("apikey", "").strip()
    apiurl = item.get("apiurl", "").strip()
    if not apikey or len(apikey) < 12:
        return None
    low = apikey.lower()
    if low.startswith(("access-control", "content-", "application/", "accept-", "cache-")):
        return None
    host = item.get("host", "") or fallback_host
    derived_url = apiurl
    if not derived_url and host:
        derived_url = host.rstrip("/") if host.startswith("http") else "https://" + host.rstrip("/")
    return Credential(
        apikey=apikey,
        apiurl=derived_url,
        source=f"gpt:{item.get('type', 'generic')}",
        source_type="header",
        host=host,
        raw_context="",
    )


def _dump_failed_batch(batch: list[dict[str, Any]], batch_idx: int) -> None:
    try:
        out_dir = settings.results_path
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"gpt_failed_batch_{ts}_{batch_idx}.json"
        path.write_text(
            json.dumps({"batch_idx": batch_idx, "hits": batch}, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        log.info("Failed batch %d dumped to %s for later re-run", batch_idx, path)
    except OSError as e:
        log.warning("Could not dump failed batch %d: %s", batch_idx, e)


def _dump_debug_payload(batch_idx: int, payload: str, batch: list[dict[str, Any]]) -> None:
    try:
        debug_dir = settings.results_path / "gpt_debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        path = debug_dir / f"batch_{batch_idx:04d}.txt"
        meta = (
            f"# batch_idx: {batch_idx}\n"
            f"# hits: {len(batch)}\n"
            f"# payload_chars: {len(payload)}\n"
            f"# hosts: {', '.join(h.get('host', '')[:40] for h in batch[:5])}\n"
            f"# ========================================\n\n"
        )
        path.write_text(meta + payload, encoding="utf-8")
    except OSError:
        pass


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
    _dump_debug_payload(batch_idx, payload, batch)
    async with sem:
        try:
            resp = await _chat(client, EXTRACT_SYSTEM, payload, max_tokens=8000)
        except httpx.TimeoutException as e:
            log.warning(
                "GPT extract batch %d/%d TIMEOUT (%s): url=%s payload_len=%d",
                batch_idx, total_batches, type(e).__name__, settings.gpt_base_url, len(payload),
            )
            _dump_failed_batch(batch, batch_idx)
            return []
        except httpx.HTTPStatusError as e:
            log.warning(
                "GPT extract batch %d/%d HTTP %s after retries: body[:300]=%r",
                batch_idx, total_batches, e.response.status_code, e.response.text[:300],
            )
            _dump_failed_batch(batch, batch_idx)
            return []
        except httpx.HTTPError as e:
            log.warning(
                "GPT extract batch %d/%d failed (%s): %s",
                batch_idx, total_batches, type(e).__name__, e,
            )
            _dump_failed_batch(batch, batch_idx)
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
    hits = [h for h in raw_hits if (h.get("header") or h.get("banner") or h.get("cert") or h.get("body"))]
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
