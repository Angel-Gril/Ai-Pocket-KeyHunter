from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult

log = logging.getLogger(__name__)

# Set by scanner.run_scan() at the start of a run so GPT debug/failed-batch dumps
# land inside the run folder. None → fall back to results/ root (scripts, tests).
_CURRENT_RUN_DIR: Path | None = None


@dataclass(frozen=True, slots=True)
class GPTBatchReport:
    credentials: tuple[Credential, ...]
    successful_entry_ids: frozenset[str]
    failed_entry_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class GPTExtractionReport:
    credentials: tuple[Credential, ...]
    successful_entry_ids: frozenset[str]
    failed_entry_ids: frozenset[str]


_EMPTY_EXTRACTION_REPORT = GPTExtractionReport((), frozenset(), frozenset())


def set_run_dir(run_dir: Path | None) -> None:
    """Stamp the active run dir so _dump_* helpers write into it."""
    global _CURRENT_RUN_DIR
    _CURRENT_RUN_DIR = run_dir


EXTRACT_SYSTEM = (
    "You are a security credential extraction tool. Extract leaked API keys and their "
    "corresponding API URLs/base URLs from the given text. Return ONLY a JSON array, "
    'no explanation. Each element: {"entry_id": "...", "apikey": "...", "apiurl": "...", "type": "openai|anthropic|google|deepseek|kimi|glm|qwen|siliconflow|generic"}. '
    "Copy entry_id exactly from the ENTRY marker containing the credential. "
    "The apikey may be an OpenAI key (sk-proj.../sk-...), Anthropic key (sk-ant...), "
    "Google key (AIza...), DeepSeek key, Moonshot/Kimi key, GLM/Zhipu key, or a generic bearer token. "
    "Skip HTTP header field names, MIME types, and non-key strings. "
    "An apiurl must be a real http(s) URL; if no explicit URL is present in the text, "
    'set "apiurl" to "" — the host field will be used to derive it. '
    "Minimum key length is 12 characters. If no credentials found, return []."
)

RECHECK_SYSTEM = (
    "You are a security validation tool. Given one or more chat completion API probe results, "
    "determine if each API key is genuinely valid for LLM inference. "
    "Return a JSON ARRAY with one object per entry in the same order: "
    '[{"idx": 0, "valid": true/false, "reason": "...", "gateway": "litellm|oneapi|openai|unknown"}, ...]. '
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


def _make_client(max_connections: int | None = None) -> httpx.AsyncClient:
    pool_size = max_connections or _concurrency() * 2
    return httpx.AsyncClient(
        timeout=60.0,
        headers={
            "Authorization": f"Bearer {settings.gpt_key}",
            "Content-Type": "application/json",
        },
        limits=httpx.Limits(max_connections=pool_size),
    )


async def _chat(
    client: httpx.AsyncClient, system: str, user_content: str, max_tokens: int = 1000
) -> str:
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
            {"role": "user", "content": user_content},
        ],
        "max_tokens": max_tokens,
        "temperature": 0,
        "stream": False,
    }
    if settings.gpt_fast:
        body["reasoning_effort"] = "low"

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
            wait = 2**attempt  # 1s, 2s, 4s
            log.warning(
                "GPT _chat transient %d (attempt %d/%d), retrying in %ds",
                r.status_code,
                attempt + 1,
                MAX_RETRIES,
                wait,
            )
            await asyncio.sleep(wait)
            continue
        break

    log.warning(
        "GPT _chat non-200: status=%s url=%s body[:500]=%r",
        last_status,
        base,
        last_body,
    )
    raise httpx.HTTPStatusError(
        f"HTTP {last_status}",
        request=httpx.Request("POST", base),
        response=httpx.Response(last_status),
    )


def _parse_json_array(text: str) -> list[dict[str, Any]] | None:
    text = text.strip().strip("`")
    if text.startswith("json"):
        text = text[4:].strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        return None
    return parsed


def _extract_json_array(text: str) -> list[dict[str, Any]]:
    return _parse_json_array(text) or []


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
        f"header:\n{header[:4000]}\n"
        f"banner:\n{banner_ctx}\n"
        f"body:\n{body_ctx}\n"
        f"cert:\n{cert[:2000]}"
    )


def _blob_to_credential(
    item: dict[str, Any], targets_by_id: dict[str, dict[str, Any]]
) -> Credential | None:
    target = targets_by_id.get(str(item.get("entry_id", "")))
    if target is None:
        return None
    apikey = item.get("apikey", "").strip()
    apiurl = item.get("apiurl", "").strip()
    if not apikey or len(apikey) < 12:
        return None
    low = apikey.lower()
    if low.startswith(("access-control", "content-", "application/", "accept-", "cache-")):
        return None
    host = str(target.get("host", ""))
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
    _UNSAFE_LINE_TERMINATORS = re.compile("[\u2028\u2029]")
    try:
        out_dir = _CURRENT_RUN_DIR or settings.results_path
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"gpt_failed_batch_{ts}_{batch_idx}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            meta = json.dumps(
                {"batch_idx": batch_idx, "total_hits": len(batch), "dumped_at": ts},
                ensure_ascii=False,
                default=str,
            )
            f.write(_UNSAFE_LINE_TERMINATORS.sub(" ", meta) + "\n")
            for hit in batch:
                line = json.dumps(hit, ensure_ascii=False, default=str)
                f.write(_UNSAFE_LINE_TERMINATORS.sub(" ", line) + "\n")
        log.info("Failed batch %d dumped to %s for later re-run", batch_idx, path)
    except OSError as e:
        log.warning("Could not dump failed batch %d: %s", batch_idx, e)


def _dump_debug_payload(batch_idx: int, payload: str, batch: list[dict[str, Any]]) -> None:
    try:
        debug_dir = (_CURRENT_RUN_DIR or settings.results_path) / "gpt_debug"
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
) -> GPTBatchReport:
    entry_ids = frozenset(str(hit.get("_entry_id", "")) for hit in batch if hit.get("_entry_id"))
    payload_parts = []
    for hit in batch:
        blob = _hit_to_blob(hit)
        if len(blob) < 30:
            continue
        payload_parts.append(f"--- ENTRY {hit.get('_entry_id', '')} ---\n{blob}")
    if not payload_parts:
        return GPTBatchReport((), entry_ids, frozenset())
    payload = "\n\n".join(payload_parts)
    if settings.gpt_debug:
        _dump_debug_payload(batch_idx, payload, batch)
    async with sem:
        try:
            resp = await _chat(client, EXTRACT_SYSTEM, payload, max_tokens=8000)
        except httpx.TimeoutException as e:
            log.warning(
                "GPT extract batch %d/%d TIMEOUT (%s): url=%s payload_len=%d",
                batch_idx,
                total_batches,
                type(e).__name__,
                settings.gpt_base_url,
                len(payload),
            )
            _dump_failed_batch(batch, batch_idx)
            return GPTBatchReport((), frozenset(), entry_ids)
        except httpx.HTTPStatusError as e:
            log.warning(
                "GPT extract batch %d/%d HTTP %s after retries: body[:300]=%r",
                batch_idx,
                total_batches,
                e.response.status_code,
                e.response.text[:300],
            )
            _dump_failed_batch(batch, batch_idx)
            return GPTBatchReport((), frozenset(), entry_ids)
        except httpx.HTTPError as e:
            log.warning(
                "GPT extract batch %d/%d failed (%s): %s",
                batch_idx,
                total_batches,
                type(e).__name__,
                e,
            )
            _dump_failed_batch(batch, batch_idx)
            return GPTBatchReport((), frozenset(), entry_ids)
        except (KeyError, ValueError) as e:
            log.warning(
                "GPT extract batch %d/%d malformed response (%s): %s",
                batch_idx,
                total_batches,
                type(e).__name__,
                e,
            )
            _dump_failed_batch(batch, batch_idx)
            return GPTBatchReport((), frozenset(), entry_ids)

    items = _parse_json_array(resp)
    if items is None:
        log.warning("GPT extract batch %d/%d returned malformed JSON", batch_idx, total_batches)
        _dump_failed_batch(batch, batch_idx)
        return GPTBatchReport((), frozenset(), entry_ids)

    targets_by_id = {str(hit["_entry_id"]): hit for hit in batch if hit.get("_entry_id")}
    creds: list[Credential] = []
    for item in items:
        cred = _blob_to_credential(item, targets_by_id)
        if cred:
            creds.append(cred)
    log.info("GPT extract batch %d/%d: +%d creds", batch_idx, total_batches, len(creds))
    return GPTBatchReport(tuple(creds), entry_ids, frozenset())


async def extract_with_gpt(raw_hits: list[dict[str, Any]]) -> GPTExtractionReport:
    if not settings.gpt_key or not settings.gpt_base_url:
        return _EMPTY_EXTRACTION_REPORT
    hits = [
        h
        for h in raw_hits
        if (h.get("header") or h.get("banner") or h.get("cert") or h.get("body"))
    ]
    if not hits:
        return _EMPTY_EXTRACTION_REPORT

    batches = [hits[i : i + _batch_size()] for i in range(0, len(hits), _batch_size())]
    total = len(batches)
    log.info(
        "GPT extract: %d hits → %d batches (batch_size=%d, concurrency=%d)",
        len(hits),
        total,
        _batch_size(),
        _concurrency(),
    )

    sem = asyncio.Semaphore(_concurrency())
    seen: set[tuple[str, str]] = set()
    all_creds: list[Credential] = []
    successful: set[str] = set()
    failed: set[str] = set()

    async with _make_client() as client:
        tasks = [
            _extract_batch(client, sem, batch, idx + 1, total) for idx, batch in enumerate(batches)
        ]
        reports = await asyncio.gather(*tasks)

    for report in reports:
        successful.update(report.successful_entry_ids)
        failed.update(report.failed_entry_ids)
        for cred in report.credentials:
            key = (cred.apikey, cred.apiurl)
            if key not in seen:
                seen.add(key)
                all_creds.append(cred)

    log.info("GPT extracted %d additional credentials", len(all_creds))
    return GPTExtractionReport(
        credentials=tuple(all_creds),
        successful_entry_ids=frozenset(successful),
        failed_entry_ids=frozenset(failed),
    )


def _recheck_concurrency() -> int:
    """Re-check uses its own (higher) concurrency to move faster."""
    return settings.gpt_recheck_concurrency


def _recheck_batch_size() -> int:
    return settings.gpt_recheck_batch_size


def _format_recheck_entry(idx: int, result: ValidationResult) -> str:
    host = result.credential.apiurl
    snippet = (result.response_snippet or "")[:300]
    return (
        f"--- ENTRY {idx} ---\n"
        f"URL: {host}\nStatus: {result.status_code}\n"
        f"Rate headers: {json.dumps(result.rate_limit_headers)}\n"
        f"Response body (first 300 chars): {snippet}"
    )


async def _recheck_batch(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    batch: list[ValidationResult],
    batch_idx: int,
    total_batches: int,
) -> tuple[list[ValidationResult], bool]:
    """Re-check a batch of valid results in one GPT call.

    Returns (batch, success) where success=False means the GPT call failed
    entirely and the batch was NOT evaluated.
    """
    payload_parts = []
    for i, r in enumerate(batch):
        payload_parts.append(_format_recheck_entry(i, r))
    payload = "\n\n".join(payload_parts)

    async with sem:
        try:
            resp = await _chat(client, RECHECK_SYSTEM, payload, max_tokens=200 + 80 * len(batch))
        except httpx.TimeoutException as e:
            log.warning(
                "GPT recheck batch %d/%d TIMEOUT (%s)", batch_idx, total_batches, type(e).__name__
            )
            return batch, False
        except httpx.HTTPStatusError as e:
            log.warning(
                "GPT recheck batch %d/%d HTTP %s: body[:300]=%r",
                batch_idx,
                total_batches,
                e.response.status_code,
                e.response.text[:300],
            )
            return batch, False
        except httpx.HTTPError as e:
            log.warning(
                "GPT recheck batch %d/%d failed (%s): %s",
                batch_idx,
                total_batches,
                type(e).__name__,
                e,
            )
            return batch, False
        except (KeyError, ValueError) as e:
            log.warning(
                "GPT recheck batch %d/%d malformed (%s): %s",
                batch_idx,
                total_batches,
                type(e).__name__,
                e,
            )
            return batch, False

    verdicts = _extract_json_array(resp)
    # Build index map from GPT response
    verdict_map: dict[int, dict[str, Any]] = {}
    for v in verdicts:
        idx = v.get("idx")
        if idx is not None:
            verdict_map[int(idx)] = v

    # Apply verdicts
    rejected = 0
    for i, result in enumerate(batch):
        verdict = verdict_map.get(i)
        if not verdict:
            continue
        if verdict.get("valid") is False:
            result.valid = False
            result.error = f"gpt-rejected: {verdict.get('reason', 'unknown')}"
            rejected += 1
        gateway = verdict.get("gateway", "")
        if gateway and gateway != "unknown":
            result.gateway = gateway

    if rejected:
        log.info(
            "GPT recheck batch %d/%d: rejected %d/%d",
            batch_idx,
            total_batches,
            rejected,
            len(batch),
        )
    return batch, True


async def _run_recheck_wave(
    client: httpx.AsyncClient,
    batches: list[list[ValidationResult]],
    concurrency: int,
    label: str,
) -> list[list[ValidationResult]]:
    """Run a wave of recheck batches; return list of FAILED batches."""
    total = len(batches)
    sem = asyncio.Semaphore(concurrency)
    tasks = [_recheck_batch(client, sem, b, idx + 1, total) for idx, b in enumerate(batches)]
    results = await asyncio.gather(*tasks)
    failed = []
    for batch, success in results:
        if not success:
            failed.append(batch)
    if failed:
        log.warning(
            "GPT recheck %s: %d/%d batches failed, will retry",
            label,
            len(failed),
            total,
        )
    return failed


async def recheck_all_with_gpt(results: list[ValidationResult]) -> list[ValidationResult]:
    if not settings.gpt_key or not settings.gpt_base_url:
        return results
    valid_results = [r for r in results if r.valid]
    if not valid_results:
        return results

    concurrency = _recheck_concurrency()
    batch_size = _recheck_batch_size()
    batches = [valid_results[i : i + batch_size] for i in range(0, len(valid_results), batch_size)]
    total = len(batches)

    log.info(
        "GPT re-checking %d valid results (%d batches, batch_size=%d, concurrency=%d)...",
        len(valid_results),
        total,
        batch_size,
        concurrency,
    )

    # Cooldown between GPT extract and re-check to reduce 529 rate-limit storms
    if settings.gpt_recheck_cooldown > 0:
        log.info(
            "Cooling down %.1fs before GPT re-check to avoid rate-limit...",
            settings.gpt_recheck_cooldown,
        )
        await asyncio.sleep(settings.gpt_recheck_cooldown)

    # Wave 1: process all batches with configured concurrency
    async with _make_client(max_connections=concurrency * 2) as client:
        failed = await _run_recheck_wave(client, batches, concurrency, "wave-1")

    # Wave 2: retry failed batches with reduced concurrency + delay
    if failed:
        retry_concurrency = max(1, concurrency // 3)
        retry_delay = 8.0
        log.info(
            "Retrying %d failed batches after %.0fs delay (concurrency=%d)...",
            len(failed),
            retry_delay,
            retry_concurrency,
        )
        await asyncio.sleep(retry_delay)
        async with _make_client(max_connections=retry_concurrency * 2) as client:
            still_failed = await _run_recheck_wave(client, failed, retry_concurrency, "wave-2")

        # Wave 3: split remaining failed batches into single items for last resort
        if still_failed:
            singles = [item for batch in still_failed for item in batch if item.valid]
            if singles:
                single_batches = [[r] for r in singles]
                single_concurrency = max(1, retry_concurrency // 2)
                log.info(
                    "Final retry: %d items individually (concurrency=%d) after 10s...",
                    len(single_batches),
                    single_concurrency,
                )
                await asyncio.sleep(10.0)
                async with _make_client(max_connections=single_concurrency * 2) as client:
                    final_failed = await _run_recheck_wave(
                        client, single_batches, single_concurrency, "wave-3-singles"
                    )
                if final_failed:
                    log.warning(
                        "GPT recheck: %d items could not be rechecked after 3 waves (kept as-is)",
                        len(final_failed),
                    )

    return results


async def recheck_with_gpt(result: ValidationResult) -> ValidationResult:
    results = await recheck_all_with_gpt([result])
    return results[0] if results else result
