from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential, ProviderInfo, ValidationResult
from aipocket.core.request_ledger import RequestAttribution
from aipocket.core.validation_state import apply_state
from aipocket.services.credential_policy import normalize_credential_endpoint
from aipocket.services.http_transport import is_http_header_value_safe
from aipocket.services.providers import (
    provider_registry,
    resolve_provider,
    uses_anthropic_adapter,
)
from aipocket.services.providers.additional import validate_additional_provider
from aipocket.services.providers.anthropic import validate_anthropic
from aipocket.services.providers.azure_openai import (
    AzureInferencePolicy,
    validate_azure_openai,
)
from aipocket.services.providers.endpoints import build_operation_url, canonicalize_endpoint
from aipocket.services.providers.gemini import validate_gemini
from aipocket.services.providers.issuer import decide_issuer
from aipocket.services.providers.openai import InferencePolicy, validate_openai
from aipocket.services.providers.vertex import validate_vertex

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


# High-value models — core canary targets. When any appear in /v1/models we
# probe them first (honeypot resistance: faking gpt-5.x is harder than gpt-3.5).
# Split by region so domestic aggregators prefer domestic models and vice versa.
# Membership set = international ∪ domestic; probe order is region-aware via
# high_value_probe_order().
HIGH_VALUE_INTERNATIONAL = [
    # OpenAI frontier (gpt-5.6-sol is flagship; gpt-5.6 is its official alias)
    "gpt-5.6-sol",
    "gpt-5.6",
    "gpt-5.5-pro",
    "gpt-5.5",
    "gpt-5.4-pro",
    "gpt-5.4",
    # Anthropic (claude-fable-5 is the widely-released flagship)
    "claude-fable-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-6",
    # OpenRouter / proxy vendor prefixes
    "openai/gpt-5.6-sol",
    "openai/gpt-5.6",
    "openai/gpt-5.5",
    "anthropic/claude-fable-5",
    "anthropic/claude-sonnet-5",
    "anthropic/claude-sonnet-4",
    "anthropic/claude-opus-4",
    "anthropic/claude-opus-4.1",
    "anthropic/claude-sonnet-4.5",
    # Legacy proxy aliases
    "claude-3-7-sonnet-latest",
    "claude-3-5-sonnet-latest",
    # Google Gemini
    "gemini-3.5-flash",
    "gemini-3.1-pro-preview",
    "gemini-pro-latest",
    # Western open-weight hosts (Together / Fireworks / Replicate style)
    "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "meta/meta-llama-3.1-405b-instruct",
    "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "llama-3.3-70b-versatile",
]

HIGH_VALUE_DOMESTIC = [
    # DeepSeek (official + OpenRouter + SiliconFlow)
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-chat",
    "deepseek-ai/DeepSeek-V4-Pro",
    "deepseek-ai/DeepSeek-V4-Flash",
    "deepseek-ai/DeepSeek-V3",
    # Kimi / Moonshot
    "kimi-k3",
    "kimi-k2.7-code",
    "kimi-k2.7-code-highspeed",
    "kimi-k2.6",
    "kimi-k2.5",
    "moonshotai/kimi-k3",
    # Zhipu / GLM
    "glm-5.2",
    "glm-5.1",
    "glm-5v-turbo",
    "glm-5-turbo",
    "glm-5",
    "z-ai/glm-4.5",
    "zai-org/GLM-4.5",
    # Qwen / DashScope
    "qwen3.7-max",
    "qwen3.6-max-preview",
    "qwen3-max",
    "qwen3-coder-next",
    "qwen3-coder-plus",
    "qwen3.7-plus",
    "qwen3.6-plus",
    "qwen3.5-plus",
    "qwen/qwen3-max",
    "Qwen/Qwen3-Max",
    "Qwen/Qwen3.5-397B-A17B",
]

# Default flat list (international first) — used for membership checks.
HIGH_VALUE_MODELS = HIGH_VALUE_INTERNATIONAL + HIGH_VALUE_DOMESTIC


def high_value_probe_order(provider: str = "") -> list[str]:
    """Region-aware high-value model order for probing.

    Domestic aggregators (SiliconFlow, official DeepSeek/Kimi/GLM/Qwen) probe
    domestic models first. International aggregators (OpenRouter, Together, …)
    probe OpenAI/Claude/Llama first. Unknown / generic gateway keeps the default
    international-first canary order.
    """
    from aipocket.services.providers.registry import (
        DOMESTIC_PROBE_PROVIDERS,
        INTERNATIONAL_PROBE_PROVIDERS,
    )

    if provider in DOMESTIC_PROBE_PROVIDERS:
        return HIGH_VALUE_DOMESTIC + HIGH_VALUE_INTERNATIONAL
    if provider in INTERNATIONAL_PROBE_PROVIDERS:
        return HIGH_VALUE_INTERNATIONAL + HIGH_VALUE_DOMESTIC
    return list(HIGH_VALUE_MODELS)


# "Generation" major version per model family — used to distinguish a plausible
# within-family downgrade (gpt-5.5 → gpt-5.4) from a honeypot cross-generation
# swap (gpt-5.5 → gpt-4o-mini / gpt-3.5-turbo). Maps a model family prefix to
# the generation number embedded in its ID.
def _model_family_and_gen(model: str) -> tuple[str, str]:
    """Return (family, generation) for a model id.

    Examples:
        'gpt-5.5'           → ('gpt', '5')
        'gpt-4o-mini'       → ('gpt', '4')
        'claude-sonnet-4-6' → ('claude', '4')
        'deepseek-v4-flash' → ('deepseek', '4')
        'glm-5.1'           → ('glm', '5')

    Generation is the FIRST integer anywhere in the id (the major version).
    """
    import re

    m = model.lower()
    families = (
        "deepseek",
        "claude",
        "gemini",
        "glm",
        "qwen",
        "kimi",
        "gpt",
    )
    family = next((f for f in families if m.startswith(f)), m.split("-")[0])
    # First integer run in the id = generation (5.5→5, 4o→4, 3.5→3, v4→4).
    num_match = re.search(r"\d+", m)
    gen = num_match.group() if num_match else ""
    return (family, gen)


def _is_severe_model_mismatch(requested: str, actual: str) -> bool:
    """True if requested→actual is a cross-family or cross-generation swap.

    A real proxy downgrades within a family AND within one generation tier to
    save cost (gpt-5.5 → gpt-5.4). It does NOT swap gpt-5.5 for gpt-4o-mini
    (two generations back) or for claude (different vendor). Those are honeypots.
    """
    fam_req, gen_req = _model_family_and_gen(requested)
    fam_act, gen_act = _model_family_and_gen(actual)
    # Different vendor entirely (gpt → claude, deepseek → gpt, …)
    if fam_req != fam_act:
        return True
    # Same family, different generation: gpt-5.x → gpt-4.x or gpt-3.x is severe.
    # gpt-5.5 → gpt-5.4 (same gen "5") is mild.
    return bool(gen_req and gen_act and gen_req != gen_act)


def _validation_client(client: httpx.AsyncClient, cred: Credential | None = None):
    from aipocket.core.observations import credential_identity
    from aipocket.services.http_transport import InstrumentedAsyncClient, LedgerContext

    if isinstance(client, InstrumentedAsyncClient):
        return client

    defaults = LedgerContext(stage="validation", source="validator")
    if cred is not None:
        identity = credential_identity(cred)
        defaults = LedgerContext(
            stage="validation",
            source="validator",
            credential_fingerprint=identity.secret_fingerprint,
            target_identity=identity.endpoint,
            product=cred.product,
        )
    return InstrumentedAsyncClient(client, defaults=defaults)


def _validate_concurrency() -> int:
    return max(1, int(settings.validate_concurrency))


def _validate_batch_size() -> int:
    return max(1, int(settings.validate_batch_size))


async def validate_all(
    credentials: list[Credential],
    *,
    attribution: dict[int, RequestAttribution] | None = None,
) -> list[ValidationResult]:
    """Validate credentials with a bounded worker pool (never N-task gather)."""
    if not credentials:
        return []

    concurrency = _validate_concurrency()
    timeout = httpx.Timeout(settings.validate_timeout)
    limits = httpx.Limits(max_connections=concurrency * 2)
    sem = asyncio.Semaphore(concurrency)
    total = len(credentials)
    worker_n = max(1, min(concurrency, total))
    progress_step = max(50, total // 10) or 1

    results: list[ValidationResult] = []
    queue: asyncio.Queue[Credential | None] = asyncio.Queue()
    for cred in credentials:
        queue.put_nowait(cred)
    for _ in range(worker_n):
        queue.put_nowait(None)

    progress_lock = asyncio.Lock()
    done_count = 0

    async def _worker(client: httpx.AsyncClient) -> None:
        nonlocal done_count
        from aipocket.core.request_ledger import current_query_attribution

        while True:
            credential = await queue.get()
            if credential is None:
                return
            token = current_query_attribution.set(
                (attribution or {}).get(id(credential), RequestAttribution())
            )
            try:
                result = await _probe_one(client, sem, credential)
            finally:
                current_query_attribution.reset(token)
            async with progress_lock:
                results.append(result)
                done_count += 1
                if done_count % progress_step == 0 or done_count == total:
                    log.info(
                        "Validate progress: %d / %d (workers=%d, concurrency=%d)",
                        done_count,
                        total,
                        worker_n,
                        concurrency,
                    )

    async with httpx.AsyncClient(
        timeout=timeout, limits=limits, follow_redirects=True
    ) as raw_client:
        client = _validation_client(raw_client)
        await asyncio.gather(*(_worker(client) for _ in range(worker_n)))

    return results


async def validate_from_store(
    run_id: str,
    *,
    stages: Sequence[str] | None = None,
    skip_identities: set[str] | None = None,
    attribution: dict[int, RequestAttribution] | None = None,
    valid_only_return: bool = False,
    resume: bool = True,
) -> list[ValidationResult]:
    """Page-load candidates from PG, validate with a worker pool, spill results.

    When ``valid_only_return`` is True, only valid results are retained in the
    returned list (invalids stay in ``scan_validation_results``). When
    ``resume`` is True, identities already present in the validation table are
    skipped (merged with ``skip_identities``).
    """
    from aipocket.services.candidate_store import (
        iter_candidate_pages,
        load_validated_identities,
        spill_enabled,
        upsert_validation_results,
    )

    if not spill_enabled() or not run_id:
        return []

    done = set(skip_identities or ())
    if resume:
        done |= await asyncio.to_thread(load_validated_identities, run_id)
    batch_size = _validate_batch_size()
    collected: list[ValidationResult] = []
    page_idx = 0
    total_validated = 0

    log.info(
        "validate_from_store: run=%s batch_size=%d skip=%d concurrency=%d",
        run_id,
        batch_size,
        len(done),
        _validate_concurrency(),
    )

    for page in iter_candidate_pages(
        run_id,
        stages=stages,
        prefilter_ok_only=True,
        batch_size=batch_size,
        skip_identities=done if done else None,
    ):
        page_idx += 1
        if not page:
            continue
        log.info(
            "validate_from_store page %d: %d credentials",
            page_idx,
            len(page),
        )
        page_results = await validate_all(page, attribution=attribution)
        await asyncio.to_thread(upsert_validation_results, run_id, page_results)
        total_validated += len(page_results)
        if valid_only_return:
            collected.extend(r for r in page_results if r.valid)
        else:
            collected.extend(page_results)
        # Free page working set before next load.
        del page, page_results

    log.info(
        "validate_from_store done: run=%s pages=%d validated=%d returned=%d",
        run_id,
        page_idx,
        total_validated,
        len(collected),
    )
    return collected


# A forged key that no real gateway would ever accept. Realistic-looking
# structure (sk- prefix, plausible length) so it isn't rejected by trivial
# format checks before reaching the auth layer.
_FORGED_KEY = "sk-aipocket-fake-probe-0000000000000000000000000000-deadbeef"

# Number of forged-key probes per host. Some honeypots are unstable — they
# return a canned chat completion on most requests but occasionally emit
# unrelated JSON (router admin APIs, etc.). A single probe can land on the
# "unrelated" response and miss the honeypot. Re-probing and treating ANY
# success as confirmation closes that gap at a 2x request cost per host.
_FORGED_PROBE_RETRIES = 2


async def _forged_key_probe(
    client: httpx.AsyncClient,
    api_url: str,
    model: str,
    *,
    provider: str = "",
    timeout: httpx.Timeout | None = None,
) -> str:
    """Send a FORGED key to ``api_url`` and return a verdict tag.

    Used both by :func:`verify_no_auth` (post-validation, per-host batch) and
    inline by :func:`_probe_chat_completions` / :func:`_probe_anthropic` when
    the REAL key returns 429 — to tell a genuine rate limit apart from a
    scam/open-proxy host that returns 429 to every key regardless of auth.

    Tags:
    * ``""``                         — clean (401/403 = real gateway rejected the forged key)
    * ``"noauth"``                   — forged key got a real completion (endpoint ignores auth)
    * ``"suspicious_429"``           — forged key also rate-limited (host rate-limits without auth)
    * ``"suspicious_noncompletion"`` — 200 non-completion after all retries (not a real gateway)
    * ``"error"``                    — network error / unable to compare (caller treats as inconclusive)

    ``provider="anthropic"`` switches the request to Anthropic's ``/v1/messages``
    convention (``x-api-key`` header); otherwise OpenAI's ``Authorization:
    Bearer`` + ``/v1/chat/completions`` is used. The forged probe tests HOST
    behavior (does it check auth?), so it must speak the host's own protocol.
    """
    if provider == "anthropic":
        endpoint = api_url.replace("/chat/completions", "/messages")
        headers = {
            "x-api-key": _FORGED_KEY,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
        }
    elif provider == "azure_openai":
        endpoint = api_url
        headers = {
            "api-key": "0" * 32,
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "input": "hello",
            "max_output_tokens": 1,
        }
    else:
        endpoint = api_url
        headers = {
            "Authorization": f"Bearer {_FORGED_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
            "stream": False,
        }

    for attempt in range(_FORGED_PROBE_RETRIES):
        try:
            request_client = _validation_client(client)
            r = await request_client.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=timeout,
                ledger_stage="noauth",
            )
        except httpx.HTTPError:
            return "error"
        if r.status_code == 429:
            # A real gateway returns 401 to a forged key — NEVER 429. A 429 to
            # a random forged key means the host rate-limits every request
            # regardless of auth: open proxy / resale gateway.
            return "suspicious_429"
        if r.status_code != 200:
            # 401/403 → real gateway rejected the forged key. Clean.
            return ""
        body = _parse_json_body(r)
        if body and _looks_like_chat_completion(body):
            # Forged key got a real completion → no-auth confirmed.
            return "noauth"
        # 200 but not a completion — ambiguous. Retry if budget left.
        if attempt == _FORGED_PROBE_RETRIES - 1:
            return "suspicious_noncompletion"
    return ""


def _forged_probe_provider(result: ValidationResult) -> str:
    """Map a validated result to the protocol tag :func:`_forged_key_probe` expects.

    The forged no-auth probe must speak the SAME protocol the real key proved out
    with, otherwise a strict non-OpenAI honeypot rejects the wrong-protocol probe
    and looks clean. Only Anthropic and Azure diverge from the OpenAI default;
    everything else (including google/gemini/vertex, which validate against their
    own official endpoints) uses the OpenAI-style probe ("").
    """
    provider = result.provider_info.provider if result.provider_info else ""
    if provider == "anthropic":
        return "anthropic"
    if provider == "azure_openai":
        return "azure_openai"
    # OpenAI-compatible gateways can carry an Anthropic-shaped key; the credential
    # bundle's protocol family (when present) still dictates the wire protocol.
    bundle = result.credential.bundle
    if bundle is not None and bundle.provider_hint == "anthropic":
        return "anthropic"
    return ""


async def verify_no_auth(
    results: list[ValidationResult],
    *,
    attribution: dict[int, RequestAttribution] | None = None,
) -> tuple[set[str], set[str]]:
    """Probe each host that has a valid result with a FORGED key.

    A legitimate gateway rejects every key but the ones issued to it — even if
    several real keys leaked onto one host. A no-auth endpoint (open proxy or
    honeypot) accepts any string. So if our forged key also produces a valid
    chat completion, the endpoint is not checking Authorization and every
    "valid" key found there is fake.

    Runs once per distinct host (not per key) to bound request volume.

    Returns ``(no_auth_hosts, suspicious_hosts)`` — sets of HOSTS matched
    against ``credential.host`` (stable, unlike apiurl normalization):

    * **no_auth_hosts** — forged key got a real chat completion. The endpoint
      ignores Authorization; every "valid" key on it is fake. Hard-rejected by
      :func:`honeypot._reject_no_auth_hosts`.
    * **suspicious_hosts** — forged key got a **429** (a real gateway returns
      401 to a forged key, never 429 — so 429 means the host rate-limits
      regardless of auth: open proxy / resale gateway), OR a 200 that is not a
      chat completion after all retries (host is not a real LLM gateway). These
      are NOT auto-rejected; the caller quarantines them to
      ``suspicious_*.jsonl`` for manual review.

    The probe targets ``credential.apiurl`` — which, after the routing-override
    persistence in :func:`_probe`, is the endpoint the key was ACTUALLY
    validated against (the official gateway for prefix-routed keys, the bare
    host otherwise). This ensures the forged probe hits the same place the real
    key proved out.
    """
    # Collect one representative (apiurl, probe_model) per host that validated.
    # We re-use the host's own validated model + api_url from its first valid
    # result — that endpoint/model already returned a completion, so a forged
    # key returning 200 there is unambiguous.
    # host -> (api_url, model, provider). The provider tag is threaded into the
    # forged probe so it speaks the HOST's own protocol (Anthropic x-api-key +
    # /messages, Azure api-key). Without it every forged probe would default to
    # OpenAI's Authorization: Bearer + /chat/completions and a no-auth honeypot
    # on a non-OpenAI protocol (e.g. a strict *.openai.azure.com endpoint) would
    # reject the wrong-protocol probe and escape detection.
    seen_hosts: dict[str, tuple[str, str, str, RequestAttribution]] = {}
    for r in results:
        if not r.valid:
            continue
        host = r.credential.host or r.credential.apiurl
        if host in seen_hosts:
            continue
        api_url = _normalize_apiurl(r.credential.apiurl)
        model = r.model_available or "gpt-4o-mini"
        provider = _forged_probe_provider(r)
        request_attribution = (attribution or {}).get(id(r.credential), RequestAttribution())
        if api_url:
            seen_hosts[host] = (api_url, model, provider, request_attribution)

    if not seen_hosts:
        return set(), set()

    sem = asyncio.Semaphore(settings.validate_concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)

    async def _probe_forged(
        host: str,
        api_url: str,
        model: str,
        provider: str,
        request_attribution: RequestAttribution,
    ) -> str:
        """Probe one host with a forged key; return a verdict tag."""
        from aipocket.core.request_ledger import current_query_attribution

        attribution_token = current_query_attribution.set(request_attribution)
        try:
            try:
                async with (
                    sem,
                    httpx.AsyncClient(timeout=timeout, follow_redirects=True) as raw_client,
                ):
                    client = _validation_client(raw_client)
                    verdict = await _forged_key_probe(
                        client, api_url, model, provider=provider, timeout=timeout
                    )
            except Exception as e:  # noqa: BLE001 — isolate per-host probe failures
                log.warning(
                    "verify_no_auth probe failed for %s (%s): %s: %s",
                    host,
                    api_url,
                    type(e).__name__,
                    e,
                )
                return "error"
            if verdict == "suspicious_429":
                log.warning(
                    "suspicious host (forged-key 429): %s (%s) — host "
                    "rate-limits without checking auth (open proxy?)",
                    host,
                    api_url,
                )
            elif verdict == "noauth":
                log.warning(
                    "no-auth host confirmed: forged key validated on "
                    "%s (%s) — voiding all keys on this host",
                    host,
                    api_url,
                )
            elif verdict == "suspicious_noncompletion":
                log.warning(
                    "suspicious host (200 non-completion): %s (%s) — "
                    "host is not a real LLM gateway",
                    host,
                    api_url,
                )
            return verdict
        finally:
            current_query_attribution.reset(attribution_token)

    tasks = [_probe_forged(h, u, m, p, a) for h, (u, m, p, a) in seen_hosts.items()]
    verdicts = await asyncio.gather(*tasks, return_exceptions=True)
    # Normalize any residual exceptions (should not happen after _probe_forged).
    clean: list[str] = []
    for host, v in zip(seen_hosts, verdicts, strict=True):
        if isinstance(v, BaseException):
            log.warning(
                "verify_no_auth gather error for %s (%s): %s",
                host,
                type(v).__name__,
                v,
            )
            clean.append("error")
        else:
            clean.append(v)
    verdicts = clean
    no_auth = {h for h, v in zip(seen_hosts, verdicts, strict=True) if v == "noauth"}
    suspicious = {
        h for h, v in zip(seen_hosts, verdicts, strict=True) if v.startswith("suspicious")
    }
    if no_auth:
        log.info(
            "verify_no_auth: %d/%d hosts accept a forged key (no-auth honeypots)",
            len(no_auth),
            len(seen_hosts),
        )
    if suspicious:
        log.info(
            "verify_no_auth: %d/%d hosts suspicious (forged-429 / non-completion) "
            "→ quarantined to suspicious_*.jsonl",
            len(suspicious),
            len(seen_hosts),
        )
    return no_auth, suspicious


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    cred: Credential,
) -> ValidationResult:
    try:
        async with sem:
            result = await _probe(_validation_client(client, cred), cred)
    except (UnicodeEncodeError, httpx.LocalProtocolError) as exc:
        # Defense in depth: illegal Authorization/header field-values.
        # Permanent rejection — not transient; retrying will never succeed.
        fingerprint = hashlib.sha256(cred.apikey.encode()).hexdigest()[:12]
        log.warning(
            "validation rejected unsafe header for credential fingerprint=%s (%s): %s",
            fingerprint,
            type(exc).__name__,
            exc,
        )
        result = ValidationResult(
            credential=cred,
            valid=False,
            error="header-unsafe",
            validation_state="auth_rejected",
        )
        return result
    except Exception as exc:  # noqa: BLE001 - per-credential isolation boundary
        fingerprint = hashlib.sha256(cred.apikey.encode()).hexdigest()[:12]
        log.error(
            "validation failed unexpectedly for credential fingerprint=%s (%s): %s",
            fingerprint,
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        result = ValidationResult(
            credential=cred,
            valid=False,
            error=f"internal-validation-error:{type(exc).__name__}",
        )
        result.validation_state = "transient_error"
        return result

    return result


async def _probe(client: httpx.AsyncClient, cred: Credential) -> ValidationResult:
    result = ValidationResult(credential=cred, validated_at=datetime.now(UTC).isoformat())
    try:
        # httpx/h11 require legal header field-values. Scraped "keys" with CJK,
        # trailing spaces (code fragments), or CR/LF crash request send.
        # Reject early as permanent invalid — never label as transient_error.
        if not is_http_header_value_safe(cred.apikey):
            result.error = "header-unsafe-apikey"
            apply_state(result, "auth_rejected")
            return result
        apply_state(result, "structurally_valid")
        return await _probe_inner(client, cred, result)
    finally:
        _apply_issuer_attribution(result)


async def _probe_inner(
    client: httpx.AsyncClient, cred: Credential, result: ValidationResult
) -> ValidationResult:
    effective_url = cred.apiurl

    key_spec = provider_registry.match_key(cred.apikey)
    if key_spec is not None and key_spec.official_api_url:
        domain_spec = provider_registry.match_domain(cred.apiurl)
        if domain_spec is None:
            # Persist the override so downstream stages (balance, verify_no_auth,
            # output) see the endpoint the key is ACTUALLY validated against,
            # not the leaking site where it was discovered.
            cred.leak_host = cred.leak_host or cred.apiurl or cred.host
            cred.apiurl = key_spec.official_api_url
            cred.routed_to_official = True
            normalize_credential_endpoint(cred)
            cred.ip = ""
            cred.port = ""
            effective_url = cred.apiurl
            log.debug(
                "Key %s… matches provider '%s' but apiurl '%s' is not a known "
                "provider gateway → overriding to %s (leak_host=%s)",
                cred.apikey[:12],
                key_spec.name,
                cred.leak_host,
                key_spec.official_api_url,
                cred.leak_host,
            )

    resolution = resolve_provider(apiurl=effective_url, apikey=cred.apikey)
    # Prefer explicit bundle provider when registry only sees an unmatched token/key.
    if (
        resolution.provider in {"unknown", "gateway"}
        and cred.bundle is not None
        and cred.bundle.provider_hint
        and cred.bundle.provider_hint not in {"unknown", "gateway", "ambiguous"}
    ):
        try:
            hinted = provider_registry.get(cred.bundle.provider_hint)  # type: ignore[arg-type]
            from aipocket.services.providers.base import ProviderResolution

            resolution = ProviderResolution(
                hinted,
                "bundle-provider-hint",
                hinted.default_model_hints,
            )
            if not effective_url and cred.bundle.endpoint_candidates:
                effective_url = cred.bundle.endpoint_candidates[0]
                cred.apiurl = effective_url
        except KeyError:
            pass

    normalize_credential_endpoint(cred)
    effective_url = cred.apiurl or effective_url
    result.provider_info = ProviderInfo(
        validation_provider=resolution.provider,
        provider=resolution.provider,
        category=resolution.category,
    )
    if resolution.reason == "provider-conflict":
        result.error = resolution.reason
        apply_state(result, "provider_conflict")
        return result

    # Official adapters do not require a pre-normalized chat/completions URL.
    adapter_providers = {
        "openai",
        "azure_openai",
        "anthropic",
        "google",
        "gemini",
        "vertex",
    }
    api_url = _normalize_apiurl(effective_url, provider=resolution.provider)
    if not api_url and resolution.provider not in adapter_providers:
        result.error = "no apiurl"
        return result

    if resolution.provider == "openai":
        validation = await validate_openai(client, cred, InferencePolicy.READ_ONLY)
        result.status_code = validation.status_code
        result.error = validation.error
        result.credential_kind = validation.credential_kind.value
        result.tier_evidence = validation.limit_profile.tier.value
        # Preserve evidence labels (tier5_confirmed / candidate / unknown). Never
        # invent tier5 from RPM alone — that mapping lives only in the OpenAI adapter.
        result.tier = validation.limit_profile.tier.value
        result.provider_info.models_available = list(validation.models)
        result.provider_info.models_verified = (
            [validation.verified_model] if validation.verified_model else []
        )
        result.model_available = validation.verified_model or (
            validation.models[0] if validation.models else ""
        )
        for limit in validation.limit_profile.models:
            if limit.rpm is not None:
                result.rate_limit_headers[f"{limit.model}:rpm"] = str(limit.rpm)
            if limit.tpm is not None:
                result.rate_limit_headers[f"{limit.model}:tpm"] = str(limit.tpm)
        if validation.valid:
            target = (
                "scope_confirmed"
                if validation.credential_kind.value == "admin"
                else "authentication_confirmed"
            )
            if validation.inference_performed and validation.verified_model:
                target = "inference_verified"
            apply_state(result, target)
        elif validation.status_code == 429 or validation.error == "rate_limited":
            # Distinct from 401: key may be real but not currently usable.
            apply_state(result, "rate_limited_unconfirmed")
        else:
            apply_state(result, "auth_rejected")
        return result

    if resolution.provider == "azure_openai":
        validation = await validate_azure_openai(
            client,
            cred,
            AzureInferencePolicy.READ_ONLY,
        )
        result.status_code = validation.status_code
        result.error = validation.error
        result.credential_kind = validation.auth_kind.value
        result.provider_info.models_available = list(validation.models)
        result.model_available = validation.models[0] if validation.models else ""
        if validation.valid:
            apply_state(
                result,
                "inference_verified"
                if validation.inference_performed
                else "authentication_confirmed",
            )
        else:
            err = validation.error
            state = (
                "unsupported_context"
                if err.startswith("missing-")
                else "provider_conflict"
                if err == "public-openai-conflict"
                else "auth_rejected"
            )
            apply_state(result, state)
        return result

    if resolution.provider == "anthropic":
        validation = await validate_anthropic(client, cred)
        result.status_code = validation.status_code
        result.error = validation.error
        result.credential_kind = validation.credential_kind.value
        result.scope = validation.scope
        result.tier = validation.scope
        result.provider_info.models_available = list(validation.models)
        result.provider_info.models_verified = (
            [validation.verified_model] if validation.verified_model else []
        )
        result.model_available = validation.verified_model or (
            validation.models[0] if validation.models else ""
        )
        if validation.organization_id:
            # Stable org identity only — never member or key listings.
            result.response_snippet = f"organization_id={validation.organization_id}"
        if validation.valid:
            target = (
                "scope_confirmed"
                if validation.scope == "org:admin"
                else (
                    "inference_verified"
                    if validation.verified_model
                    else "authentication_confirmed"
                )
            )
            apply_state(result, target)
        elif validation.status_code == 429 or validation.error == "rate_limited":
            # Distinct from 401: do not report models-list 200 as success.
            apply_state(result, "rate_limited_unconfirmed")
        else:
            apply_state(result, "auth_rejected")
        return result

    if resolution.provider in {"google", "gemini"}:
        validation = await validate_gemini(client, cred)
        result.status_code = validation.status_code
        result.error = validation.error
        result.credential_kind = "api_key"
        result.provider_info.models_available = list(validation.models)
        result.model_available = validation.models[0] if validation.models else ""
        if validation.valid:
            apply_state(result, "authentication_confirmed")
        else:
            apply_state(result, "auth_rejected")
        return result

    if resolution.provider == "vertex":
        validation = await validate_vertex(client, cred)
        result.status_code = validation.status_code
        result.error = validation.error
        kind = cred.bundle.credential_kind if cred.bundle is not None else "token"
        result.credential_kind = kind
        result.provider_info.models_available = list(validation.models)
        result.model_available = validation.models[0] if validation.models else ""
        if validation.valid:
            apply_state(result, "authentication_confirmed")
        else:
            err = validation.error
            state = (
                "unsupported_context"
                if err.startswith("missing-")
                else "auth_rejected"
                if err in {"unauthorized", "forbidden", "expired-token"}
                else "transient_error"
                if err in {"token-exchange-failed", "assertion-failed", "models-read-failed"}
                else "auth_rejected"
            )
            apply_state(result, state)
        return result

    if resolution.provider in {"cohere", "replicate", "together", "fireworks"}:
        validation = await validate_additional_provider(client, cred, resolution.provider)
        result.status_code = validation.status_code
        result.error = validation.error
        result.credential_kind = "api_key"
        result.scope = validation.scope
        result.provider_info.models_available = list(validation.models)
        result.model_available = validation.models[0] if validation.models else ""
        if validation.valid:
            apply_state(result, "authentication_confirmed")
        elif validation.status_code == 429:
            apply_state(result, "rate_limited_unconfirmed")
        else:
            apply_state(result, "auth_rejected")
        return result

    probe_models = list(resolution.default_model_hints)
    # Best-effort: query /v1/models to enrich models_available for OpenAI-compatible gateways.
    available_models = await _fetch_models_list(client, cred, api_url)
    if available_models:
        result.provider_info.models_available = available_models

        # STRATEGY: Probe with HIGH-VALUE MODELS FIRST if they exist in the list.
        # Region-aware: domestic aggregators prefer DeepSeek/GLM/Qwen/Kimi;
        # international aggregators prefer OpenAI/Claude/Llama.
        # Also honeypot-resistant (faking gpt-5.x is harder than gpt-3.5).
        hv_order = high_value_probe_order(resolution.provider)
        hv_available = [m for m in hv_order if m in available_models]
        if hv_available:
            # Put high-value models at the front of probe list
            probe_models = hv_available + probe_models
        else:
            # No high-value models in the gateway's list. Do NOT fall back to
            # cheap models (gpt-4o-mini / gpt-3.5-turbo) — honeypots hardcode
            # exactly those IDs, so probing with them validates nothing and
            # feeds false positives. Instead probe with the gateway's OWN
            # advertised models (its first few), which at least tests what it
            # claims to serve.
            probe_models = available_models[:5] + probe_models

    if resolution.provider == "longcat" and cred.apiurl.endswith("/anthropic") or resolution.protocol_family == "anthropic":
        result = await _probe_anthropic(client, cred, api_url, result, probe_models)
    else:
        result = await _probe_chat_completions(client, cred, api_url, result, probe_models)

    return result


def _apply_issuer_attribution(result: ValidationResult) -> None:
    """Fill dual attribution fields after auth; discovery-only leaves issuer unknown."""
    cred = result.credential
    pi = result.provider_info
    validation_provider = (
        pi.validation_provider if pi.validation_provider != "unknown" else pi.provider
    )
    hint = "unknown"
    variables: tuple[str, ...] = ()
    if cred.bundle is not None:
        hint = cred.bundle.provider_hint or "unknown"
        variables = tuple(ev.variable for ev in cred.bundle.evidence if ev.variable)
    decision = decide_issuer(
        apikey=cred.apikey,
        apiurl=cred.apiurl,
        validation_provider=validation_provider,
        auth_confirmed=result.is_authenticated,
        models_available=pi.models_available,
        models_verified=pi.models_verified,
        provider_hint=hint,
        variable_names=variables,
    )
    pi.validation_provider = decision.validation_provider
    # Dual-read alias for one release.
    pi.provider = decision.validation_provider
    pi.credential_issuer = decision.credential_issuer
    pi.issuer_evidence = decision.issuer_evidence
    pi.served_model_families = list(decision.served_model_families)


def _models_list_request(cred: Credential, chat_url: str) -> tuple[str, dict[str, str]]:
    """Build models URL + auth headers for the credential's protocol.

    OpenAI-compatible gateways use ``Authorization: Bearer``. Anthropic official
    (and Anthropic-protocol hosts) require ``x-api-key`` + ``anthropic-version``;
    Bearer alone returns 401, which previously made the UI show an empty model list
    even for live ``sk-ant-…`` keys.
    """
    provider = resolve_provider(apiurl=cred.apiurl or chat_url, apikey=cred.apikey).provider
    endpoint = canonicalize_endpoint(cred.apiurl or chat_url, provider=provider)
    models_url = build_operation_url(endpoint, provider=provider, operation="models")
    is_anthropic = uses_anthropic_adapter(
        apiurl=cred.apiurl or chat_url, apikey=cred.apikey
    ) or cred.apikey.startswith("sk-ant-")
    if is_anthropic:
        headers = {
            "x-api-key": cred.apikey,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        return models_url, headers
    return models_url, {"Authorization": f"Bearer {cred.apikey}"}


async def _fetch_models_list(
    client: httpx.AsyncClient, cred: Credential, chat_url: str
) -> list[str]:
    if not is_http_header_value_safe(cred.apikey):
        return []
    models_url, headers = _models_list_request(cred, chat_url)
    try:
        r = await client.get(models_url, headers=headers)
    except (httpx.HTTPError, UnicodeEncodeError, httpx.LocalProtocolError):
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
                result.tier = _limit_profile_label(result.rate_limit_headers, r.headers)
                result.model_available = model
                result.response_snippet = _snippet(body)
                result.provider_info.models_verified.append(model)
                apply_state(result, "inference_verified")
                return result

        # Auth succeeded but org has no spendable credits — key is real.
        if r.status_code == 400:
            body = _parse_json_body(r)
            err_text = ""
            if isinstance(body, dict):
                err = body.get("error")
                if isinstance(err, dict):
                    err_text = str(err.get("message") or "")
                elif isinstance(err, str):
                    err_text = err
            low = err_text.lower()
            if "credit balance" in low or "too low" in low or "billing" in low:
                result.error = err_text or "credit balance too low"
                result.model_available = model
                apply_state(result, "authentication_confirmed")
                return result

        if r.status_code == 429:
            body = _parse_json_body(r)
            if not (body and _looks_like_api_error(body)):
                # Not an API error body → fall through to "unexpected" handling
                # (which continues to the next model).
                result.error = f"unexpected {r.status_code}: {r.text[:120]}"
                continue

            # 429 disambiguation — same rationale as _probe_chat_completions.
            # Re-probe with a forged key (Anthropic convention: x-api-key +
            # /v1/messages) and compare host behavior.
            result.tier = _limit_profile_label(result.rate_limit_headers, r.headers)
            result.model_available = model
            forged = await _forged_key_probe(client, chat_url, model, provider="anthropic")
            if forged == "suspicious_429":
                result.error = (
                    "honeypot:429-indiscriminate (real + forged key both 429 — "
                    "host rate-limits without checking auth; key not proven valid)"
                )
                apply_state(result, "auth_rejected")
                return result
            if forged == "noauth":
                result.error = (
                    "honeypot:no-auth-host (forged key returned a message under "
                    "429 retry — endpoint ignores auth, key is fake)"
                )
                apply_state(result, "no_auth_endpoint")
                return result
            if forged == "":
                result.error = "rate-limited but key is valid (forged key rejected)"
                result.suspicious_reason = (
                    "429 with forged-key rejected: real rate limit likely but "
                    "unverified — manual review"
                )
                apply_state(result, "rate_limited_unconfirmed")
                return result
            result.error = f"rate-limited but key is valid (forged probe inconclusive: {forged})"
            result.suspicious_reason = (
                f"429 with inconclusive forged-key probe ({forged}) — manual review"
            )
            apply_state(result, "rate_limited_unconfirmed")
            return result

        result.error = f"unexpected {r.status_code}: {r.text[:120]}"

    if result.status_code in (401, 403):
        apply_state(result, "auth_rejected")
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
            apply_state(result, "auth_rejected")
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
                apply_state(result, "auth_rejected")
                return result

            # Model-mismatch detection: a legitimate proxy may downgrade within
            # a family to save cost (gpt-5.5 → gpt-5.4 is plausible). But a
            # CROSS-GENERATION drop (gpt-5.5 → gpt-4o-mini / gpt-3.5-turbo) or a
            # CROSS-FAMILY swap (gpt → claude) is not a real proxy behavior —
            # it's a honeypot that accepts any model name and serves canned junk.
            # Treat severe mismatch as INVALID (honeypot), mild mismatch as valid.
            actual_model = body.get("model", "")
            if actual_model and actual_model != model and model in HIGH_VALUE_MODELS:
                if _is_severe_model_mismatch(model, actual_model):
                    # Honeypot: requested a frontier model, got a totally
                    # different/cheap one. Reject — this "key" is worthless.
                    log.warning(
                        "Severe model mismatch (honeypot): requested %s but got "
                        "%s for key %s… — rejecting",
                        model,
                        actual_model,
                        cred.apikey[:12],
                    )
                    result.model_available = actual_model
                    result.error = (
                        f"honeypot:model-mismatch (requested {model}, got "
                        f"{actual_model} — cross-generation/family swap)"
                    )
                    apply_state(result, "auth_rejected")
                    return result
                # Mild within-family downgrade (gpt-5.5 → gpt-5.4): plausible
                # proxy cost-saving. Keep valid but record the mismatch.
                log.info(
                    "Mild model mismatch: requested %s but got %s — treating as valid",
                    model,
                    actual_model,
                )
                result.tier = _limit_profile_label(result.rate_limit_headers, r.headers)
                result.model_available = actual_model
                result.response_snippet = _snippet(body)
                result.error = f"model-mismatch: requested {model}, got {actual_model}"
                result.provider_info.models_verified.append(actual_model)
                apply_state(result, "inference_verified")
                return result

            result.tier = _limit_profile_label(result.rate_limit_headers, r.headers)
            result.model_available = model
            result.response_snippet = _snippet(body)
            result.provider_info.models_verified.append(model)
            apply_state(result, "inference_verified")
            return result

        if r.status_code == 429:
            body = _parse_json_body(r)
            if body is None:
                result.error = f"status 429 non-json (body: {r.text[:120]})"
                apply_state(result, "transient_error")
                return result
            if not _looks_like_api_error(body):
                result.error = f"status 429 but body not api error (body: {r.text[:120]})"
                apply_state(result, "transient_error")
                return result

            # 429 no longer means "valid" unconditionally. Scam / open-proxy
            # gateways return 429 to EVERY key (real or fake) — so a lone 429
            # proves nothing. Disambiguate by re-probing the same endpoint with
            # a FORGED key and comparing the host's behavior. See the verdict
            # matrix in the plan / _forged_key_probe docstring.
            result.tier = _limit_profile_label(result.rate_limit_headers, r.headers)
            result.model_available = model
            forged = await _forged_key_probe(client, api_url, model)
            if forged == "suspicious_429":
                # Real AND forged key both 429 → host does not check auth at
                # all. This is the apillm.cn pattern: the 429 was never a real
                # rate limit. Reject — key is not proven.
                result.error = (
                    "honeypot:429-indiscriminate (real + forged key both 429 — "
                    "host rate-limits without checking auth; key not proven valid)"
                )
                apply_state(result, "auth_rejected")
                return result
            if forged == "noauth":
                # Forged key got a completion → endpoint ignores auth entirely.
                result.error = (
                    "honeypot:no-auth-host (forged key returned a completion under "
                    "429 retry — endpoint ignores Authorization, key is fake)"
                )
                apply_state(result, "no_auth_endpoint")
                return result
            if forged == "":
                # Forged key was REJECTED (401/403) → host DOES distinguish
                # keys. The real key's 429 is plausibly a genuine rate limit,
                # but we never saw a completion, so quarantine for review.
                result.error = "rate-limited but key is valid (forged key rejected)"
                result.suspicious_reason = (
                    "429 with forged-key rejected: real rate limit likely but "
                    "unverified — manual review"
                )
                apply_state(result, "rate_limited_unconfirmed")
                return result
            # "suspicious_noncompletion" / "error" / anything else → host
            # behaved oddly under the forged probe. Quarantine, never final.
            result.error = f"rate-limited but key is valid (forged probe inconclusive: {forged})"
            result.suspicious_reason = (
                f"429 with inconclusive forged-key probe ({forged}) — manual review"
            )
            apply_state(result, "rate_limited_unconfirmed")
            return result

        # 400 with "model not found" / "model not exist" → try next model, don't fail the key.
        try:
            body_text = r.text[:300]
        except Exception:
            body_text = ""
        low = body_text.lower()
        if r.status_code == 400 and any(
            kw in low for kw in ("model", "not found", "not exist", "does not exist")
        ):
            continue
        if "model" in low and ("not found" in low or "not exist" in low):
            continue
        result.error = f"unexpected {r.status_code}: {body_text[:120]}"

    if result.status_code in (401, 403):
        apply_state(result, "auth_rejected")
    return result


def _normalize_apiurl(url: str | None, *, provider: str = "") -> str:
    raw_url = (url or "").strip()
    if not raw_url:
        return ""
    resolved_provider = provider or resolve_provider(apiurl=raw_url).provider
    endpoint = canonicalize_endpoint(raw_url, provider=resolved_provider)
    return build_operation_url(endpoint, provider=resolved_provider, operation="chat")


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


def _limit_profile_label(rate_headers: dict[str, str], all_headers: Any) -> str:
    """Record rate-limit profile without inventing OpenAI usage tiers.

    A single ``x-ratelimit-limit-requests`` value is model-scoped evidence, not
    an account tier. Explicit ``tier`` response headers are preserved as-is.
    """
    lower_map = {k.lower(): v for k, v in all_headers.items()}
    explicit = lower_map.get("tier") or lower_map.get("x-tier")
    if explicit:
        return str(explicit)

    limit_req = rate_headers.get("x-ratelimit-limit-requests")
    if limit_req:
        try:
            return f"rpm:{int(limit_req)}"
        except ValueError:
            return f"rpm:{limit_req}"
    return ""


# Backward-compatible alias for tests/callers that still import the old name.
# Does not map RPM thresholds to tier5/4/3.
def _infer_tier(rate_headers: dict[str, str], all_headers: Any) -> str:
    return _limit_profile_label(rate_headers, all_headers)


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
    return bool(
        any(
            kw in msg or kw in detail
            for kw in ("rate", "limit", "quota", "exceeded", "unauthorized")
        )
    )
