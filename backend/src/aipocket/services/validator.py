from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential, ProviderInfo, ValidationResult

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

# Fallback model list used when the provider is unknown (e.g. a bare IP gateway)
# or when /v1/models is unreachable. HIGH-VALUE ONLY — no cheap models.
# Reason: cheap IDs (gpt-4o-mini, gpt-3.5-turbo) are exactly what honeypots
# hardcode, so probing with them validates nothing and inflates false positives.
# If a random gateway actually serves one of these, that's the finding we want.
FALLBACK_MODELS = [
    # OpenAI frontier
    "gpt-5.5", "gpt-5.4",
    # Anthropic Claude 4 family
    "claude-sonnet-4-6", "claude-opus-4-8", "claude-opus-4-7",
    # DeepSeek
    "deepseek-v4-pro", "deepseek-v4-flash",
    # Zhipu GLM (glm-5.1 per target spec)
    "glm-5.1",
]

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
        "deepseek", "claude", "gemini", "glm", "qwen", "kimi", "gpt",
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
    if gen_req and gen_act and gen_req != gen_act:
        return True
    return False


# Key-prefix → (official_api_url, provider_name).
# When a credential's key matches one of these prefixes but its apiurl points to an
# unrelated leaked host (e.g. a PHP blog that exposed the key in response headers),
# we override the apiurl with the official endpoint so the key is actually testable.
KEY_PREFIX_ROUTING: list[tuple[str, str, str]] = [
    ("sk-proj", "https://api.openai.com/v1", "openai"),
    ("sk-admin", "https://api.openai.com/v1", "openai"),
    ("sk-svcacct", "https://api.openai.com/v1", "openai"),
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
            r = await client.post(endpoint, headers=headers, json=payload, timeout=timeout)
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


async def verify_no_auth(
    results: list[ValidationResult],
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
    seen_hosts: dict[str, tuple[str, str]] = {}  # host -> (api_url, model)
    for r in results:
        if not r.valid:
            continue
        host = r.credential.host or r.credential.apiurl
        if host in seen_hosts:
            continue
        api_url = _normalize_apiurl(r.credential.apiurl)
        model = r.model_available or "gpt-4o-mini"
        if api_url:
            seen_hosts[host] = (api_url, model)

    if not seen_hosts:
        return set(), set()

    sem = asyncio.Semaphore(settings.validate_concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)

    async def _probe_forged(host: str, api_url: str, model: str) -> str:
        """Probe one host with a forged key; return a verdict tag.

        Thin wrapper over :func:`_forged_key_probe` that carries the per-host
        ``log.warning`` calls (those need ``host``/``api_url`` for triage).
        """
        async with sem, httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            verdict = await _forged_key_probe(client, api_url, model, timeout=timeout)
        if verdict == "suspicious_429":
            log.warning(
                "suspicious host (forged-key 429): %s (%s) — host "
                "rate-limits without checking auth (open proxy?)",
                host, api_url,
            )
        elif verdict == "noauth":
            log.warning(
                "no-auth host confirmed: forged key validated on "
                "%s (%s) — voiding all keys on this host",
                host, api_url,
            )
        elif verdict == "suspicious_noncompletion":
            log.warning(
                "suspicious host (200 non-completion): %s (%s) — "
                "host is not a real LLM gateway",
                host, api_url,
            )
        return verdict

    tasks = [_probe_forged(h, u, m) for h, (u, m) in seen_hosts.items()]
    verdicts = await asyncio.gather(*tasks)
    no_auth = {h for h, v in zip(seen_hosts, verdicts) if v == "noauth"}
    suspicious = {h for h, v in zip(seen_hosts, verdicts) if v.startswith("suspicious")}
    if no_auth:
        log.info(
            "verify_no_auth: %d/%d hosts accept a forged key (no-auth honeypots)",
            len(no_auth), len(seen_hosts),
        )
    if suspicious:
        log.info(
            "verify_no_auth: %d/%d hosts suspicious (forged-429 / non-completion) "
            "→ quarantined to suspicious_*.jsonl",
            len(suspicious), len(seen_hosts),
        )
    return no_auth, suspicious


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    cred: Credential,
) -> ValidationResult:
    async with sem:
        result = await _probe(client, cred)

    # Real-time persistence: save high-value official keys immediately.
    from .high_value_writer import try_save
    try_save(result)

    return result


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
                # Persist the override so downstream stages (balance, verify_no_auth,
                # output) see the endpoint the key is ACTUALLY validated against,
                # not the leaking blog/banner host the key was scraped from. The
                # original leak site is preserved in cred.leak_host.
                cred.leak_host = cred.apiurl
                cred.apiurl = official_url
                cred.routed_to_official = True
                parsed = urlparse(official_url)
                cred.host = parsed.hostname or cred.host
                # ip/port described the leak host, not the official gateway — clear
                # them so clustering/no-auth logic keys on the validation endpoint.
                cred.ip = ""
                cred.port = str(parsed.port) if parsed.port else ""
                effective_url = official_url
                log.debug(
                    "Key %s… matches prefix '%s' but apiurl '%s' is not a known "
                    "provider gateway → overriding to %s (leak_host=%s)",
                    cred.apikey[:12], prefix, cred.leak_host, official_url,
                    cred.leak_host,
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
            # No high-value models in the gateway's list. Do NOT fall back to
            # cheap models (gpt-4o-mini / gpt-3.5-turbo) — honeypots hardcode
            # exactly those IDs, so probing with them validates nothing and
            # feeds false positives. Instead probe with the gateway's OWN
            # advertised models (its first few), which at least tests what it
            # claims to serve.
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
            if not (body and _looks_like_api_error(body)):
                # Not an API error body → fall through to "unexpected" handling
                # (which continues to the next model).
                result.error = f"unexpected {r.status_code}: {r.text[:120]}"
                continue

            # 429 disambiguation — same rationale as _probe_chat_completions.
            # Re-probe with a forged key (Anthropic convention: x-api-key +
            # /v1/messages) and compare host behavior.
            result.tier = _infer_tier(result.rate_limit_headers, r.headers)
            result.model_available = model
            forged = await _forged_key_probe(client, chat_url, model, provider="anthropic")
            if forged == "suspicious_429":
                result.valid = False
                result.error = (
                    "honeypot:429-indiscriminate (real + forged key both 429 — "
                    "host rate-limits without checking auth; key not proven valid)"
                )
                return result
            if forged == "noauth":
                result.valid = False
                result.error = (
                    "honeypot:no-auth-host (forged key returned a message under "
                    "429 retry — endpoint ignores auth, key is fake)"
                )
                return result
            if forged == "":
                result.valid = True
                result.suspicious = True
                result.error = "rate-limited but key is valid (forged key rejected)"
                result.suspicious_reason = (
                    "429 with forged-key rejected: real rate limit likely but "
                    "unverified — manual review"
                )
                return result
            result.valid = True
            result.suspicious = True
            result.error = f"rate-limited but key is valid (forged probe inconclusive: {forged})"
            result.suspicious_reason = (
                f"429 with inconclusive forged-key probe ({forged}) — manual review"
            )
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
                        model, actual_model, cred.apikey[:12],
                    )
                    result.valid = False
                    result.model_available = actual_model
                    result.error = (
                        f"honeypot:model-mismatch (requested {model}, got "
                        f"{actual_model} — cross-generation/family swap)"
                    )
                    return result
                # Mild within-family downgrade (gpt-5.5 → gpt-5.4): plausible
                # proxy cost-saving. Keep valid but record the mismatch.
                log.info(
                    "Mild model mismatch: requested %s but got %s — treating as valid",
                    model, actual_model,
                )
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

            # 429 no longer means "valid" unconditionally. Scam / open-proxy
            # gateways return 429 to EVERY key (real or fake) — so a lone 429
            # proves nothing. Disambiguate by re-probing the same endpoint with
            # a FORGED key and comparing the host's behavior. See the verdict
            # matrix in the plan / _forged_key_probe docstring.
            result.tier = _infer_tier(result.rate_limit_headers, r.headers)
            result.model_available = model
            forged = await _forged_key_probe(client, api_url, model)
            if forged == "suspicious_429":
                # Real AND forged key both 429 → host does not check auth at
                # all. This is the apillm.cn pattern: the 429 was never a real
                # rate limit. Reject.
                result.valid = False
                result.error = (
                    "honeypot:429-indiscriminate (real + forged key both 429 — "
                    "host rate-limits without checking auth; key not proven valid)"
                )
                return result
            if forged == "noauth":
                # Forged key got a completion → endpoint ignores auth entirely.
                result.valid = False
                result.error = (
                    "honeypot:no-auth-host (forged key returned a completion under "
                    "429 retry — endpoint ignores Authorization, key is fake)"
                )
                return result
            if forged == "":
                # Forged key was REJECTED (401/403) → host DOES distinguish
                # keys. The real key's 429 is plausibly a genuine rate limit,
                # but we never saw a completion, so keep it as suspicious for
                # manual review rather than trusting it outright.
                result.valid = True
                result.suspicious = True
                result.error = "rate-limited but key is valid (forged key rejected)"
                result.suspicious_reason = (
                    "429 with forged-key rejected: real rate limit likely but "
                    "unverified — manual review"
                )
                return result
            # "suspicious_noncompletion" / "error" / anything else → host
            # behaved oddly under the forged probe (non-completion 200, network
            # error). Could not confirm the key is real. Keep valid but
            # suspicious.
            result.valid = True
            result.suspicious = True
            result.error = f"rate-limited but key is valid (forged probe inconclusive: {forged})"
            result.suspicious_reason = (
                f"429 with inconclusive forged-key probe ({forged}) — manual review"
            )
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
        base = url.rsplit("/v1/", 1)[0]
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
