from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
from rich.table import Table

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult
from aipocket.core.request_ledger import RequestAttribution
from aipocket.services.balance_dispatch import ProbeResult, apply_probe_result, dispatch_probe
from aipocket.services.http_transport import is_http_header_value_safe
from aipocket.services.providers import resolve_provider, uses_openai_adapter

_BALANCE_BATCH_SIZE = 100
_CACHE_WARNING_LIMIT = 3


if TYPE_CHECKING:
    from .dedup import DedupStore

log = logging.getLogger(__name__)


def _credential_label(cred: Credential) -> str:
    """Return a non-secret identifier suitable for failure logs."""
    from aipocket.core.observations import credential_identity

    return credential_identity(cred).secret_fingerprint[:12]


def _evidence_provider(result: ValidationResult) -> str:
    provider = result.provider_info.validation_provider
    if provider in {"", "unknown", "ambiguous"}:
        provider = resolve_provider(
            apiurl=result.credential.apiurl,
            apikey=result.credential.apikey,
        ).provider
    return provider


def _log_cache_failure(operation: str, cred: Credential, exc: Exception, count: int) -> None:
    if count <= _CACHE_WARNING_LIMIT:
        log.warning(
            "Balance cache %s failed for credential fingerprint=%s (%s): %s",
            operation,
            _credential_label(cred),
            type(exc).__name__,
            exc,
        )
    elif count == _CACHE_WARNING_LIMIT + 1:
        log.warning("Balance cache failures continue; suppressing per-credential warnings")


_ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
_ANTHROPIC_VERSION = "2023-06-01"
# Anthropic does not expose remaining prepaid balance via API key.
# We surface a stable sentinel so UI/reprobe treat the row as resolved.
_ANTHROPIC_BALANCE_NA = "N/A"

_OPENAI_API_HOST = "https://api.openai.com"
# OpenAI has no fully-public remaining-balance API for all key types; when
# dashboard endpoints reject API keys we still mark the row resolved.
_OPENAI_BALANCE_NA = "N/A"


def _balance_client(client: httpx.AsyncClient, cred: Credential):
    from aipocket.core.observations import credential_identity
    from aipocket.services.http_transport import InstrumentedAsyncClient, LedgerContext

    if isinstance(client, InstrumentedAsyncClient):
        return client

    identity = credential_identity(cred)
    return InstrumentedAsyncClient(
        client,
        defaults=LedgerContext(
            stage="balance",
            source="balance",
            credential_fingerprint=identity.secret_fingerprint,
            target_identity=identity.endpoint,
            product=cred.product,
        ),
    )


async def _safe_get(
    client: httpx.AsyncClient,
    url: str,
    key: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """GET with error handling. Returns parsed JSON dict or None on failure."""
    if not is_http_header_value_safe(key):
        return None
    if headers is None:
        headers = {"Authorization": f"Bearer {key}"}
    try:
        r = await client.get(url, headers=headers, params=params)
    except (httpx.HTTPError, UnicodeEncodeError, httpx.LocalProtocolError):
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _strip_api_base(apiurl: str) -> str:
    base = (apiurl or "").rstrip("/")
    if base.endswith("/v1/chat/completions"):
        base = base[: -len("/v1/chat/completions")]
    elif base.endswith("/v1"):
        base = base[: -len("/v1")]
    if base and not base.startswith("http"):
        base = "https://" + base
    return base


async def query_balance(client: httpx.AsyncClient, cred: Credential) -> dict[str, Any]:
    if not is_http_header_value_safe(cred.apikey):
        return {"gateway": "unsupported", "balance_usd": ""}
    client = _balance_client(client, cred)
    probe_context = ValidationResult(credential=cred)
    resolution = __import__(
        "aipocket.services.providers", fromlist=["resolve_provider"]
    ).resolve_provider(apiurl=cred.apiurl, apikey=cred.apikey)
    probe_context.provider_info.validation_provider = resolution.provider
    probe_context.provider_info.provider = resolution.provider
    dispatched = await dispatch_probe(client, probe_context)
    if dispatched.matched:
        data = dispatched.model_dump()
        data["gateway"] = "dashscope" if dispatched.provider == "qwen" else dispatched.provider
        data["balance_usd"] = dispatched.balance_usd
        legacy_source = dispatched.detail.get("source")
        if legacy_source:
            data["source"] = legacy_source
        data.update(dispatched.detail)
        if dispatched.balance_native != "":
            data["balance_native"] = dispatched.balance_native
        return data
    # Official OpenAI keys: force platform host (billing lives on the account,
    # not a reverse-proxy leak host). Runs before generic gateway probes.
    if uses_openai_adapter(apiurl=cred.apiurl, apikey=cred.apikey) or _is_openai_official_key(
        cred.apikey
    ):
        try:
            oai = await _probe_openai(client, cred)
        except (httpx.HTTPError, ValueError):
            oai = {}
        if oai:
            oai["gateway"] = "openai"
            return oai

    base = _strip_api_base(cred.apiurl)

    probes = [
        # OpenRouter first: sk-or-v1 keys always hit the official host, and
        # domain-matched openrouter.ai bases must not fall through to generic
        # gateway probes that would burn requests and return unsupported.
        ("openrouter", _probe_openrouter, base),
        # Anthropic next: official keys have no remaining-balance endpoint.
        # Probe marks gateway + N/A (API) or admin org spend (Admin keys).
        ("anthropic", _probe_anthropic, base),
        # DashScope / 阿里云百炼 (not ModelScope) — before generic gateway probes.
        ("dashscope", _probe_dashscope, base),
        ("litellm", _probe_litellm, base),
        ("oneapi", _probe_oneapi, base),
        ("newapi", _probe_newapi, base),
        ("newapi_billing", _probe_newapi_billing, base),
        ("nexus", _probe_nexus_usage, base),
        ("deepseek", _probe_deepseek, base),
        ("moonshot", _probe_moonshot, base),
        ("glm", _probe_glm, base),
        ("siliconflow", _probe_siliconflow, base),
        # Last-chance: OpenAI-compatible billing proxy on the credential host
        # (new-api / one-api forks). Official OpenAI keys already handled above.
        ("openai", _probe_openai_billing_on_host, base),
    ]

    for gateway, fn, url in probes:
        try:
            result = await fn(client, url, cred.apikey)
        except (httpx.HTTPError, ValueError):
            continue
        if result:
            result["gateway"] = gateway
            return result
    return {"gateway": "unsupported", "balance_usd": ""}


def _anthropic_headers(key: str) -> dict[str, str]:
    headers = {
        "anthropic-version": _ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    if key.startswith("sk-ant-oat") or key.startswith("sk-ant-sid"):
        headers["Authorization"] = f"Bearer {key}"
    else:
        headers["x-api-key"] = key
    return headers


def _sum_anthropic_cost_usd(payload: dict[str, Any]) -> float | None:
    """Sum Cost Report amounts (cents as decimal strings) into USD."""
    data = payload.get("data")
    if not isinstance(data, list):
        return None
    total_cents = 0.0
    found = False
    for bucket in data:
        if not isinstance(bucket, dict):
            continue
        results = bucket.get("results")
        if not isinstance(results, list):
            continue
        for row in results:
            if not isinstance(row, dict):
                continue
            amount = row.get("amount")
            if amount is None:
                continue
            try:
                total_cents += float(amount)
                found = True
            except (TypeError, ValueError):
                continue
    if not found:
        return None
    return round(total_cents / 100.0, 4)


async def _probe_anthropic(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    """Probe Anthropic official keys.

    Remaining prepaid balance is **not** available via the public API for
    ordinary ``sk-ant-api…`` keys (only Console UI). This probe:

    * Confirms the key is alive via ``GET /v1/models`` and returns
      ``balance_usd="N/A"`` with ``source=api_key_no_balance``.
    * For Admin / OAuth org-scoped keys, reads ``/v1/organizations/me`` and
      optionally the last-30d Cost Report (spend, not remaining balance).

    Always hits the official Anthropic host — balance lives on the account,
    not a reverse proxy. Non-Anthropic keys/hosts return ``{}`` so other
    gateway probes can run.
    """
    is_ant_key = key.startswith("sk-ant-")
    is_ant_host = "anthropic.com" in base.lower()
    if not is_ant_key and not is_ant_host:
        return {}

    headers = _anthropic_headers(key)
    kind = "api"
    if key.startswith("sk-ant-admin"):
        kind = "admin"
    elif key.startswith("sk-ant-oat") or key.startswith("sk-ant-sid"):
        kind = "oauth"

    # Admin / OAuth: org scope + optional cost report (Admin API).
    if kind in ("admin", "oauth"):
        try:
            org_resp = await client.get(f"{_ANTHROPIC_API_BASE}/organizations/me", headers=headers)
        except httpx.HTTPError:
            return {}
        if org_resp.status_code != 200:
            # Fall through so a misclassified sk-ant-admin on a gateway can still
            # hit one-api / new-api probes when the official host rejects it.
            if not is_ant_host and org_resp.status_code not in (401, 403, 429):
                return {}
            if not is_ant_host and not is_ant_key:
                return {}
            # Distinguish auth death vs rate limit vs other errors.
            if org_resp.status_code in (401, 403):
                source = "unauthorized"
                alive = False
            elif org_resp.status_code == 429:
                source = "rate_limited"
                alive = True  # key accepted; throttled
            else:
                source = "admin_org_error"
                alive = False
            return {
                "balance_usd": _ANTHROPIC_BALANCE_NA,
                "source": source,
                "credential_kind": kind,
                "alive": alive,
                "status_code": org_resp.status_code,
            }
        org_body: dict[str, Any] = {}
        try:
            parsed = org_resp.json()
            if isinstance(parsed, dict):
                org_body = parsed
        except ValueError:
            pass
        org_id = str(org_body.get("id") or org_body.get("organization_id") or "")
        org_name = str(org_body.get("name") or "")

        spend_usd: float | None = None
        cost_raw: dict[str, Any] | None = None
        # Cost report is Admin-API; OAuth may lack permission — best-effort.
        ending = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(
            days=1
        )
        starting = ending - timedelta(days=30)
        try:
            cost_resp = await client.get(
                f"{_ANTHROPIC_API_BASE}/organizations/cost_report",
                headers=headers,
                params={
                    "starting_at": starting.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "ending_at": ending.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "bucket_width": "1d",
                },
            )
            if cost_resp.status_code == 200:
                try:
                    raw = cost_resp.json()
                except ValueError:
                    raw = None
                if isinstance(raw, dict):
                    cost_raw = raw
                    spend_usd = _sum_anthropic_cost_usd(raw)
        except httpx.HTTPError:
            pass

        # Rate Limits API (Admin): infer Start / Build / Scale usage tier.
        usage_tier = ""
        rate_limits_raw: dict[str, Any] | None = None
        try:
            rl_resp = await client.get(
                f"{_ANTHROPIC_API_BASE}/organizations/rate_limits",
                headers=headers,
            )
            if rl_resp.status_code == 200:
                try:
                    rl_body = rl_resp.json()
                except ValueError:
                    rl_body = None
                if isinstance(rl_body, dict):
                    rate_limits_raw = rl_body
                    usage_tier = _anthropic_usage_tier_from_rate_limits(rl_body)
        except httpx.HTTPError:
            pass

        tier_label = usage_tier or "org:admin"
        result: dict[str, Any] = {
            "balance_usd": _ANTHROPIC_BALANCE_NA,
            "source": "admin_cost_report" if spend_usd is not None else "admin_org_alive",
            "credential_kind": kind,
            "alive": True,
            "tier": tier_label,
            "organization_id": org_id,
            "organization_name": org_name,
            "status_code": 200,
        }
        if spend_usd is not None:
            # 30d spend is not remaining balance — surface separately.
            result["spend_usd_30d"] = spend_usd
        if usage_tier:
            result["usage_tier"] = usage_tier
        raw_out: dict[str, Any] = {"organization": org_body}
        if cost_raw is not None:
            raw_out["cost_report"] = cost_raw
        if rate_limits_raw is not None:
            raw_out["rate_limits"] = rate_limits_raw
        result["raw"] = raw_out
        return result

    # Ordinary Console API key — models list proves liveness; no balance API.
    # Status contract: 200=alive, 429=rate-limited (alive), 401/403=dead.
    try:
        models_resp = await client.get(f"{_ANTHROPIC_API_BASE}/models", headers=headers)
    except httpx.HTTPError:
        return {}
    if models_resp.status_code in (401, 403):
        if not is_ant_host and is_ant_key:
            # Real-looking prefix on a third-party host; let gateway probes run.
            return {}
        return {
            "balance_usd": _ANTHROPIC_BALANCE_NA,
            "source": "unauthorized",
            "credential_kind": "api",
            "alive": False,
            "status_code": models_resp.status_code,
        }
    if models_resp.status_code == 429:
        # Key is accepted but rate-limited — distinct from 401 and from 200.
        if not is_ant_host and not is_ant_key:
            return {}
        return {
            "balance_usd": _ANTHROPIC_BALANCE_NA,
            "source": "rate_limited",
            "credential_kind": "api",
            "alive": True,
            "status_code": 429,
            "note": "Anthropic API key rate-limited on /v1/models (not unauthorized).",
        }
    if models_resp.status_code != 200:
        if is_ant_host or is_ant_key:
            return {
                "balance_usd": _ANTHROPIC_BALANCE_NA,
                "source": "models_error",
                "credential_kind": "api",
                "alive": False,
                "status_code": models_resp.status_code,
            }
        return {}

    models: list[str] = []
    try:
        body = models_resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        data = body.get("data", [])
        if isinstance(data, list):
            models = [
                str(item["id"])
                for item in data
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ]

    # Rate-limit headers on /models (when present) beat model-name heuristics.
    tier_label = _tier_from_anthropic_headers(models_resp.headers)
    if not tier_label:
        # Ordinary Console API keys have no remaining balance and no Pro/Max
        # subscription surface — those products are claude.ai (session), not API.
        # Usage & Cost / Rate Limits Admin APIs require sk-ant-admin… keys.
        tier_label = "api:payg"
        if any("opus" in m.lower() for m in models):
            tier_label = "api:usage_tier_frontier"
        elif any("sonnet" in m.lower() for m in models):
            tier_label = "api:usage_tier_standard"

    return {
        "balance_usd": _ANTHROPIC_BALANCE_NA,
        "source": "api_key_no_balance",
        "credential_kind": "api",
        "alive": True,
        "tier": tier_label,
        "model_count": len(models),
        "models": models[:20],
        "status_code": 200,
        "note": (
            "Anthropic Console API keys have no remaining-balance endpoint. "
            "Usage & Cost Admin API requires sk-ant-admin… keys. "
            "claude.ai Pro/Max subscriptions are not exposed on API keys."
        ),
    }


def _tier_from_anthropic_headers(headers: httpx.Headers) -> str:
    """Build a compact rate-limit label from Anthropic response headers."""
    rpm = headers.get("anthropic-ratelimit-requests-limit")
    itpm = headers.get("anthropic-ratelimit-input-tokens-limit")
    otpm = headers.get("anthropic-ratelimit-output-tokens-limit")
    tokens = headers.get("anthropic-ratelimit-tokens-limit")
    parts: list[str] = []
    if rpm:
        parts.append(f"rpm:{rpm}")
    if itpm:
        parts.append(f"itpm:{itpm}")
    if otpm:
        parts.append(f"otpm:{otpm}")
    if not parts and tokens:
        parts.append(f"tpm:{tokens}")
    if not parts:
        return ""
    # Best-effort Start/Build/Scale from published RPM/ITPM tables.
    try:
        rpm_n = int(float(rpm)) if rpm else 0
    except (TypeError, ValueError):
        rpm_n = 0
    try:
        itpm_n = int(float(itpm or tokens or 0))
    except (TypeError, ValueError):
        itpm_n = 0
    usage = _anthropic_usage_tier_from_numbers(rpm_n, itpm_n)
    if usage:
        return f"{usage} ({', '.join(parts)})"
    return ", ".join(parts)


def _anthropic_usage_tier_from_numbers(rpm: int, itpm: int) -> str:
    """Map RPM/ITPM to Start / Build / Scale (published Anthropic tables)."""
    # Scale: Opus RPM 10k / ITPM 10M; Build: 5k / 5M; Start: 1k / 2M (model-dependent).
    if rpm >= 10000 or itpm >= 10_000_000:
        return "usage_tier:scale"
    if rpm >= 5000 or itpm >= 5_000_000:
        return "usage_tier:build"
    if rpm >= 1000 or itpm >= 500_000:
        return "usage_tier:start"
    return ""


def _anthropic_usage_tier_from_rate_limits(payload: dict[str, Any]) -> str:
    """Infer usage tier from Admin Rate Limits API payload."""
    data = payload.get("data")
    if not isinstance(data, list):
        return ""
    max_rpm = 0
    max_itpm = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        # Prefer model_group entries (Messages API tiers); skip batch/files/etc.
        gt = entry.get("group_type")
        if gt is not None and gt != "model_group":
            continue
        limits = entry.get("limits")
        if not isinstance(limits, list):
            continue
        for lim in limits:
            if not isinstance(lim, dict):
                continue
            kind = str(lim.get("type") or "")
            try:
                value = int(float(lim.get("value") or 0))
            except (TypeError, ValueError):
                continue
            if kind == "requests_per_minute":
                max_rpm = max(max_rpm, value)
            elif kind in ("input_tokens_per_minute", "tokens_per_minute"):
                max_itpm = max(max_itpm, value)
    return _anthropic_usage_tier_from_numbers(max_rpm, max_itpm)


async def _probe_openrouter(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    """Probe OpenRouter key credits via GET /api/v1/auth/key (+ /credits fallback).

    ``query_balance`` strips a trailing ``/v1`` so *base* is typically
    ``https://openrouter.ai/api``.  ``sk-or-v1-`` keys always query the official
    host (balance lives on the account, not a proxy). Domain-matched bases that
    already point at openrouter.ai are also accepted.
    """
    is_or_key = key.startswith("sk-or-v1-")
    is_or_host = "openrouter.ai" in base
    if not is_or_key and not is_or_host:
        return {}

    # Force official API for prefix-matched keys so proxy/leaked hosts still
    # resolve real account credits.
    probe_base = "https://openrouter.ai/api" if is_or_key else base.rstrip("/")

    data = await _safe_get(client, f"{probe_base}/v1/auth/key", key)
    if data is None:
        return {}
    d = data.get("data")
    if not isinstance(d, dict):
        return {}

    usage = float(d.get("usage") or 0)
    limit = d.get("limit")
    limit_remaining = d.get("limit_remaining")
    is_free_tier = bool(d.get("is_free_tier"))

    balance: float | None = None
    source = "key"

    if limit_remaining is not None:
        # Per-key spend cap remaining (preferred when set).
        balance = float(limit_remaining)
    elif limit is not None:
        balance = max(float(limit) - usage, 0.0)
    else:
        # Unlimited key: fall back to account-level remaining credits.
        credits = await _safe_get(client, f"{probe_base}/v1/credits", key)
        cd = credits.get("data") if isinstance(credits, dict) else None
        if isinstance(cd, dict) and (
            cd.get("total_credits") is not None or cd.get("total_usage") is not None
        ):
            total_credits = float(cd.get("total_credits") or 0)
            total_usage = float(cd.get("total_usage") or 0)
            balance = max(total_credits - total_usage, 0.0)
            source = "credits"
            return {
                "balance_usd": round(balance, 4),
                "usage": round(total_usage, 4),
                "total_credits": round(total_credits, 4),
                "is_free_tier": is_free_tier,
                "source": source,
                "raw": {"key": d, "credits": cd},
            }
        # Key authenticated but no spend limit and credits endpoint unavailable.
        # Free-tier keys effectively have $0 prepaid balance.
        if is_free_tier:
            balance = 0.0
            source = "free_tier"
        else:
            # Still mark as openrouter so callers don't keep re-probing forever;
            # leave balance empty rather than invent a number.
            return {
                "balance_usd": "",
                "usage": round(usage, 4),
                "limit": limit,
                "is_free_tier": is_free_tier,
                "source": "key_no_limit",
                "raw": d,
            }

    return {
        "balance_usd": round(balance, 4) if balance is not None else "",
        "usage": round(usage, 4),
        "limit": limit,
        "limit_remaining": limit_remaining,
        "is_free_tier": is_free_tier,
        "source": source,
        "raw": d,
    }


async def _probe_oneapi(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/api/user/self", key)
    if data is None or not data.get("success"):
        return {}
    user = data.get("data", {})
    quota = user.get("quota", 0)
    used = user.get("used_quota", 0)
    return {
        "quota": quota,
        "used": used,
        "remaining": quota - used,
        "balance_usd": round(quota / 500000, 4),
        "raw": user,
    }


async def _probe_newapi(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/api/user/self", key)
    if data is None or not data.get("success"):
        return {}
    user = data.get("data", {})
    quota = user.get("quota", 0)
    used = user.get("used_quota", 0)
    return {
        "quota": quota,
        "used": used,
        "remaining": quota - used,
        "balance_usd": round(quota / 500000, 4),
        "raw": user,
    }


async def _probe_newapi_billing(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    """Probe new-api's OpenAI-style billing proxy endpoints.

    new-api (and one-api forks) accept an ``sk-`` API key on the proxied billing
    endpoints even though the REST ``/api/user/self`` requires a separate user
    access token. Reads the quota limit from ``/dashboard/billing/subscription``
    and cumulative usage (in cents) from ``/dashboard/billing/usage``.
    """
    sub = await _safe_get(client, f"{base}/dashboard/billing/subscription", key)
    if not sub or sub.get("object") != "billing_subscription":
        return {}
    hard_limit = float(sub.get("hard_limit_usd") or sub.get("system_hard_limit_usd") or 0)

    # Usage is reported in cents (OpenAI convention). Use a wide date range so
    # the cumulative total is captured regardless of when the key was created.
    params = {"start_date": "2024-01-01", "end_date": "2099-12-31"}
    usage = await _safe_get(client, f"{base}/dashboard/billing/usage", key, params=params)
    used_usd = 0.0
    if usage and usage.get("object") == "list":
        used_usd = float(usage.get("total_usage") or 0) / 100.0

    remaining = round(max(hard_limit - used_usd, 0.0), 4)
    return {
        "balance_usd": remaining,
        "hard_limit_usd": hard_limit,
        "used_usd": round(used_usd, 4),
        "raw": {"subscription": sub, "usage": usage},
    }


def _litellm_key_info_blob(data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract LiteLLM key budget object from known response envelopes.

    Observed shapes:
    * ``{"key_info": {...}}`` (older/proxy docs)
    * ``{"key": "...", "info": {...}}`` (current proxy, e.g. llm.alem.ai)
    """
    for field in ("key_info", "info"):
        blob = data.get(field)
        if isinstance(blob, dict):
            return blob
    return None


async def _probe_litellm(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/key/info", key, params={"key": key})
    if data is None:
        return {}
    if data.get("success") is False or "error" in data:
        return {}
    key_info = _litellm_key_info_blob(data)
    if key_info is None:
        return {}
    # Require at least one real budget field so error HTML/JSON cannot match.
    budget_fields = ("spend", "max_budget", "max_budget_soft")
    has_numeric_budget = any(
        isinstance(key_info.get(field), int | float) and not isinstance(key_info.get(field), bool)
        for field in budget_fields
    )
    # Null-only max_budget rows need spend or models[] to claim LiteLLM contract.
    if not has_numeric_budget and key_info.get("spend") is None and key_info.get("max_budget") is None:
        return {}

    spend_raw = key_info.get("spend")
    spend = (
        float(spend_raw)
        if isinstance(spend_raw, int | float) and not isinstance(spend_raw, bool)
        else 0.0
    )
    maximum = key_info.get("max_budget")
    if not (isinstance(maximum, int | float) and not isinstance(maximum, bool)):
        soft = key_info.get("max_budget_soft")
        maximum = soft if isinstance(soft, int | float) and not isinstance(soft, bool) else None

    models = key_info.get("models") if isinstance(key_info.get("models"), list) else []
    tier = str(key_info.get("tier") or "")

    # LiteLLM: max_budget=null means unlimited (not $0 remaining).
    if maximum is None:
        return {
            "spend": spend,
            "max_budget": None,
            "remaining": "",
            "balance_usd": "N/A",
            "source": "key_no_limit",
            "tier": tier,
            "models": models,
            "note": "LiteLLM max_budget is null (unlimited); spend is cumulative usage",
            "raw": key_info,
        }

    remaining = max(float(maximum) - spend, 0.0)
    return {
        "spend": spend,
        "max_budget": float(maximum),
        "remaining": remaining,
        "balance_usd": round(remaining, 2),
        "source": "litellm:key_info",
        "tier": tier,
        "models": models,
        "raw": key_info,
    }


def _is_openai_official_key(key: str) -> bool:
    """True for key shapes that always belong to platform.openai.com."""
    return key.startswith(("sk-proj-", "sk-svcacct-", "sk-admin-", "sess-"))


def _openai_auth_headers(cred: Credential) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {cred.apikey}"}
    context = cred.bundle.context if cred.bundle is not None else None
    if context is not None:
        if context.project:
            headers["OpenAI-Project"] = context.project
        if context.organization:
            headers["OpenAI-Organization"] = context.organization
    return headers


def _parse_openai_credit_grants(data: dict[str, Any]) -> float | None:
    """Extract remaining prepaid credits from credit_grants payload.

    Known shapes:
    * ``credit_summary``: top-level total_available / total_granted / total_used
    * Nested ``grants.data[]`` with grant_amount + used_amount
    * Flat ``data[]`` list of credit_grant objects
    """
    if data.get("total_available") is not None:
        try:
            return round(float(data["total_available"]), 4)
        except (TypeError, ValueError):
            pass

    grants_block = data.get("grants")
    grant_rows: list[Any] = []
    if isinstance(grants_block, dict) and isinstance(grants_block.get("data"), list):
        grant_rows = grants_block["data"]
    elif isinstance(data.get("data"), list):
        grant_rows = data["data"]

    total = 0.0
    found = False
    for g in grant_rows:
        if not isinstance(g, dict):
            continue
        grant_amount = g.get("grant_amount")
        used = g.get("used_amount", g.get("used"))
        if grant_amount is None and used is None:
            continue
        try:
            total += float(grant_amount or 0) - float(used or 0)
            found = True
        except (TypeError, ValueError):
            continue
    if found:
        return round(max(total, 0.0), 4)
    return None


def _openai_tier_from_headers(headers: httpx.Headers) -> str:
    """Compact rate-limit profile from OpenAI response headers (not authoritative tier)."""
    rpm = headers.get("x-ratelimit-limit-requests")
    tpm = headers.get("x-ratelimit-limit-tokens")
    parts: list[str] = []
    if rpm:
        parts.append(f"rpm:{rpm}")
    if tpm:
        parts.append(f"tpm:{tpm}")
    return " ".join(parts)


def _openai_usage_tier_label(
    explicit: str = "", *, rpm: int | None = None, tpm: int | None = None
) -> str:
    """Prefer explicit account_tier; otherwise leave a candidate label from limits."""
    cleaned = (explicit or "").strip().lower().replace(" ", "_")
    if cleaned:
        # Normalize tier_5 / Tier5 / tier5 → tier5
        cleaned = cleaned.replace("tier_", "tier")
        if cleaned.startswith("tier") or cleaned in {"free", "payg", "enterprise"}:
            return cleaned
        return explicit.strip()
    # Soft candidate only — OpenAI tiers are org-level and model-specific.
    if rpm is not None and rpm >= 10000:
        return "tier5_candidate"
    if rpm is not None and rpm >= 5000:
        return "tier4_candidate"
    if rpm is not None and rpm >= 500:
        return "tier1+_candidate"
    if tpm is not None and tpm >= 2_000_000:
        return "tier5_candidate"
    if tpm is not None and tpm >= 450_000:
        return "tier3+_candidate"
    return ""


async def _probe_openai(client: httpx.AsyncClient, cred: Credential) -> dict[str, Any]:
    """Probe official OpenAI account balance + usage tier.

    Strategy (always hits ``api.openai.com`` for known key prefixes):

    1. ``GET /dashboard/billing/credit_grants`` (and ``/v1/...`` alias) —
       prepaid remaining credit when the key/session still has access.
    2. ``GET /dashboard/billing/subscription`` + ``/usage`` —
       hard spend limit minus period usage (PAYG budget remaining).
    3. Liveness via ``GET /v1/models``; capture rate-limit headers for a
       coarse tier profile.
    4. Admin keys (``sk-admin-``): organization project rate_limits for
       authoritative ``account_tier``.

    When billing endpoints reject API keys (common since ~2023 — session
    tokens preferred), still return ``balance_usd=N/A`` with tier so the
    high-value UI can show usage level instead of an empty unsupported row.
    """
    key = cred.apikey
    apiurl = (cred.apiurl or "").lower()
    is_prefix = _is_openai_official_key(key)
    is_host = "openai.com" in apiurl
    # Bare sk- only when the credential already points at OpenAI (or registry
    # already classified it via uses_openai_adapter in the caller).
    is_ordinary = key.startswith("sk-") and not key.startswith(
        ("sk-or-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-")
    )
    if not is_prefix and not is_host and not is_ordinary:
        return {}

    headers = _openai_auth_headers(cred)
    host = _OPENAI_API_HOST
    kind = "ordinary"
    if key.startswith("sk-proj-"):
        kind = "project"
    elif key.startswith("sk-svcacct-"):
        kind = "service_account"
    elif key.startswith("sk-admin-"):
        kind = "admin"
    elif key.startswith("sess-"):
        kind = "session"

    # --- 1) Credit grants (prepaid remaining) ---
    for path in (
        "/dashboard/billing/credit_grants",
        "/v1/dashboard/billing/credit_grants",
    ):
        data = await _safe_get(client, f"{host}{path}", key, headers=headers)
        if not data:
            continue
        remaining = _parse_openai_credit_grants(data)
        if remaining is None:
            continue
        return {
            "balance_usd": remaining,
            "source": "credit_grants",
            "credential_kind": kind,
            "alive": True,
            "raw": data,
        }

    # --- 2) Subscription hard limit − usage (PAYG budget) ---
    sub: dict[str, Any] | None = None
    for path in (
        "/dashboard/billing/subscription",
        "/v1/dashboard/billing/subscription",
    ):
        sub = await _safe_get(client, f"{host}{path}", key, headers=headers)
        if sub:
            break
    if sub and (
        sub.get("object") == "billing_subscription"
        or sub.get("hard_limit_usd") is not None
        or sub.get("system_hard_limit_usd") is not None
    ):
        hard_limit = float(sub.get("hard_limit_usd") or sub.get("system_hard_limit_usd") or 0)
        today = datetime.now(UTC).date()
        # Wide window captures cumulative usage for hard-limit accounting.
        params = {
            "start_date": (today.replace(day=1) - timedelta(days=90)).isoformat(),
            "end_date": (today + timedelta(days=1)).isoformat(),
        }
        usage: dict[str, Any] | None = None
        for path in (
            "/dashboard/billing/usage",
            "/v1/dashboard/billing/usage",
            "/v1/usage",
        ):
            usage = await _safe_get(client, f"{host}{path}", key, headers=headers, params=params)
            if usage:
                break
        used_usd = 0.0
        if usage:
            # OpenAI dashboard usage: total_usage is cents.
            if usage.get("total_usage") is not None:
                try:
                    used_usd = float(usage["total_usage"]) / 100.0
                except (TypeError, ValueError):
                    used_usd = 0.0
            elif usage.get("total_usage_usd") is not None:
                try:
                    used_usd = float(usage["total_usage_usd"])
                except (TypeError, ValueError):
                    used_usd = 0.0
        remaining: float | str
        if hard_limit:
            remaining = round(max(hard_limit - used_usd, 0.0), 4)
            source = "subscription_budget"
        else:
            remaining = _OPENAI_BALANCE_NA
            source = "subscription"
        plan = ""
        plan_obj = sub.get("plan")
        if isinstance(plan_obj, dict):
            plan = str(plan_obj.get("id") or plan_obj.get("title") or "")
        result: dict[str, Any] = {
            "balance_usd": remaining,
            "source": source,
            "credential_kind": kind,
            "alive": True,
            "hard_limit_usd": hard_limit,
            "used_usd": round(used_usd, 4),
            "plan": plan,
            "raw": {"subscription": sub, "usage": usage},
        }
        # Soft signal: hard limit size correlates with usage-tier spend caps.
        if hard_limit >= 200_000:
            result["tier"] = "tier5_candidate"
        elif hard_limit >= 5000:
            result["tier"] = "tier4_candidate"
        elif hard_limit >= 1000:
            result["tier"] = "tier3_candidate"
        elif hard_limit >= 100:
            result["tier"] = "tier1+_candidate"
        return result

    # --- 3) Admin: authoritative account_tier from project rate_limits ---
    if kind == "admin":
        try:
            projects_resp = await client.get(
                f"{host}/v1/organization/projects",
                headers=headers,
            )
        except httpx.HTTPError:
            projects_resp = None
        if projects_resp is not None and projects_resp.status_code == 200:
            try:
                projects_body = projects_resp.json()
            except ValueError:
                projects_body = None
            projects = projects_body.get("data", []) if isinstance(projects_body, dict) else []
            explicit_tier = ""
            limits_summary: list[dict[str, Any]] = []
            for item in projects if isinstance(projects, list) else []:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                pid = str(item["id"])
                try:
                    rl = await client.get(
                        f"{host}/v1/organization/projects/{pid}/rate_limits",
                        headers=headers,
                    )
                except httpx.HTTPError:
                    continue
                if rl.status_code != 200:
                    continue
                try:
                    body = rl.json()
                except ValueError:
                    continue
                if not isinstance(body, dict):
                    continue
                if body.get("account_tier"):
                    explicit_tier = str(body["account_tier"])
                limits_summary.append(
                    {
                        "project_id": pid,
                        "account_tier": body.get("account_tier"),
                        "count": len(body.get("data") or [])
                        if isinstance(body.get("data"), list)
                        else 0,
                    }
                )
                if explicit_tier:
                    break
            tier = _openai_usage_tier_label(explicit_tier) or "admin"
            return {
                "balance_usd": _OPENAI_BALANCE_NA,
                "source": "admin_rate_limits",
                "credential_kind": kind,
                "alive": True,
                "tier": tier,
                "account_tier": explicit_tier,
                "raw": {"projects": limits_summary},
                "note": (
                    "OpenAI Admin keys expose account_tier via project rate_limits; "
                    "remaining prepaid balance needs dashboard/session access."
                ),
            }
        if projects_resp is not None and projects_resp.status_code in (401, 403):
            return {
                "balance_usd": _OPENAI_BALANCE_NA,
                "source": "unauthorized",
                "credential_kind": kind,
                "alive": False,
                "status_code": projects_resp.status_code,
            }
        if projects_resp is not None and projects_resp.status_code == 429:
            return {
                "balance_usd": _OPENAI_BALANCE_NA,
                "source": "rate_limited",
                "credential_kind": kind,
                "alive": True,
                "status_code": 429,
            }

    # --- 4) Liveness via models + rate-limit header profile ---
    # Status contract: 200=alive, 429=rate-limited (alive), 401/403=dead.
    try:
        models_resp = await client.get(f"{host}/v1/models", headers=headers)
    except httpx.HTTPError:
        return {}
    if models_resp.status_code in (401, 403):
        # Dead key on official host. For non-official hosts, allow gateway probes.
        if not is_host and not is_prefix:
            return {}
        # Prefix keys are always OpenAI — report unauthorized rather than
        # wasting requests on one-api/litellm paths that will also fail.
        if is_prefix or is_host:
            return {
                "balance_usd": _OPENAI_BALANCE_NA,
                "source": "unauthorized",
                "credential_kind": kind,
                "alive": False,
                "status_code": models_resp.status_code,
            }
        return {}
    if models_resp.status_code == 429:
        if not is_prefix and not is_host and not is_ordinary:
            return {}
        return {
            "balance_usd": _OPENAI_BALANCE_NA,
            "source": "rate_limited",
            "credential_kind": kind,
            "alive": True,
            "status_code": 429,
            "note": "OpenAI API key rate-limited on /v1/models (not unauthorized).",
        }
    if models_resp.status_code != 200:
        # Transient / unexpected — only claim openai if host matched.
        if is_prefix or is_host:
            return {
                "balance_usd": _OPENAI_BALANCE_NA,
                "source": "models_error",
                "credential_kind": kind,
                "alive": False,
                "status_code": models_resp.status_code,
            }
        return {}

    models: list[str] = []
    try:
        body = models_resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        data = body.get("data", [])
        if isinstance(data, list):
            models = [
                str(item["id"])
                for item in data
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ]

    rpm_raw = models_resp.headers.get("x-ratelimit-limit-requests")
    tpm_raw = models_resp.headers.get("x-ratelimit-limit-tokens")
    rpm_n: int | None = None
    tpm_n: int | None = None
    if rpm_raw is not None:
        with contextlib.suppress(ValueError):
            rpm_n = int(rpm_raw)
    if tpm_raw is not None:
        with contextlib.suppress(ValueError):
            tpm_n = int(tpm_raw)

    header_profile = _openai_tier_from_headers(models_resp.headers)
    tier = _openai_usage_tier_label("", rpm=rpm_n, tpm=tpm_n) or header_profile or "api:payg"

    return {
        "balance_usd": _OPENAI_BALANCE_NA,
        "source": "api_key_no_balance",
        "credential_kind": kind,
        "alive": True,
        "tier": tier,
        "model_count": len(models),
        "models": models[:20],
        "status_code": 200,
        "rate_limit_profile": header_profile,
        "note": (
            "OpenAI remaining balance requires dashboard credit_grants/subscription "
            "(often session-token gated). Key is alive; tier is from rate-limit "
            "headers or model access, not an official usage-tier API."
        ),
    }


async def _probe_openai_billing_on_host(
    client: httpx.AsyncClient, base: str, key: str
) -> dict[str, Any]:
    """Best-effort billing probe against the credential host (gateway proxies).

    Official OpenAI keys are handled by :func:`_probe_openai` first. This path
    covers third-party OpenAI-compatible gateways that expose the legacy
    ``/dashboard/billing/*`` surface.
    """
    if not base or "openai.com" in base.lower():
        # Official host already covered; avoid double-probing.
        return {}
    for path in (
        "/dashboard/billing/credit_grants",
        "/v1/dashboard/billing/credit_grants",
    ):
        data = await _safe_get(client, f"{base}{path}", key)
        if not data:
            continue
        remaining = _parse_openai_credit_grants(data)
        if remaining is None:
            continue
        return {
            "balance_usd": remaining,
            "source": "credit_grants",
            "raw": data,
        }
    return {}


async def _probe_deepseek(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/user/balance", key)
    if data is None:
        return {}
    infos = data.get("balance_infos") or []
    total_cny = 0.0
    for info in infos:
        total_cny += float(info.get("total_balance", 0) or 0)
    return {
        "balance_usd": round(total_cny / 7.2, 2),
        "balance_cny": round(total_cny, 2),
        "raw": data,
    }


async def _probe_moonshot(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/v1/users/me/balance", key)
    if data is None:
        return {}
    avail = 0.0
    d = data.get("data")
    if isinstance(d, dict):
        avail = float(d.get("available_balance", 0) or 0)
    return {
        "balance_cny": round(avail, 2),
        "balance_usd": round(avail / 7.2, 2),
        "raw": data,
    }


async def _probe_glm(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/api/paas/v4/biz/finance/balance", key)
    if data is None:
        return {}
    d = data.get("data")
    bal = float(d.get("balance", 0) or 0) if isinstance(d, dict) else 0.0
    return {
        "balance_cny": round(bal, 2),
        "balance_usd": round(bal / 7.2, 2),
        "raw": data,
    }


async def _probe_siliconflow(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/v1/user/info", key)
    if data is None:
        return {}
    d = data.get("data")
    bal = float(d.get("balance", 0) or 0) if isinstance(d, dict) else 0.0
    return {
        "balance_usd": round(bal, 4),
        "raw": data,
    }


async def _probe_nexus_usage(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    """Probe /v1/usage — used by Nexus AI and similar custom platforms.

    Handles two known response formats:
    - Nexus AI: {"object": "list", "daily_costs": [...], "total_usage": <float>}
      **total_usage is cumulative spend, NOT remaining balance.** We never map it
      to balance_usd (honeypots advertise ~$100 usage as fake "balance").
    - xyxhqy-style: {"balance": <float>, "remaining": <float>, "unit": "USD", ...}
    """
    data = await _safe_get(client, f"{base}/v1/usage", key)
    if data is None:
        return {}
    # Wallet-style only — real remaining/balance fields.
    if "balance" in data or "remaining" in data:
        bal = float(data.get("balance") or data.get("remaining") or 0)
        return {"balance_usd": round(bal, 4), "raw": data}
    # Nexus list format: usage only. Mark gateway so we don't re-probe forever,
    # but leave balance empty (do NOT treat total_usage as balance).
    if data.get("object") == "list" and data.get("total_usage") is not None:
        return {
            "balance_usd": "",
            "usage_usd": round(float(data["total_usage"]), 4),
            "source": "usage_not_balance",
            "note": "total_usage is spend, not remaining balance",
            "raw": data,
        }
    return {}


async def _probe_dashscope(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    """Probe Alibaba Cloud DashScope / 百炼 (compatible-mode) keys.

    Official sk- keys do not expose remaining prepaid balance via the public
    compatible-mode API. We:

    1. Confirm liveness via GET /compatible-mode/v1/models (or /models).
    2. Best-effort try a few account/quota endpoints that some tenants expose.
    3. Otherwise return balance=N/A with source=api_key_no_balance.

    Always targets the official dashscope host for domain-matched / known keys
    so proxy leak hosts still resolve the real account when possible.
    """
    host = base.lower()
    # DashScope / 百炼 (incl. intl + coding-plan hosts). Not modelscope.cn.
    is_ds = "dashscope.aliyuncs.com" in host or "dashscope-intl.aliyuncs.com" in host
    is_ds = is_ds or "coding.dashscope" in host or "coding-intl.dashscope" in host
    if not is_ds:
        return {}

    # Prefer CN endpoint; intl keys live on dashscope-intl.
    if "dashscope-intl" in host:
        official = "https://dashscope-intl.aliyuncs.com"
    elif "coding-intl.dashscope" in host:
        official = "https://coding-intl.dashscope.aliyuncs.com"
    elif "coding.dashscope" in host:
        official = "https://coding.dashscope.aliyuncs.com"
    else:
        official = "https://dashscope.aliyuncs.com"

    headers = {"Authorization": f"Bearer {key}"}

    # --- best-effort quota endpoints (may 404 for most keys) ---
    for path in (
        "/api/v1/account/balance",
        "/api/v1/fe-taurus/users/quota",
        "/api/v1/services/aigc/workspace/balance",
    ):
        data = await _safe_get(client, f"{official}{path}", key, headers=headers)
        if not data:
            continue
        # Common shapes: {data:{totalAvailable / balance / available}} or top-level
        d = data.get("data") if isinstance(data.get("data"), dict) else data
        for field in (
            "totalAvailable",
            "total_available",
            "available_balance",
            "available",
            "balance",
            "quota",
        ):
            if field in d and d[field] is not None:
                try:
                    bal = float(d[field])
                except (TypeError, ValueError):
                    continue
                return {
                    "balance_usd": round(bal / 7.2, 4) if bal > 50 else round(bal, 4),
                    "balance_cny": round(bal, 4) if bal > 50 else None,
                    "source": f"dashscope:{path}:{field}",
                    "raw": data,
                }

    # Liveness via models list (compatible-mode).
    models_urls = [
        f"{official}/compatible-mode/v1/models",
        f"{official}/api/v1/models",
        f"{base.rstrip('/')}/models" if base else "",
    ]
    for murl in models_urls:
        if not murl:
            continue
        try:
            resp = await client.get(murl, headers=headers)
        except httpx.HTTPError:
            continue
        if resp.status_code in (401, 403):
            return {
                "balance_usd": "N/A",
                "source": "unauthorized",
                "alive": False,
                "status_code": resp.status_code,
            }
        if resp.status_code == 200:
            return {
                "balance_usd": "N/A",
                "source": "api_key_no_balance",
                "alive": True,
                "status_code": 200,
                "note": (
                    "DashScope/百炼 sk- keys have no public remaining-balance "
                    "endpoint; check 百炼 console billing. (Not ModelScope.)"
                ),
            }
    return {}


async def enrich_results(
    results: list[ValidationResult],
    dedup: DedupStore | None = None,
    *,
    use_cache: bool = True,
    attribution: dict[int, RequestAttribution] | None = None,
) -> list[ValidationResult]:
    if not results:
        return results

    concurrency = max(1, int(settings.validate_concurrency))
    sem = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)
    limits = httpx.Limits(max_connections=concurrency * 2)
    cache_failures = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
    ) as client:

        async def _one(r: ValidationResult) -> ValidationResult:
            nonlocal cache_failures
            from aipocket.core.request_ledger import current_query_attribution

            attribution_token = current_query_attribution.set(
                (attribution or {}).get(id(r.credential), RequestAttribution())
            )
            try:
                if not r.valid:
                    return r
                # Suspicious rows are intentionally enriched with provider-specific
                # read-only evidence; rejected rows never reach this function.
                # Redis is an optional cache. A saturated/unavailable pool must
                # never abort enrichment or the scan's final persistence.
                if dedup is not None and use_cache:
                    try:
                        cached = await dedup.get_cached_balance(r.credential)
                    except Exception as exc:  # noqa: BLE001 - cache is best-effort
                        cache_failures += 1
                        _log_cache_failure("read", r.credential, exc, cache_failures)
                        cached = None
                    if cached:
                        try:
                            cached_probe = ProbeResult.model_validate(cached)
                        except (TypeError, ValueError):
                            cached_probe = ProbeResult()
                        if cached_probe.matched:
                            apply_probe_result(r, cached_probe)
                            cached_observed_at = str(cached.get("observed_at") or "")
                            if cached_observed_at:
                                r.provider_info.evidence_observed_at = cached_observed_at
                                r.provider_evidence["observed_at"] = cached_observed_at
                            return r
                        r.balance = str(cached.get("balance_usd", ""))
                        r.gateway = cached.get("gateway", "") or r.gateway
                        if cached.get("tier"):
                            r.tier = r.tier or cached["tier"]
                        return r
                try:
                    async with sem:
                        probe = await dispatch_probe(client, r)
                        if not probe.matched:
                            if _evidence_provider(r) not in {"gateway", "unknown", "ambiguous"}:
                                return r
                            legacy_bal = await query_balance(client, r.credential)
                            if legacy_bal.get("gateway") == "unsupported":
                                return r
                            r.balance = str(legacy_bal.get("balance_usd", ""))
                            r.gateway = str(legacy_bal.get("gateway", ""))
                            if legacy_bal.get("tier"):
                                r.tier = r.tier or str(legacy_bal["tier"])
                            if dedup is not None:
                                try:
                                    await dedup.cache_balance(r.credential, legacy_bal)
                                except Exception as exc:  # noqa: BLE001 - cache is best-effort
                                    cache_failures += 1
                                    _log_cache_failure("write", r.credential, exc, cache_failures)
                            return r
                except Exception as exc:  # noqa: BLE001 - per-credential isolation
                    log.warning(
                        "Provider evidence failed for credential fingerprint=%s (%s): %s",
                        _credential_label(r.credential),
                        type(exc).__name__,
                        exc,
                    )
                    return r
                apply_probe_result(r, probe)
                bal = probe.model_dump()
                bal["gateway"] = probe.provider
                bal["balance_usd"] = probe.balance_usd
                bal["observed_at"] = r.provider_info.evidence_observed_at
                if dedup is not None:
                    try:
                        await dedup.cache_balance(r.credential, bal)
                    except Exception as exc:  # noqa: BLE001 - cache is best-effort
                        cache_failures += 1
                        _log_cache_failure("write", r.credential, exc, cache_failures)
                return r
            except Exception as exc:  # noqa: BLE001 - final task isolation boundary
                log.warning(
                    "Balance enrichment skipped for credential fingerprint=%s (%s): %s",
                    _credential_label(r.credential),
                    type(exc).__name__,
                    exc,
                )
                return r
            finally:
                current_query_attribution.reset(attribution_token)

        for start in range(0, len(results), _BALANCE_BATCH_SIZE):
            batch = results[start : start + _BALANCE_BATCH_SIZE]
            await asyncio.gather(*(_one(result) for result in batch))

    return results


async def _query_latest_balances_async() -> list[dict[str, Any]]:
    from .writer import load_latest

    results_data = load_latest()
    if not results_data:
        return []
    out: list[dict[str, Any]] = []
    timeout = httpx.Timeout(settings.validate_timeout)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for item in results_data:
            raw = item.get("credential") or item
            if not raw.get("apikey"):
                continue
            cred = Credential(
                apikey=raw["apikey"],
                apiurl=raw.get("apiurl", ""),
                host=raw.get("host", ""),
            )
            bal = await query_balance(client, cred)
            out.append(
                {
                    "apikey": cred.apikey,
                    "apiurl": cred.apiurl,
                    "gateway": bal.get("gateway", "-"),
                    "balance": bal.get("balance_usd", "-"),
                    "tier": bal.get("tier", "-"),
                }
            )
    return out


def query_latest_balances() -> Table:
    table = Table(title="Balance check — latest scan")
    table.add_column("apikey")
    table.add_column("apiurl")
    table.add_column("gateway")
    table.add_column("balance")
    table.add_column("tier")

    rows = asyncio.run(_query_latest_balances_async())
    for r in rows:
        table.add_row(
            r["apikey"][:12] + "…",
            r["apiurl"][:40],
            str(r["gateway"]),
            str(r["balance"]),
            str(r["tier"]),
        )
    return table
