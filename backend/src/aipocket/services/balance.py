from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import httpx
from rich.table import Table

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult
from aipocket.services.providers import uses_openai_adapter
from aipocket.services.providers.openai import InferencePolicy, validate_openai

if TYPE_CHECKING:
    from .dedup import DedupStore

log = logging.getLogger(__name__)


async def _safe_get(
    client: httpx.AsyncClient,
    url: str,
    key: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """GET with error handling. Returns parsed JSON dict or None on failure."""
    if headers is None:
        headers = {"Authorization": f"Bearer {key}"}
    try:
        r = await client.get(url, headers=headers, params=params)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def query_balance(client: httpx.AsyncClient, cred: Credential) -> dict[str, Any]:
    if cred.bundle is not None and uses_openai_adapter(apiurl=cred.apiurl, apikey=cred.apikey):
        validation = await validate_openai(client, cred, InferencePolicy.READ_ONLY)
        return {
            "gateway": "openai",
            "balance_usd": "",
            "tier": validation.limit_profile.tier.value,
            "limit_profile": validation.limit_profile.model_dump(mode="json"),
        }
    base = cred.apiurl.rstrip("/")
    if base.endswith("/v1/chat/completions"):
        base = base[: -len("/v1/chat/completions")]
    elif base.endswith("/v1"):
        base = base[: -len("/v1")]
    if not base.startswith("http"):
        base = "https://" + base

    probes = [
        # OpenRouter first: sk-or-v1 keys always hit the official host, and
        # domain-matched openrouter.ai bases must not fall through to generic
        # gateway probes that would burn requests and return unsupported.
        ("openrouter", _probe_openrouter, base),
        ("litellm", _probe_litellm, base),
        ("oneapi", _probe_oneapi, base),
        ("newapi", _probe_newapi, base),
        ("newapi_billing", _probe_newapi_billing, base),
        ("nexus", _probe_nexus_usage, base),
        ("deepseek", _probe_deepseek, base),
        ("moonshot", _probe_moonshot, base),
        ("glm", _probe_glm, base),
        ("siliconflow", _probe_siliconflow, base),
        ("openai", _probe_openai_billing, base),
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


async def _probe_litellm(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/key/info", key, params={"key": key})
    if data is None:
        return {}
    key_info = data.get("key_info", data)
    spend = key_info.get("spend", 0)
    max_budget = key_info.get("max_budget", 0) or key_info.get("max_budget_soft", 0)
    return {
        "spend": spend,
        "max_budget": max_budget,
        "remaining": max_budget - spend if max_budget else 0,
        "balance_usd": round(max_budget - spend, 2) if max_budget else 0,
        "tier": key_info.get("tier", ""),
        "models": key_info.get("models", []),
        "raw": key_info,
    }


async def _probe_openai_billing(client: httpx.AsyncClient, base: str, key: str) -> dict[str, Any]:
    data = await _safe_get(client, f"{base}/v1/dashboard/billing/credit_grants", key)
    if data is None:
        return {}
    grants = data.get("data", [])
    total = sum(g.get("grant_amount", 0) - g.get("used", 0) for g in grants)
    return {
        "balance_usd": round(total, 2),
        "grants": grants,
        "raw": data,
    }


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
    - xyxhqy-style: {"balance": <float>, "remaining": <float>, "unit": "USD", ...}
    """
    data = await _safe_get(client, f"{base}/v1/usage", key)
    if data is None:
        return {}
    # Nexus AI format
    if data.get("object") == "list":
        total = data.get("total_usage")
        if total is not None:
            return {"balance_usd": round(float(total), 4), "raw": data}
    # xyxhqy / wallet-style format
    if "balance" in data or "remaining" in data:
        bal = float(data.get("balance") or data.get("remaining") or 0)
        return {"balance_usd": round(bal, 4), "raw": data}
    return {}


async def enrich_results(
    results: list[ValidationResult],
    dedup: DedupStore | None = None,
) -> list[ValidationResult]:
    sem = asyncio.Semaphore(settings.validate_concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:

        async def _one(r: ValidationResult) -> ValidationResult:
            if not r.valid:
                return r
            # Cross-run balance cache: reuse the previous run's balance result
            # instead of re-querying the endpoint. Falls through to a live
            # query on miss / when dedup is disabled.
            if dedup is not None:
                cached = await dedup.get_cached_balance(r.credential)
                if cached:
                    r.balance = str(cached.get("balance_usd", ""))
                    r.gateway = cached.get("gateway", "") or r.gateway
                    if cached.get("tier"):
                        r.tier = r.tier or cached["tier"]
                    r.rate_limit_headers["balance_detail"] = str(cached)
                    r.provider_info.balance_provider = (
                        cached.get("gateway", "") or r.provider_info.balance_provider
                    )
                    return r
            try:
                async with sem:
                    bal = await query_balance(client, r.credential)
            except Exception as e:
                log.warning("Balance query failed for %s…: %s", r.credential.apikey[:12], e)
                return r
            if bal:
                r.balance = str(bal.get("balance_usd", ""))
                r.gateway = bal.get("gateway", "")
                if bal.get("tier"):
                    r.tier = r.tier or bal["tier"]
                r.rate_limit_headers["balance_detail"] = str(bal)
                r.provider_info.balance_provider = bal.get("gateway", "")
                if dedup is not None:
                    await dedup.cache_balance(r.credential, bal)
            return r

        return await asyncio.gather(*[_one(r) for r in results])


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
