from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
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

_ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
_ANTHROPIC_VERSION = "2023-06-01"
# Anthropic does not expose remaining prepaid balance via API key.
# We surface a stable sentinel so UI/reprobe treat the row as resolved.
_ANTHROPIC_BALANCE_NA = "N/A"


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
        # Anthropic next: official keys have no remaining-balance endpoint.
        # Probe marks gateway + N/A (API) or admin org spend (Admin keys).
        ("anthropic", _probe_anthropic, base),
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
            if not is_ant_host:
                return {}
            return {
                "balance_usd": _ANTHROPIC_BALANCE_NA,
                "source": "admin_unauthorized",
                "credential_kind": kind,
                "alive": False,
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

        result: dict[str, Any] = {
            "balance_usd": _ANTHROPIC_BALANCE_NA,
            "source": "admin_cost_report" if spend_usd is not None else "admin_org_alive",
            "credential_kind": kind,
            "alive": True,
            "tier": "org:admin",
            "organization_id": org_id,
            "organization_name": org_name,
            "status_code": 200,
        }
        if spend_usd is not None:
            result["spend_usd_30d"] = spend_usd
        if cost_raw is not None:
            result["raw"] = {"organization": org_body, "cost_report": cost_raw}
        else:
            result["raw"] = {"organization": org_body}
        return result

    # Ordinary Console API key — models list proves liveness; no balance API.
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
    if models_resp.status_code != 200:
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

    return {
        "balance_usd": _ANTHROPIC_BALANCE_NA,
        "source": "api_key_no_balance",
        "credential_kind": "api",
        "alive": True,
        "model_count": len(models),
        "models": models[:20],
        "status_code": 200,
        "note": "Anthropic Console API keys have no remaining-balance endpoint; check Console billing.",
    }


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
    *,
    use_cache: bool = True,
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
            if dedup is not None and use_cache:
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
