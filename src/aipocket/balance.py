from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
from rich.table import Table

from .config import settings
from .models import Credential, ValidationResult

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
    base = cred.apiurl.rstrip("/")
    if base.endswith("/v1/chat/completions"):
        base = base[: -len("/v1/chat/completions")]
    elif base.endswith("/v1"):
        base = base[: -len("/v1")]
    if not base.startswith("http"):
        base = "https://" + base

    probes = [
        ("litellm", _probe_litellm, base),
        ("oneapi", _probe_oneapi, base),
        ("newapi", _probe_newapi, base),
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

async def enrich_results(results: list[ValidationResult]) -> list[ValidationResult]:
    sem = asyncio.Semaphore(settings.validate_concurrency)
    timeout = httpx.Timeout(settings.validate_timeout)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async def _one(r: ValidationResult) -> ValidationResult:
            if not r.valid:
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
