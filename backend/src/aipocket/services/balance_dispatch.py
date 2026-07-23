from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from aipocket.core.models import Credential, ValidationResult
from aipocket.services.http_transport import is_http_header_value_safe
from aipocket.services.providers import resolve_provider
from aipocket.services.providers.endpoints import build_operation_url, canonicalize_endpoint

EvidenceKind = Literal["cash_balance", "plan", "quota", "entitlement", "identity", "liveness"]


class ProbeResult(BaseModel):
    matched: bool = False
    provider: str = ""
    source: str = ""
    evidence_kind: EvidenceKind = "liveness"
    balance_usd: str | float = ""
    balance_native: str | float = ""
    currency: str = ""
    plan: str = ""
    tier: str = ""
    account_type: str = ""
    quota: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, Any] = Field(default_factory=dict)
    entitlements: dict[str, Any] = Field(default_factory=dict)
    identity: dict[str, Any] = Field(default_factory=dict)
    alive: bool | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


_OFFICIAL_PROVIDERS = frozenset(
    {
        "openai",
        "anthropic",
        "deepseek",
        "kimi",
        "glm",
        "qwen",
        "siliconflow",
        "cohere",
        "replicate",
        "together",
        "fireworks",
        "groq",
        "openrouter",
        "azure_openai",
        "vertex",
        "minimax",
        "nvidia",
        "ksyun",
        "longcat",
    }
)
_NEWAPI_STATUS_FIELDS = frozenset(
    {"quota_per_unit", "stripe_unit_price", "self_use_mode_enabled", "system_name", "version"}
)
_GLM_PASSIVE_CODES = frozenset({"1308", "1310", "1311", *(str(code) for code in range(1314, 1322))})
_RESET_AT_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+Z?\b")
_LONGCAT_DEPLETED_MARKERS = (
    "credit balance",
    "insufficient balance",
    "insufficient quota",
    "余额不足",
    "额度不足",
    "欠费",
)


def _headers(credential: Credential) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential.apikey}"}


async def _json_get(
    client: httpx.AsyncClient,
    url: str,
    credential: Credential,
    *,
    params: dict[str, str] | None = None,
) -> tuple[httpx.Response | None, dict[str, Any] | None]:
    if not url or not is_http_header_value_safe(credential.apikey):
        return None, None
    try:
        response = await client.get(url, headers=_headers(credential), params=params)
    except (httpx.HTTPError, UnicodeEncodeError, httpx.LocalProtocolError):
        return None, None
    try:
        payload = response.json()
    except ValueError:
        return response, None
    return response, payload if isinstance(payload, dict) else None


def _numeric(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _coerce_number(value: object) -> float | None:
    """Parse JSON numbers that may arrive as int/float *or* decimal strings.

    Official DeepSeek balance docs type ``total_balance`` as string
    (e.g. ``"110.00"``). Strict ``_numeric`` rejects those and makes the
    probe look like an unsupported provider.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _model_ids(payload: dict[str, Any] | None) -> list[str] | None:
    if payload is None or not isinstance(payload.get("data"), list):
        return None
    ids = [
        str(item["id"])
        for item in payload["data"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    return ids if ids else None


def _probe_glm_passive(result: ValidationResult) -> ProbeResult:
    evidence_text = " ".join(part for part in (result.error, result.response_snippet) if part)
    code = next(
        (
            candidate
            for candidate in _GLM_PASSIVE_CODES
            if re.search(rf"(?<!\d){candidate}(?!\d)", evidence_text)
        ),
        "",
    )
    if not code:
        return ProbeResult()
    reset_match = _RESET_AT_PATTERN.search(evidence_text)
    quota: dict[str, Any] = {"business_code": code}
    if reset_match:
        quota["reset_at"] = reset_match.group(0)
    return ProbeResult(
        matched=True,
        provider="glm",
        source="glm:passive_error",
        evidence_kind="quota",
        quota=quota,
        alive=True,
        detail={"business_code": code, "message": evidence_text[:500]},
    )


def _longcat_liveness(result: ValidationResult) -> ProbeResult:
    evidence_text = " ".join(part for part in (result.error, result.response_snippet) if part)
    detail: dict[str, Any] = {
        "models": result.provider_info.models_available,
        "validation_state": result.validation_state,
        "passive_error": result.error,
    }
    if any(marker in evidence_text.lower() for marker in _LONGCAT_DEPLETED_MARKERS):
        detail["cash_balance_state"] = "depleted"
    return ProbeResult(
        matched=result.is_authenticated,
        provider="longcat",
        source="longcat:validated_liveness",
        evidence_kind="liveness",
        alive=result.is_authenticated,
        detail=detail,
    )


async def _probe_deepseek(
    client: httpx.AsyncClient, credential: Credential, provider: str
) -> ProbeResult:
    """GET /user/balance — official schema uses string decimal balances.

    See https://api-docs.deepseek.com/api/get-user-balance/ ::

        {"is_available": true, "balance_infos": [
            {"currency": "CNY", "total_balance": "110.00", ...}
        ]}

    Currency may be ``CNY`` or ``USD``. CNY → ``balance_native``; USD →
    ``balance_usd``. Empty ``balance_infos`` is treated as zero cash.
    """
    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)
    response, payload = await _json_get(
        client,
        build_operation_url(endpoint, provider=provider, operation="balance"),
        credential,
    )
    infos = payload.get("balance_infos") if payload else None
    if response is None or response.status_code != 200 or not isinstance(infos, list):
        return ProbeResult()
    totals: dict[str, float] = {}
    for item in infos:
        if not isinstance(item, dict):
            return ProbeResult()
        amount = _coerce_number(item.get("total_balance"))
        if amount is None:
            return ProbeResult()
        currency = str(item.get("currency") or "CNY").upper()
        totals[currency] = totals.get(currency, 0.0) + amount
    cny = totals.get("CNY")
    usd = totals.get("USD")
    # Empty list → zero available cash (key is valid; wallet is empty).
    if cny is None and usd is None:
        cny = 0.0
    return ProbeResult(
        matched=True,
        provider="deepseek",
        source="deepseek:user_balance",
        evidence_kind="cash_balance",
        balance_usd=round(usd, 4) if usd is not None else "",
        balance_native=round(cny, 4) if cny is not None else "",
        currency="CNY" if cny is not None else "USD",
        detail={"balance_infos": infos, "totals": totals},
        alive=True,
    )


async def _probe_kimi(
    client: httpx.AsyncClient, credential: Credential, provider: str
) -> ProbeResult:
    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)
    if "api.moonshot.cn" not in endpoint.origin:
        return await _probe_models(client, credential, provider)
    response, payload = await _json_get(
        client,
        build_operation_url(endpoint, provider=provider, operation="balance"),
        credential,
    )
    data = payload.get("data") if payload else None
    if (
        response is None
        or response.status_code != 200
        or not isinstance(data, dict)
        or not _numeric(data.get("available_balance"))
    ):
        return ProbeResult()
    return ProbeResult(
        matched=True,
        provider="kimi",
        source="kimi:users_me_balance",
        evidence_kind="cash_balance",
        balance_native=float(data["available_balance"]),
        currency="CNY",
        detail={"data": data},
        alive=True,
    )


async def _probe_minimax(
    client: httpx.AsyncClient, credential: Credential, provider: str
) -> ProbeResult:
    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)
    response, payload = await _json_get(
        client,
        build_operation_url(endpoint, provider=provider, operation="quota"),
        credential,
    )
    if response is None or response.status_code != 200 or payload is None:
        return ProbeResult()
    base_resp = payload.get("base_resp")
    remains = payload.get("model_remains")
    if not isinstance(base_resp, dict) or base_resp.get("status_code") not in {0, "0"}:
        return ProbeResult()
    if not isinstance(remains, list):
        return ProbeResult()
    return ProbeResult(
        matched=True,
        provider="minimax",
        source="minimax:token_plan_remains",
        evidence_kind="quota",
        quota={"model_remains": remains},
        detail={"base_resp": base_resp},
        alive=True,
    )


async def _probe_cohere(
    client: httpx.AsyncClient, credential: Credential, _provider: str
) -> ProbeResult:
    if not is_http_header_value_safe(credential.apikey):
        return ProbeResult()
    try:
        response = await client.post(
            "https://api.cohere.com/v1/check-api-key", headers=_headers(credential)
        )
    except (httpx.HTTPError, UnicodeEncodeError, httpx.LocalProtocolError):
        return ProbeResult()
    try:
        payload = response.json()
    except ValueError:
        return ProbeResult()
    if (
        response.status_code != 200
        or not isinstance(payload, dict)
        or payload.get("valid") is not True
    ):
        return ProbeResult()
    identity = {
        field: payload[field]
        for field in ("organization_id", "owner_id")
        if isinstance(payload.get(field), str) and payload[field]
    }
    return ProbeResult(
        matched=True,
        provider="cohere",
        source="cohere:check_api_key",
        evidence_kind="identity" if identity else "liveness",
        identity=identity,
        alive=True,
        detail={"valid": True},
    )


async def _probe_together(
    client: httpx.AsyncClient, credential: Credential, _provider: str
) -> ProbeResult:
    response, payload = await _json_get(client, "https://api.together.ai/v1/whoami", credential)
    if response is None or response.status_code != 200 or payload is None:
        return ProbeResult()
    identity = {
        field: payload[field]
        for field in ("id", "name", "email", "project_id", "organization_id")
        if isinstance(payload.get(field), str) and payload[field]
    }
    if not identity:
        return ProbeResult()
    rate_limits = _rate_limit_headers(response)
    return ProbeResult(
        matched=True,
        provider="together",
        source="together:whoami",
        evidence_kind="quota" if rate_limits else "identity",
        quota={"rate_limits": rate_limits} if rate_limits else {},
        identity=identity,
        alive=True,
        detail={},
    )


async def _probe_replicate(
    client: httpx.AsyncClient, credential: Credential, _provider: str
) -> ProbeResult:
    response, payload = await _json_get(client, "https://api.replicate.com/v1/account", credential)
    if response is None or response.status_code != 200 or payload is None:
        return ProbeResult()
    identity = {
        field: payload[field]
        for field in ("type", "username", "name", "github_url")
        if isinstance(payload.get(field), str) and payload[field]
    }
    if not identity:
        return ProbeResult()
    return ProbeResult(
        matched=True,
        provider="replicate",
        source="replicate:account",
        evidence_kind="identity",
        identity=identity,
        account_type=str(payload.get("type") or ""),
        alive=True,
    )


def _rate_limit_headers(response: httpx.Response) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in response.headers.items()
        if key.lower().startswith(("x-ratelimit-", "ratelimit-"))
    }


async def _probe_models(
    client: httpx.AsyncClient, credential: Credential, provider: str
) -> ProbeResult:
    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)
    response, payload = await _json_get(
        client,
        build_operation_url(endpoint, provider=provider, operation="models"),
        credential,
    )
    if response is None:
        return ProbeResult()
    if response.status_code == 429:
        return ProbeResult(
            matched=True,
            provider=provider,
            source=f"{provider}:models",
            evidence_kind="liveness",
            alive=True,
            detail={"status_code": 429, "rate_limits": _rate_limit_headers(response)},
        )
    models = _model_ids(payload)
    if response.status_code != 200 or models is None:
        return ProbeResult()
    rate_limits = _rate_limit_headers(response)
    evidence_kind: EvidenceKind = "quota" if rate_limits else "liveness"
    entitlements = {"models": models} if provider == "ksyun" else {}
    if entitlements:
        evidence_kind = "entitlement"
    return ProbeResult(
        matched=True,
        provider=provider,
        source=f"{provider}:models",
        evidence_kind=evidence_kind,
        quota={"rate_limits": rate_limits} if rate_limits else {},
        entitlements=entitlements,
        alive=True,
        detail={"models": models[:100]},
    )


def _fireworks_tier(max_value: float, account_type: str) -> str:
    if account_type.upper() == "ENTERPRISE":
        return "enterprise"
    return {50.0: "tier1", 500.0: "tier2", 5000.0: "tier3", 50000.0: "tier4"}.get(max_value, "")


async def _probe_fireworks(
    client: httpx.AsyncClient, credential: Credential, _provider: str
) -> ProbeResult:
    response, payload = await _json_get(client, "https://api.fireworks.ai/v1/accounts", credential)
    accounts = payload.get("accounts") if payload else None
    if response is None or response.status_code != 200 or not isinstance(accounts, list):
        return ProbeResult()
    summaries: list[dict[str, Any]] = []
    matched_quota: dict[str, Any] = {}
    account_type = ""
    suspend_state = ""
    tier = ""
    for item in accounts:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"].strip("/")
        if not name.startswith("accounts/") or name.count("/") != 1:
            continue
        account_response, account = await _json_get(
            client, f"https://api.fireworks.ai/v1/{name}", credential
        )
        quota_response, quotas = await _json_get(
            client, f"https://api.fireworks.ai/v1/{name}/quotas", credential
        )
        if account_response is not None and account_response.status_code == 200 and account:
            account_type = str(account.get("accountType") or account_type)
            suspend_state = str(account.get("suspendState") or suspend_state)
        quota_rows = quotas.get("quotas") if quotas else None
        if (
            quota_response is None
            or quota_response.status_code != 200
            or not isinstance(quota_rows, list)
        ):
            continue
        for quota in quota_rows:
            if not isinstance(quota, dict) or quota.get("name") != "monthly-spend-usd":
                continue
            if not _numeric(quota.get("maxValue")):
                continue
            max_value = float(quota["maxValue"])
            tier = _fireworks_tier(max_value, account_type)
            matched_quota = dict(quota)
            summaries.append({"account": name, "quota": quota})
    if not matched_quota and not account_type:
        return ProbeResult()
    return ProbeResult(
        matched=True,
        provider="fireworks",
        source="fireworks:accounts_quotas",
        evidence_kind="quota" if matched_quota else "identity",
        tier=tier,
        account_type=account_type,
        quota=matched_quota,
        identity={"suspend_state": suspend_state} if suspend_state else {},
        alive=True,
        detail={"accounts": summaries},
    )


def _litellm_key_info_blob(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """LiteLLM key budget object: ``key_info`` or nested ``info`` (proxy default)."""
    if not isinstance(payload, dict):
        return None
    for field in ("key_info", "info"):
        blob = payload.get(field)
        if isinstance(blob, dict):
            return blob
    return None


async def _probe_litellm(
    client: httpx.AsyncClient, credential: Credential, endpoint: str
) -> ProbeResult:
    response, payload = await _json_get(
        client, f"{endpoint.rstrip('/')}/key/info", credential, params={"key": credential.apikey}
    )
    key_info = _litellm_key_info_blob(payload)
    if response is None or response.status_code != 200 or key_info is None:
        return ProbeResult()
    if payload is not None and (payload.get("success") is False or "error" in payload):
        return ProbeResult()
    budget_fields = ("spend", "max_budget", "max_budget_soft")
    has_budget_signal = any(_numeric(key_info.get(field)) for field in budget_fields)
    # Explicit null max_budget + models list is still a valid LiteLLM key_info
    # envelope (unlimited budget), but only when spend is numeric or present as 0.
    spend_raw = key_info.get("spend")
    has_spend = (
        _numeric(spend_raw)
        or spend_raw is None
        and ("max_budget" in key_info or "models" in key_info)
    )
    if not has_budget_signal and not (
        "max_budget" in key_info and isinstance(key_info.get("models"), list)
    ):
        return ProbeResult()
    if not has_spend and not has_budget_signal:
        return ProbeResult()
    spend = float(spend_raw) if _numeric(spend_raw) else 0.0
    maximum = key_info.get("max_budget")
    if not _numeric(maximum):
        soft = key_info.get("max_budget_soft")
        maximum = soft if _numeric(soft) else None
    models = key_info.get("models") if isinstance(key_info.get("models"), list) else []
    quota: dict[str, Any] = {"spend": spend}
    if _numeric(maximum):
        remaining = max(float(maximum) - spend, 0.0)
        quota["max_budget"] = float(maximum)
        quota["remaining"] = remaining
        return ProbeResult(
            matched=True,
            provider="litellm",
            source="litellm:key_info",
            evidence_kind="quota",
            balance_usd=round(remaining, 2),
            quota=quota,
            tier=str(key_info.get("tier") or ""),
            alive=True,
            detail={"models": models},
        )
    # max_budget=null → unlimited; do not invent balance=0.
    quota["max_budget"] = None
    quota["unlimited"] = True
    return ProbeResult(
        matched=True,
        provider="litellm",
        source="litellm:key_no_limit",
        evidence_kind="quota",
        balance_usd="N/A",
        quota=quota,
        usage={"spend": spend},
        tier=str(key_info.get("tier") or ""),
        alive=True,
        detail={
            "models": models,
            "note": "LiteLLM max_budget is null (unlimited); spend is cumulative usage",
        },
    )


async def _probe_gateway(
    client: httpx.AsyncClient, credential: Credential, endpoint: str
) -> ProbeResult:
    status_response, status = await _json_get(
        client, f"{endpoint.rstrip('/')}/api/status", credential
    )
    self_response, self_payload = await _json_get(
        client, f"{endpoint.rstrip('/')}/api/user/self", credential
    )
    status_data = status.get("data") if status else None
    user = self_payload.get("data") if self_payload else None
    status_signal = (
        status_response is not None
        and status_response.status_code == 200
        and status is not None
        and status.get("success") is True
        and isinstance(status_data, dict)
        and len(_NEWAPI_STATUS_FIELDS.intersection(status_data)) >= 3
    )
    self_signal = (
        self_response is not None
        and self_response.status_code == 200
        and self_payload is not None
        and self_payload.get("success") is True
        and isinstance(user, dict)
        and _numeric(user.get("quota"))
        and _numeric(user.get("used_quota"))
    )
    billing_response, subscription = await _json_get(
        client, f"{endpoint.rstrip('/')}/dashboard/billing/subscription", credential
    )
    billing_signal = (
        billing_response is not None
        and billing_response.status_code == 200
        and subscription is not None
        and subscription.get("object") == "billing_subscription"
        and _numeric(subscription.get("hard_limit_usd"))
    )
    oneapi_status_signal = (
        status_response is not None
        and status_response.status_code == 200
        and status is not None
        and status.get("success") is True
        and isinstance(status_data, dict)
        and isinstance(status_data.get("system_name"), str)
        and isinstance(status_data.get("version"), str)
        and not status_signal
    )
    if status_signal and (self_signal or billing_signal):
        quota: dict[str, Any] = {}
        usage: dict[str, Any] = {}
        if self_signal and isinstance(user, dict):
            quota = {"quota": user["quota"], "used_quota": user["used_quota"]}
        if billing_signal and subscription is not None:
            quota["hard_limit_usd"] = subscription["hard_limit_usd"]
            usage_response, usage_payload = await _json_get(
                client,
                f"{endpoint.rstrip('/')}/dashboard/billing/usage",
                credential,
                params={"start_date": "2024-01-01", "end_date": "2099-12-31"},
            )
            if (
                usage_response is not None
                and usage_response.status_code == 200
                and usage_payload is not None
                and usage_payload.get("object") == "list"
                and _numeric(usage_payload.get("total_usage"))
            ):
                usage = {"total_usage": usage_payload["total_usage"], "unit": "cents"}
        return ProbeResult(
            matched=True,
            provider="newapi",
            source="newapi:fingerprint",
            evidence_kind="quota",
            quota=quota,
            usage=usage,
            alive=True,
            detail={
                "signals": {"status": status_signal, "self": self_signal, "billing": billing_signal}
            },
        )
    if oneapi_status_signal and self_signal:
        return ProbeResult(
            matched=True,
            provider="oneapi",
            source="oneapi:fingerprint",
            evidence_kind="quota",
            quota={"quota": user["quota"], "used_quota": user["used_quota"]}
            if isinstance(user, dict)
            else {},
            alive=True,
            detail={"signals": {"status": True, "self": True}},
        )
    litellm = await _probe_litellm(client, credential, endpoint)
    if litellm.matched:
        return litellm
    return ProbeResult()


async def _probe_legacy_provider(
    client: httpx.AsyncClient,
    credential: Credential,
    provider: str,
) -> ProbeResult:
    from aipocket.services import balance as legacy

    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)
    base = endpoint.api_base
    legacy_result: dict[str, Any] = {}
    if provider == "openai":
        legacy_result = await legacy._probe_openai(client, credential)
    elif provider == "anthropic":
        legacy_result = await legacy._probe_anthropic(client, base, credential.apikey)
    elif provider == "openrouter":
        legacy_result = await legacy._probe_openrouter(
            client, base.removesuffix("/v1"), credential.apikey
        )
    elif provider == "qwen":
        legacy_result = await legacy._probe_dashscope(client, base, credential.apikey)
    elif provider == "siliconflow":
        legacy_result = await legacy._probe_siliconflow(client, endpoint.origin, credential.apikey)
    if not legacy_result:
        return ProbeResult()
    balance = legacy_result.get("balance_usd", "")
    evidence_kind: EvidenceKind = (
        "cash_balance"
        if isinstance(balance, int | float)
        else "quota"
        if legacy_result.get("tier") or legacy_result.get("rate_limit_profile")
        else "liveness"
    )
    return ProbeResult(
        matched=True,
        provider=provider,
        source=f"{provider}:{legacy_result.get('source') or 'provider_probe'}",
        evidence_kind=evidence_kind,
        balance_usd=balance,
        tier=str(legacy_result.get("tier") or ""),
        quota={
            key: value
            for key, value in legacy_result.items()
            if key in {"limit", "limit_remaining", "hard_limit_usd", "rate_limit_profile"}
        },
        usage={
            key: value
            for key, value in legacy_result.items()
            if key in {"usage", "used_usd", "spend_usd_30d"}
        },
        identity={
            key: value
            for key, value in legacy_result.items()
            if key in {"organization_id", "organization_name", "credential_kind"}
        },
        alive=legacy_result.get("alive"),
        detail=dict(legacy_result),
    )


_LEGACY_PROVIDER_PROBES = frozenset({"openai", "anthropic", "openrouter", "qwen", "siliconflow"})


_PROBES = {
    "deepseek": _probe_deepseek,
    "kimi": _probe_kimi,
    "minimax": _probe_minimax,
    "cohere": _probe_cohere,
    "together": _probe_together,
    "replicate": _probe_replicate,
    "fireworks": _probe_fireworks,
}


async def dispatch_probe(
    client: httpx.AsyncClient,
    result: ValidationResult,
) -> ProbeResult:
    credential = result.credential
    resolution = resolve_provider(apiurl=credential.apiurl, apikey=credential.apikey)
    provider = result.provider_info.validation_provider
    if provider in {"", "unknown", "ambiguous"}:
        provider = resolution.provider
    endpoint = canonicalize_endpoint(credential.apiurl, provider=provider)

    if provider in {"google", "gemini"}:
        return ProbeResult()
    if provider == "glm":
        passive = _probe_glm_passive(result)
        if passive.matched:
            return passive
    if provider == "longcat":
        return _longcat_liveness(result)
    if provider in {"azure_openai", "vertex"}:
        return ProbeResult(
            matched=result.is_authenticated,
            provider=provider,
            source=f"{provider}:validated_liveness",
            evidence_kind="liveness",
            alive=result.is_authenticated,
            detail={
                "models": result.provider_info.models_available,
                "validation_state": result.validation_state,
                "passive_error": result.error,
            },
        )
    if provider in _LEGACY_PROVIDER_PROBES:
        return await _probe_legacy_provider(client, credential, provider)
    specific = _PROBES.get(provider)
    if specific is not None:
        return await specific(client, credential, provider)
    if provider in _OFFICIAL_PROVIDERS:
        return await _probe_models(client, credential, provider)
    return await _probe_gateway(client, credential, endpoint.origin)


def apply_probe_result(result: ValidationResult, probe: ProbeResult) -> None:
    if not probe.matched:
        return
    observed_at = datetime.now(UTC).isoformat()
    provider_info = result.provider_info
    provider_info.validation_provider = probe.provider  # type: ignore[assignment]
    provider_info.provider = probe.provider  # type: ignore[assignment]
    if provider_info.credential_issuer in {"unknown", "gateway"}:
        provider_info.credential_issuer = probe.provider  # type: ignore[assignment]
    provider_info.evidence_source = probe.source
    provider_info.evidence_kind = probe.evidence_kind
    provider_info.evidence_observed_at = observed_at
    if probe.evidence_kind == "cash_balance":
        provider_info.balance_provider = probe.provider
    if probe.balance_usd != "":
        result.balance = str(probe.balance_usd)
    elif probe.balance_native != "":
        currency = (probe.currency or "").upper()
        # Avoid formatBalance() prepending "$" to CNY native cash.
        if currency == "CNY":
            result.balance = f"¥{probe.balance_native}"
        elif currency and currency != "USD":
            result.balance = f"{probe.balance_native} {currency}"
        else:
            result.balance = str(probe.balance_native)
    if probe.tier:
        result.tier = probe.tier
    result.gateway = probe.provider
    evidence = probe.model_dump(exclude={"matched"})
    evidence["observed_at"] = observed_at
    result.provider_evidence = evidence
