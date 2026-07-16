from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict


class QueryFunnel(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_hits: int = 0
    unique_targets: int = 0
    # Compat: validation credential count (not physical HTTP). Prefer
    # total_active_http_requests as the KPI denominator (metrics v3).
    active_requests: int = 0
    candidates: int = 0
    prefilter_survivors: int = 0
    auth_confirmed: int = 0
    final_verified: int = 0
    noauth_rejected: int = 0
    query_credits: int = 0
    # Physical HTTP attempts attributed to this query (ledger-backed).
    total_active_http_requests: int = 0


class QueryMetric(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    query: str
    funnel: QueryFunnel
    attribution_version: int = 2
    # v3 fields (empty for historical v2 rows)
    query_id: str = ""
    lane: str = ""
    pack_id: str = ""


ErrorClass = Literal[
    "none",
    "auth",
    "rate_limit",
    "timeout",
    "network",
    "tls",
    "parse",
    "protocol",
    "provider_conflict",
    "unsupported",
    "no_auth",
    "internal",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class ExtractionMethodAggregate:
    method: Literal["regex", "prober", "gpt"]
    count: int


@dataclass(frozen=True, slots=True)
class ValidationOutcomeAggregate:
    source: str
    query: str
    provider: str
    validation_state: str
    error_class: ErrorClass
    status_code: int | None
    count: int


def classify_error(error: str, validation_state: str, status_code: int | None) -> ErrorClass:
    text = error.lower()
    if validation_state == "final_verified":
        return "none"
    if validation_state == "auth_rejected" or status_code in {401, 403}:
        return "auth"
    if validation_state == "rate_limited_unconfirmed" or status_code == 429:
        return "rate_limit"
    if validation_state == "provider_conflict":
        return "provider_conflict"
    if validation_state == "unsupported_context":
        return "unsupported"
    if validation_state == "no_auth_endpoint":
        return "no_auth"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "tls" in text or "ssl" in text or "certificate" in text:
        return "tls"
    if "json" in text or "parse" in text or "decode" in text:
        return "parse"
    if "network" in text or "connect" in text or "dns" in text:
        return "network"
    if "protocol" in text or "invalid response" in text:
        return "protocol"
    if validation_state == "transient_error" and text:
        return "internal"
    return "unknown"


@dataclass(frozen=True, slots=True)
class QueryUsage:
    query: str
    credits: int = 0
    query_id: str = ""
    lane: str = ""
    pack_id: str = ""
