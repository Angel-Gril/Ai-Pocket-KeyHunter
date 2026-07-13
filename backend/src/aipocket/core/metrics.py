from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict


class QueryFunnel(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_hits: int = 0
    unique_targets: int = 0
    active_requests: int = 0
    candidates: int = 0
    prefilter_survivors: int = 0
    auth_confirmed: int = 0
    final_verified: int = 0
    noauth_rejected: int = 0
    query_credits: int = 0


class QueryMetric(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    query: str
    funnel: QueryFunnel
    attribution_version: int = 2


@dataclass(frozen=True, slots=True)
class QueryUsage:
    query: str
    credits: int = 0
