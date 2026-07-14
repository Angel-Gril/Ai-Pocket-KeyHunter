"""Shared types for the vuln-class probe capability model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from aipocket.core.models import Credential


class VulnClass(StrEnum):
    UNAUTH_READ = "unauth_read"
    WEAK_PASSWORD = "weak_password"
    IDOR = "idor"
    SSRF = "ssrf"
    SQLI = "sqli"
    RCE = "rce"


class RiskLevel(IntEnum):
    """Risk tiers for probe steps.

    L0 — passive unauth reads (default on)
    L1 — weak password, read-only IDOR (needs intrusive; scope optional)
    L2 — SSRF / SQLi read proofs (explicit enable + scope)
    L3 — RCE minimal proof (default off, explicit enable + scope)
    """

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3


class NodeStatus(StrEnum):
    EXECUTED = "executed"
    SKIPPED_GATE = "skipped_gate"
    SKIPPED_BUDGET = "skipped_budget"
    SKIPPED_NO_AUTH = "skipped_no_auth"
    SKIPPED_DEPENDENCY = "skipped_dependency"
    SKIPPED_CLASS = "skipped_class"
    FAILED = "failed"


@dataclass(slots=True)
class ProbeContext:
    """Mutable per-target state shared across probe nodes."""

    hit: dict[str, Any]
    product: str
    session: str | None = None
    auth_headers: dict[str, str] = field(default_factory=dict)
    object_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    advisory_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """Evidence that a vulnerability class is present (credential optional)."""

    vuln_class: VulnClass
    product: str
    target_origin: str
    spec_id: str
    cve_ids: tuple[str, ...]
    confirmed: bool
    severity: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    credentials: tuple[Credential, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeOutcome:
    spec_id: str
    vuln_class: VulnClass
    risk_level: RiskLevel
    status: NodeStatus
    requests_used: int = 0
    reason: str = ""
    credentials_found: int = 0


@dataclass(slots=True)
class ProbeResult:
    credentials: list[Credential] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    node_outcomes: list[NodeOutcome] = field(default_factory=list)
