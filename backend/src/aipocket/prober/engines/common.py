"""Shared helpers for vuln-class engines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aipocket.core.models import Credential

from ..capability.types import Finding, VulnClass


@dataclass(slots=True)
class EngineResult:
    credentials: list[Credential] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    requests_used: int = 0
    reason: str = ""


def make_finding(
    *,
    vuln_class: VulnClass,
    product: str,
    target_origin: str,
    spec_id: str,
    cve_ids: tuple[str, ...],
    confirmed: bool,
    summary: str,
    severity: str = "medium",
    evidence: dict[str, Any] | None = None,
    credentials: list[Credential] | None = None,
) -> Finding:
    return Finding(
        vuln_class=vuln_class,
        product=product,
        target_origin=target_origin,
        spec_id=spec_id,
        cve_ids=cve_ids,
        confirmed=confirmed,
        severity=severity,
        summary=summary,
        evidence=evidence or {},
        credentials=tuple(credentials or ()),
    )


def format_path(template: str, **kwargs: Any) -> str:
    try:
        return template.format(**kwargs)
    except (KeyError, ValueError):
        return template
