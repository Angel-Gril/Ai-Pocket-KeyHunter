"""ProbeSpec — audited, product-declared attack-surface declaration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .types import RiskLevel, VulnClass


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    """A single audited probe node for a product.

    ``entry`` carries engine-specific parameters (paths, login body shape,
    IDOR object templates, fixed SSRF/SQLi/RCE payloads). Only reviewed Specs
    are executable — natural-language CVE text never becomes a payload.
    """

    id: str
    product: str
    vuln_class: VulnClass
    risk_level: RiskLevel
    cve_ids: tuple[str, ...] = ()
    requires_auth: bool = False
    depends_on: tuple[str, ...] = ()
    entry: dict[str, Any] = field(default_factory=dict)
    success: dict[str, Any] = field(default_factory=dict)
    extract: str = "default"
    max_requests: int = 5
