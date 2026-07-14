"""Select and order ProbeSpecs for a target under a RiskPolicy."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..security import allows, normalized_origin
from .policy import RiskPolicy
from .spec import ProbeSpec
from .types import RiskLevel, VulnClass

if TYPE_CHECKING:
    from ..base import Prober

# Execution order: cheap L0 first, then session acquisition, then higher risk.
_CLASS_ORDER = {
    VulnClass.UNAUTH_READ: 0,
    VulnClass.WEAK_PASSWORD: 1,
    VulnClass.IDOR: 2,
    VulnClass.SSRF: 3,
    VulnClass.SQLI: 4,
    VulnClass.RCE: 5,
}


def plan_specs(
    product: str,
    specs: list[ProbeSpec],
    *,
    hit: dict[str, Any],
    policy: RiskPolicy,
    prober: Prober,
    advisory_ids: tuple[str, ...] = (),
) -> list[ProbeSpec]:
    """Filter specs by risk gate and sort by phase / CVE match weight."""
    origin = normalized_origin(prober._url(hit))
    advisory_set = {a.upper() for a in advisory_ids if a}
    selected: list[tuple[int, int, ProbeSpec]] = []

    for spec in specs:
        if spec.product and spec.product.lower().replace("_", "-") != product.lower().replace(
            "_", "-"
        ):
            continue
        if not policy.class_enabled(spec.vuln_class):
            continue
        if int(spec.risk_level) > int(policy.max_risk):
            continue
        if not allows(spec, origin, policy):
            continue
        cve_boost = 0
        if advisory_set and any(c.upper() in advisory_set for c in spec.cve_ids):
            cve_boost = -1  # lower sort key = earlier
        phase = _CLASS_ORDER.get(spec.vuln_class, 9)
        selected.append((phase, cve_boost, spec))

    selected.sort(key=lambda item: (item[0], item[1], item[2].id))
    return [spec for _, _, spec in selected]


def risk_for_class(vuln_class: VulnClass) -> RiskLevel:
    if vuln_class is VulnClass.UNAUTH_READ:
        return RiskLevel.L0
    if vuln_class in (VulnClass.WEAK_PASSWORD, VulnClass.IDOR):
        return RiskLevel.L1
    if vuln_class in (VulnClass.SSRF, VulnClass.SQLI):
        return RiskLevel.L2
    return RiskLevel.L3
