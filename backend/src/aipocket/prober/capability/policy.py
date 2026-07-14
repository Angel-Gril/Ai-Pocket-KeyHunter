"""Risk policy for selecting which vuln-class nodes may run."""

from __future__ import annotations

from dataclasses import dataclass, field

from aipocket.core.config import settings

from .types import RiskLevel, VulnClass

_ALL_CLASSES = frozenset(VulnClass)


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    """Controls which vuln classes and risk levels are allowed.

    Defaults: L0 always; L1 when intrusive_checks (authorized_scope empty =
    all targets; non-empty = origin allowlist); L2/L3 need explicit flags.
    """

    enabled_classes: frozenset[VulnClass] = field(default_factory=lambda: frozenset(_ALL_CLASSES))
    max_risk: RiskLevel = RiskLevel.L1
    intrusive_checks: bool = False
    # Empty tuple = no origin restriction when intrusive_checks is True.
    authorized_scope: tuple[str, ...] = ()
    rce_enabled: bool = False
    sqli_enabled: bool = False
    ssrf_enabled: bool = False
    product_allowlist: frozenset[str] = field(default_factory=frozenset)

    def class_enabled(self, vuln_class: VulnClass) -> bool:
        if vuln_class not in self.enabled_classes:
            return False
        if vuln_class is VulnClass.RCE:
            return self.rce_enabled
        if vuln_class is VulnClass.SQLI:
            return self.sqli_enabled
        if vuln_class is VulnClass.SSRF:
            return self.ssrf_enabled
        return True


def _parse_vuln_classes(raw: str) -> frozenset[VulnClass]:
    raw = (raw or "").strip()
    if not raw or raw.lower() in {"*", "all"}:
        return frozenset(_ALL_CLASSES)
    out: set[VulnClass] = set()
    for part in raw.split(","):
        token = part.strip().lower()
        if not token:
            continue
        try:
            out.add(VulnClass(token))
        except ValueError:
            continue
    return frozenset(out) if out else frozenset(_ALL_CLASSES)


def policy_from_settings(
    *,
    intrusive_checks: bool | None = None,
    authorized_scope: tuple[str, ...] | None = None,
) -> RiskPolicy:
    """Build a RiskPolicy from global settings (with optional overrides)."""
    max_risk_raw = getattr(settings, "probe_max_risk", 1)
    try:
        max_risk = RiskLevel(int(max_risk_raw))
    except (TypeError, ValueError):
        max_risk = RiskLevel.L1

    return RiskPolicy(
        enabled_classes=_parse_vuln_classes(getattr(settings, "probe_vuln_classes", "*")),
        max_risk=max_risk,
        intrusive_checks=(
            settings.intrusive_checks if intrusive_checks is None else intrusive_checks
        ),
        authorized_scope=(
            settings.authorized_probe_scope_list if authorized_scope is None else authorized_scope
        ),
        rce_enabled=bool(getattr(settings, "probe_rce_enabled", False)),
        sqli_enabled=bool(getattr(settings, "probe_sqli_enabled", False)),
        ssrf_enabled=bool(getattr(settings, "probe_ssrf_enabled", False)),
    )
