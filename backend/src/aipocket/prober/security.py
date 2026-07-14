from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .capability.policy import RiskPolicy
    from .capability.spec import ProbeSpec

Origin = tuple[str, str, int]


def normalized_origin(url: str) -> Origin | None:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    effective_port = port if port is not None else {"http": 80, "https": 443}[scheme]
    return scheme, hostname.lower(), effective_port


def scope_authorizes_origin(scope: str, origin: Origin) -> bool:
    try:
        parsed = urlsplit(scope)
    except ValueError:
        return False
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False
    return normalized_origin(scope) == origin


def origin_in_scope(
    origin: Origin | None, authorized_scope: tuple[str, ...] | frozenset[str]
) -> bool:
    if origin is None:
        return False
    return any(scope_authorizes_origin(scope, origin) for scope in authorized_scope)


def scope_permits(
    origin: Origin | None, authorized_scope: tuple[str, ...] | frozenset[str]
) -> bool:
    """Whether *origin* may receive intrusive probes under *authorized_scope*.

    - Empty scope → unrestricted (all origins allowed). Use this for broad
      weak-password / L1 sweeps when ``INTRUSIVE_CHECKS=true``.
    - Non-empty scope → origin must exactly match one listed origin.
    """
    if not authorized_scope:
        return True
    return origin_in_scope(origin, authorized_scope)


def allows(spec: ProbeSpec, origin: Origin | None, policy: RiskPolicy) -> bool:
    """Return True when *spec* may run against *origin* under *policy*.

    Risk tiers:
      L0 — always (passive unauth reads)
      L1 — intrusive_checks; optional origin allowlist (empty = all targets)
      L2 — class enable flag + intrusive_checks + optional scope
      L3 — rce_enabled + intrusive_checks + optional scope
    """
    from .capability.types import RiskLevel, VulnClass

    if not policy.class_enabled(spec.vuln_class):
        return False
    if int(spec.risk_level) > int(policy.max_risk):
        return False

    if spec.risk_level is RiskLevel.L0:
        return True

    # L1+ require intrusive opt-in. Scope is optional: empty = unrestricted.
    if not policy.intrusive_checks:
        return False
    if not scope_permits(origin, policy.authorized_scope):
        return False

    if spec.risk_level is RiskLevel.L1:
        return True

    if spec.risk_level is RiskLevel.L2:
        if spec.vuln_class is VulnClass.SSRF:
            return policy.ssrf_enabled
        if spec.vuln_class is VulnClass.SQLI:
            return policy.sqli_enabled
        return policy.ssrf_enabled or policy.sqli_enabled

    # L3 RCE
    return policy.rce_enabled
