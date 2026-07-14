"""Vuln-class execution engines (product-agnostic loops)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..capability.types import VulnClass
from .idor import run_idor
from .rce import run_rce
from .sqli import run_sqli
from .ssrf import run_ssrf
from .unauth_read import run_unauth_read
from .weak_password import run_weak_password

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext
    from .common import EngineResult

_ENGINES = {
    VulnClass.UNAUTH_READ: run_unauth_read,
    VulnClass.WEAK_PASSWORD: run_weak_password,
    VulnClass.IDOR: run_idor,
    VulnClass.SSRF: run_ssrf,
    VulnClass.SQLI: run_sqli,
    VulnClass.RCE: run_rce,
}


async def run_engine(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    runner = _ENGINES.get(spec.vuln_class)
    if runner is None:
        from .common import EngineResult

        return EngineResult(reason=f"no engine for {spec.vuln_class}")
    return await runner(prober, ctx, spec)


__all__ = ["run_engine"]
