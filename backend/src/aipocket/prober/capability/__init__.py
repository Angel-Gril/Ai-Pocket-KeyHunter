"""Vuln-class probe capability layer.

Products declare audited :class:`ProbeSpec` nodes; the planner filters by
:class:`RiskPolicy`; engines execute by vuln class; the executor handles
dependencies, budget, and failure isolation.
"""

from __future__ import annotations

from .executor import run_product_plan
from .policy import RiskPolicy, policy_from_settings
from .registry import register_specs, specs_for
from .spec import ProbeSpec
from .types import (
    Finding,
    NodeOutcome,
    NodeStatus,
    ProbeContext,
    ProbeResult,
    RiskLevel,
    VulnClass,
)

__all__ = [
    "Finding",
    "NodeOutcome",
    "NodeStatus",
    "ProbeContext",
    "ProbeResult",
    "ProbeSpec",
    "RiskLevel",
    "RiskPolicy",
    "VulnClass",
    "policy_from_settings",
    "register_specs",
    "run_product_plan",
    "specs_for",
]
