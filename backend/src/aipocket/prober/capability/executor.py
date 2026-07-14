"""Execute a planned list of ProbeSpecs with dependency + failure isolation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..budget import BudgetExhausted
from ..engines import run_engine
from .planner import plan_specs
from .policy import RiskPolicy, policy_from_settings
from .types import NodeOutcome, NodeStatus, ProbeContext, ProbeResult, VulnClass

if TYPE_CHECKING:
    from ..base import Prober
    from .spec import ProbeSpec

log = logging.getLogger(__name__)


async def run_product_plan(
    prober: Prober,
    hit: dict[str, Any],
    specs: list[ProbeSpec],
    *,
    policy: RiskPolicy | None = None,
) -> ProbeResult:
    """Plan + execute product Specs; return credentials + findings + outcomes.

    Single-node failures never abort sibling nodes. Budget exhaustion stops
    remaining nodes with SKIPPED_BUDGET.
    """
    product = prober.product_name
    if policy is None:
        policy = policy_from_settings(
            intrusive_checks=prober._intrusive_checks,
            authorized_scope=tuple(prober._authorized_scope),
        )

    advisory_raw = hit.get("_advisory_ids") or hit.get("advisory_ids") or ()
    advisory_ids = tuple(str(a) for a in advisory_raw if a)

    planned = plan_specs(
        product,
        specs,
        hit=hit,
        policy=policy,
        prober=prober,
        advisory_ids=advisory_ids,
    )

    ctx = ProbeContext(hit=hit, product=product, advisory_ids=advisory_ids)
    result = ProbeResult()
    completed_ids: set[str] = set()
    failed_or_skipped: set[str] = set()

    # Specs that didn't make the plan (gated) — record for observability
    planned_ids = {s.id for s in planned}
    for spec in specs:
        if spec.id not in planned_ids:
            status = NodeStatus.SKIPPED_GATE
            reason = "risk gate or class disabled"
            if not policy.class_enabled(spec.vuln_class):
                status = NodeStatus.SKIPPED_CLASS
                reason = f"class {spec.vuln_class} disabled"
            result.node_outcomes.append(
                NodeOutcome(
                    spec_id=spec.id,
                    vuln_class=spec.vuln_class,
                    risk_level=spec.risk_level,
                    status=status,
                    reason=reason,
                )
            )

    # Two-pass style: process in order; defer auth-required until session exists
    pending: list[ProbeSpec] = list(planned)
    safety = 0
    while pending and safety < len(planned) + 5:
        safety += 1
        progress = False
        next_pending: list[ProbeSpec] = []
        for spec in pending:
            # Dependencies
            deps_ok = True
            for dep in spec.depends_on:
                if dep in failed_or_skipped:
                    result.node_outcomes.append(
                        NodeOutcome(
                            spec_id=spec.id,
                            vuln_class=spec.vuln_class,
                            risk_level=spec.risk_level,
                            status=NodeStatus.SKIPPED_DEPENDENCY,
                            reason=f"dependency {dep} failed/skipped",
                        )
                    )
                    failed_or_skipped.add(spec.id)
                    deps_ok = False
                    progress = True
                    break
                if dep not in completed_ids:
                    deps_ok = False
                    next_pending.append(spec)
                    break
            if not deps_ok:
                continue

            if spec.requires_auth and not (ctx.session or ctx.auth_headers):
                # If weak_password already finished without session, skip
                weak_done = any(
                    s.vuln_class is VulnClass.WEAK_PASSWORD
                    and s.id in (completed_ids | failed_or_skipped)
                    for s in planned
                )
                if weak_done or not any(s.vuln_class is VulnClass.WEAK_PASSWORD for s in planned):
                    result.node_outcomes.append(
                        NodeOutcome(
                            spec_id=spec.id,
                            vuln_class=spec.vuln_class,
                            risk_level=spec.risk_level,
                            status=NodeStatus.SKIPPED_NO_AUTH,
                            reason="no session",
                        )
                    )
                    failed_or_skipped.add(spec.id)
                    progress = True
                    continue
                next_pending.append(spec)
                continue

            # Budget
            remaining = prober.budget_remaining
            if remaining is not None and remaining <= 0:
                result.node_outcomes.append(
                    NodeOutcome(
                        spec_id=spec.id,
                        vuln_class=spec.vuln_class,
                        risk_level=spec.risk_level,
                        status=NodeStatus.SKIPPED_BUDGET,
                        reason="budget exhausted",
                    )
                )
                failed_or_skipped.add(spec.id)
                for rest in pending:
                    if rest.id != spec.id and rest.id not in completed_ids | failed_or_skipped:
                        result.node_outcomes.append(
                            NodeOutcome(
                                spec_id=rest.id,
                                vuln_class=rest.vuln_class,
                                risk_level=rest.risk_level,
                                status=NodeStatus.SKIPPED_BUDGET,
                                reason="budget exhausted",
                            )
                        )
                        failed_or_skipped.add(rest.id)
                pending = []
                progress = True
                break

            try:
                engine_result = await run_engine(prober, ctx, spec)
                result.credentials.extend(engine_result.credentials)
                result.findings.extend(engine_result.findings)
                result.node_outcomes.append(
                    NodeOutcome(
                        spec_id=spec.id,
                        vuln_class=spec.vuln_class,
                        risk_level=spec.risk_level,
                        status=NodeStatus.EXECUTED,
                        requests_used=engine_result.requests_used,
                        reason=engine_result.reason,
                        credentials_found=len(engine_result.credentials),
                    )
                )
                completed_ids.add(spec.id)
                progress = True
            except BudgetExhausted:
                result.node_outcomes.append(
                    NodeOutcome(
                        spec_id=spec.id,
                        vuln_class=spec.vuln_class,
                        risk_level=spec.risk_level,
                        status=NodeStatus.SKIPPED_BUDGET,
                        reason="budget exhausted mid-node",
                    )
                )
                failed_or_skipped.add(spec.id)
                pending = []
                progress = True
                break
            except Exception as exc:  # noqa: BLE001 — isolate node failures
                log.debug("probe node %s failed: %s", spec.id, type(exc).__name__)
                result.node_outcomes.append(
                    NodeOutcome(
                        spec_id=spec.id,
                        vuln_class=spec.vuln_class,
                        risk_level=spec.risk_level,
                        status=NodeStatus.FAILED,
                        reason=type(exc).__name__,
                    )
                )
                failed_or_skipped.add(spec.id)
                progress = True

        pending = next_pending
        if not progress:
            for spec in pending:
                result.node_outcomes.append(
                    NodeOutcome(
                        spec_id=spec.id,
                        vuln_class=spec.vuln_class,
                        risk_level=spec.risk_level,
                        status=NodeStatus.SKIPPED_DEPENDENCY,
                        reason="unresolved dependency",
                    )
                )
                failed_or_skipped.add(spec.id)
            break

    return result
