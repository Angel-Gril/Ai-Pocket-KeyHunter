from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ShadowSample:
    """Redacted historical hit/result metadata for offline replay (no secrets)."""

    sample_id: str
    product_hint: str
    raw_hits: int
    unique_targets: int
    active_requests: int
    final_verified: int
    false_positives: int
    known_finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ShadowDecision:
    sample_id: str
    old_active_requests: int
    new_active_requests: int
    old_final_verified: int
    new_final_verified: int
    old_false_positives: int
    new_false_positives: int
    retained_findings: tuple[str, ...]
    production_changed: bool


@dataclass(frozen=True, slots=True)
class ShadowReport:
    decisions: tuple[ShadowDecision, ...]
    accepted: bool
    reasons: tuple[str, ...]


def evaluate_shadow(
    samples: tuple[ShadowSample, ...],
    *,
    # Predicted new-path metrics keyed by sample_id (still redacted counts only).
    new_metrics: dict[str, dict[str, Any]],
    shadow_mode: bool = True,
) -> ShadowReport:
    """Compare new logic against redacted historical baselines.

    Acceptance requires:
    - no fewer known final findings retained
    - fewer or equal active requests overall
    - no higher false-positive count overall

    In shadow mode, production output is never changed (``production_changed`` is False).
    """
    decisions: list[ShadowDecision] = []
    total_old_requests = 0
    total_new_requests = 0
    total_old_fp = 0
    total_new_fp = 0
    missing_findings = 0

    for sample in samples:
        predicted = new_metrics.get(sample.sample_id, {})
        new_requests = int(predicted.get("active_requests", sample.active_requests))
        new_verified = int(predicted.get("final_verified", sample.final_verified))
        new_fp = int(predicted.get("false_positives", sample.false_positives))
        retained = tuple(predicted.get("known_finding_ids", sample.known_finding_ids))
        # Known findings must be a superset of the historical set.
        if set(sample.known_finding_ids) - set(retained):
            missing_findings += 1
            new_verified = min(new_verified, sample.final_verified - 1)

        decisions.append(
            ShadowDecision(
                sample_id=sample.sample_id,
                old_active_requests=sample.active_requests,
                new_active_requests=new_requests,
                old_final_verified=sample.final_verified,
                new_final_verified=new_verified,
                old_false_positives=sample.false_positives,
                new_false_positives=new_fp,
                retained_findings=retained,
                production_changed=not shadow_mode,
            )
        )
        total_old_requests += sample.active_requests
        total_new_requests += new_requests
        total_old_fp += sample.false_positives
        total_new_fp += new_fp

    reasons: list[str] = []
    retained_ok = missing_findings == 0 and all(
        d.new_final_verified >= d.old_final_verified for d in decisions
    )
    requests_ok = total_new_requests <= total_old_requests
    fp_ok = total_new_fp <= total_old_fp
    if not retained_ok:
        reasons.append("lost-known-findings")
    if not requests_ok:
        reasons.append("active-requests-increased")
    if not fp_ok:
        reasons.append("false-positives-increased")
    if shadow_mode:
        reasons.append("shadow-mode-no-production-change")

    accepted = retained_ok and requests_ok and fp_ok
    return ShadowReport(
        decisions=tuple(decisions),
        accepted=accepted,
        reasons=tuple(reasons),
    )


def plan_with_shadow(
    *,
    production_selection: tuple[str, ...],
    candidate_selection: tuple[str, ...],
    shadow_mode: bool = True,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (effective_selection, shadow_candidate_selection).

    When shadow_mode is True, production keeps the old selection and the new
    selection is only recorded for comparison.
    """
    if shadow_mode:
        return production_selection, candidate_selection
    return candidate_selection, candidate_selection
