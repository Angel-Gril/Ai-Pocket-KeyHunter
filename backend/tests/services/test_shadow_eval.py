from __future__ import annotations

from aipocket.services.shadow_eval import (
    ShadowSample,
    evaluate_shadow,
    plan_with_shadow,
)

FIXTURE = (
    ShadowSample(
        sample_id="run-a",
        product_hint="dify",
        raw_hits=100,
        unique_targets=40,
        active_requests=200,
        final_verified=2,
        false_positives=5,
        known_finding_ids=("find-1", "find-2"),
    ),
    ShadowSample(
        sample_id="run-b",
        product_hint="litellm",
        raw_hits=80,
        unique_targets=30,
        active_requests=150,
        final_verified=1,
        false_positives=3,
        known_finding_ids=("find-3",),
    ),
)


def test_shadow_accepts_when_findings_retained_with_fewer_requests() -> None:
    report = evaluate_shadow(
        FIXTURE,
        new_metrics={
            "run-a": {
                "active_requests": 120,
                "final_verified": 2,
                "false_positives": 3,
                "known_finding_ids": ("find-1", "find-2"),
            },
            "run-b": {
                "active_requests": 100,
                "final_verified": 1,
                "false_positives": 2,
                "known_finding_ids": ("find-3",),
            },
        },
        shadow_mode=True,
    )
    assert report.accepted is True
    assert all(not d.production_changed for d in report.decisions)
    assert "shadow-mode-no-production-change" in report.reasons


def test_shadow_rejects_lost_findings_or_higher_false_positives() -> None:
    lost = evaluate_shadow(
        FIXTURE,
        new_metrics={
            "run-a": {
                "active_requests": 50,
                "final_verified": 1,
                "false_positives": 1,
                "known_finding_ids": ("find-1",),  # lost find-2
            },
            "run-b": {
                "active_requests": 50,
                "final_verified": 1,
                "false_positives": 1,
                "known_finding_ids": ("find-3",),
            },
        },
    )
    assert lost.accepted is False
    assert "lost-known-findings" in lost.reasons

    more_fp = evaluate_shadow(
        FIXTURE,
        new_metrics={
            "run-a": {
                "active_requests": 100,
                "final_verified": 2,
                "false_positives": 50,
                "known_finding_ids": ("find-1", "find-2"),
            },
            "run-b": {
                "active_requests": 100,
                "final_verified": 1,
                "false_positives": 1,
                "known_finding_ids": ("find-3",),
            },
        },
    )
    assert more_fp.accepted is False
    assert "false-positives-increased" in more_fp.reasons


def test_plan_with_shadow_keeps_production_selection() -> None:
    production = ("q-old-1", "q-old-2")
    candidate = ("q-new-1", "q-new-2", "q-new-3")
    effective, shadow = plan_with_shadow(
        production_selection=production,
        candidate_selection=candidate,
        shadow_mode=True,
    )
    assert effective == production
    assert shadow == candidate

    live, _ = plan_with_shadow(
        production_selection=production,
        candidate_selection=candidate,
        shadow_mode=False,
    )
    assert live == candidate
