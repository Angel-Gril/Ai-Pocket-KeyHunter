"""ScanPolicy: full mode is discovery coverage only, not force revalidate."""

from __future__ import annotations

from aipocket.core.scan_policy import (
    policy_from_mode,
    policy_with_fresh_verification,
)


def test_incremental_defaults():
    p = policy_from_mode("incremental")
    assert p.discovery_scope == "incremental"
    assert p.verification_policy == "ttl"
    assert p.balance_policy == "ttl"
    assert not p.force_revalidate


def test_full_does_not_force_revalidate():
    p = policy_from_mode("full")
    assert p.discovery_scope == "full"
    assert p.verification_policy == "ttl"
    assert p.balance_policy == "ttl"
    assert not p.force_revalidate
    assert not p.force_balance


def test_explicit_fresh_verification():
    base = policy_from_mode("full")
    fresh = policy_with_fresh_verification(base)
    assert fresh.discovery_scope == "full"
    assert fresh.verification_policy == "fresh"
    assert fresh.force_revalidate
    assert fresh.force_balance
