"""Map external scan mode to independent discovery/verification freshness policies.

``mode=full`` means discovery coverage only — it does **not** force re-validation
of every cached credential. Use explicit future flags for ``verification_policy=fresh``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from aipocket.core.models import ScanMode

DiscoveryScope = Literal["full", "incremental"]
VerificationPolicy = Literal["ttl", "fresh"]
IntrusivePolicy = Literal["changed_spec", "always", "ttl"]
BalancePolicy = Literal["ttl", "fresh"]


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    discovery_scope: DiscoveryScope
    verification_policy: VerificationPolicy
    intrusive_policy: IntrusivePolicy
    balance_policy: BalancePolicy

    @property
    def skip_host_dedup(self) -> bool:
        """When discovery is full, host probe/GPT cache is still TTL-gated.

        Full mode expands discovery budgets but does not force revalidation.
        """
        return False

    @property
    def force_revalidate(self) -> bool:
        return self.verification_policy == "fresh"

    @property
    def force_balance(self) -> bool:
        return self.balance_policy == "fresh"


def policy_from_mode(mode: ScanMode) -> ScanPolicy:
    """Map CLI/API ``full|incremental`` to a ScanPolicy.

    Both modes currently use TTL verification/balance. ``full`` only widens
    discovery (unlimited FOFA/Shodan budgets upstream).
    """
    if mode == "full":
        return ScanPolicy(
            discovery_scope="full",
            verification_policy="ttl",
            intrusive_policy="ttl",
            balance_policy="ttl",
        )
    return ScanPolicy(
        discovery_scope="incremental",
        verification_policy="ttl",
        intrusive_policy="ttl",
        balance_policy="ttl",
    )


def policy_with_fresh_verification(base: ScanPolicy) -> ScanPolicy:
    """Helper for future explicit revalidate flags."""
    return ScanPolicy(
        discovery_scope=base.discovery_scope,
        verification_policy="fresh",
        intrusive_policy=base.intrusive_policy,
        balance_policy="fresh",
    )
