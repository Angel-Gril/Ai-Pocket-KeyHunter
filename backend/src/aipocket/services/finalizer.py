from __future__ import annotations

import asyncio
from dataclasses import dataclass

from aipocket.core.models import ValidationResult

from .dedup import DedupStore
from .high_value_writer import try_save
from .honeypot import filter_honeypots


@dataclass(frozen=True, slots=True)
class FinalizedResults:
    final_verified: list[ValidationResult]
    rejected: list[ValidationResult]
    rate_limited_unconfirmed: list[ValidationResult]


async def save_final_high_value(result: ValidationResult) -> None:
    await asyncio.to_thread(try_save, result)


async def finalize_results(
    results: list[ValidationResult],
    *,
    dedup: DedupStore,
    no_auth_hosts: set[str],
    suspicious_hosts: set[str],
) -> FinalizedResults:
    """Apply explicit terminal verdicts before cache or high-value persistence."""
    filtered = filter_honeypots(
        results,
        no_auth_hosts=no_auth_hosts,
        suspicious_hosts=suspicious_hosts,
    )
    final_verified = [result for result in filtered if result.valid and not result.suspicious]
    rate_limited_unconfirmed = [
        result for result in filtered if result.valid and result.suspicious
    ]
    rejected = [result for result in filtered if not result.valid]

    for result in final_verified:
        await dedup.cache_valid(result)
        await save_final_high_value(result)
    for result in rejected:
        await dedup.mark_rejected(result.credential)
    for result in rate_limited_unconfirmed:
        await dedup.mark_transient(result.credential)

    return FinalizedResults(
        final_verified=final_verified,
        rejected=rejected,
        rate_limited_unconfirmed=rate_limited_unconfirmed,
    )
