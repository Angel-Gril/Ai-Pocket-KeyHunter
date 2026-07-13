from __future__ import annotations

import asyncio
from dataclasses import dataclass

from aipocket.core.models import ValidationResult
from aipocket.core.validation_state import (
    AUTHENTICATED_STATES,
    FAILURE_STATES,
    apply_state,
    is_quarantined,
)

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


def _promote_to_final(result: ValidationResult) -> ValidationResult:
    """Terminal success gate — only authenticated, non-quarantined results."""
    if result.validation_state == "final_verified":
        result.valid = True
        return result
    try:
        apply_state(result, "final_verified")
    except ValueError:
        # Legacy callers that only set valid=True still land on final after filters.
        result.validation_state = "final_verified"
        result.valid = True
        result.suspicious = False
    return result


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

    final_verified: list[ValidationResult] = []
    rate_limited_unconfirmed: list[ValidationResult] = []
    rejected: list[ValidationResult] = []

    for result in filtered:
        state = result.validation_state
        if state == "rate_limited_unconfirmed" or is_quarantined(result):
            if state != "rate_limited_unconfirmed":
                try:
                    apply_state(result, "rate_limited_unconfirmed")
                except ValueError:
                    result.validation_state = "rate_limited_unconfirmed"
                    result.suspicious = True
                    result.valid = True
            rate_limited_unconfirmed.append(result)
            continue

        if state in AUTHENTICATED_STATES or (result.valid and not result.suspicious):
            final_verified.append(_promote_to_final(result))
            continue

        if state in FAILURE_STATES or not result.valid:
            rejected.append(result)
            continue

        rejected.append(result)

    # Rejected/transient outcomes are marked here (they carry no balance data).
    # Caching + high-value persistence of the final-verified set is deferred to
    # the scanner via :func:`commit_final_results` so it runs AFTER balance
    # enrichment and the saved/cached record carries the enriched balance.
    for result in rejected:
        outcome = "transient" if result.validation_state == "transient_error" else "rejected"
        await dedup.mark_failure(result.credential, outcome)
    for result in rate_limited_unconfirmed:
        await dedup.mark_failure(result.credential, "transient")

    return FinalizedResults(
        final_verified=final_verified,
        rejected=rejected,
        rate_limited_unconfirmed=rate_limited_unconfirmed,
    )


async def commit_final_results(results: list[ValidationResult], *, dedup: DedupStore) -> None:
    """Cache + persist final-verified results. Call AFTER balance enrichment.

    Kept separate from :func:`finalize_results` so the cached ValidationResult
    and the high-value record both include balance/tier evidence rather than the
    pre-enrichment snapshot.
    """
    for result in results:
        await dedup.cache_valid(result)
        await save_final_high_value(result)
