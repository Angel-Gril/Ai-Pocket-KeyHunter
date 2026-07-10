from __future__ import annotations

from unittest.mock import AsyncMock

from aipocket.core.models import Credential, ValidationResult
from aipocket.services.finalizer import finalize_results


def _result(*, host: str, status_code: int = 200) -> ValidationResult:
    return ValidationResult(
        credential=Credential(
            apikey="sk-proj-example-not-a-real-secret",
            apiurl=f"https://{host}/v1",
            host=host,
        ),
        valid=True,
        status_code=status_code,
    )


async def test_no_auth_result_is_rejected_before_persistence(monkeypatch):
    result = _result(host="no-auth.example")
    dedup = AsyncMock()
    save = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", save)

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts={"no-auth.example"}, suspicious_hosts=set()
    )

    assert finalized.final_verified == []
    dedup.cache_valid.assert_not_awaited()
    dedup.mark_rejected.assert_awaited_once_with(result.credential)
    save.assert_not_awaited()


async def test_suspicious_429_remains_rate_limited_unconfirmed(monkeypatch):
    result = _result(host="limited.example", status_code=429)
    dedup = AsyncMock()
    save = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", save)

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts=set(), suspicious_hosts={"limited.example"}
    )

    assert finalized.rate_limited_unconfirmed == [result]
    dedup.mark_transient.assert_awaited_once_with(result.credential)
    dedup.cache_valid.assert_not_awaited()
    save.assert_not_awaited()


async def test_empty_run_does_not_inherit_previous_verdicts():
    finalized = await finalize_results(
        [], dedup=AsyncMock(), no_auth_hosts={"old.example"}, suspicious_hosts={"old.example"}
    )

    assert finalized.final_verified == []
    assert finalized.rejected == []
    assert finalized.rate_limited_unconfirmed == []


async def test_final_verified_result_is_cached_and_saved(monkeypatch):
    result = _result(host="verified.example")
    dedup = AsyncMock()
    save = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", save)

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts=set(), suspicious_hosts=set()
    )

    assert finalized.final_verified == [result]
    dedup.cache_valid.assert_awaited_once_with(result)
    save.assert_awaited_once_with(result)
