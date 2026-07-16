from __future__ import annotations

from unittest.mock import AsyncMock

from aipocket.core.models import Credential, ValidationResult
from aipocket.services.finalizer import commit_final_results, finalize_results


def _result(*, host: str, status_code: int = 200) -> ValidationResult:
    return ValidationResult(
        credential=Credential(
            apikey="sk-proj-example-not-a-real-secret",
            apiurl=f"https://{host}/v1",
            host=host,
        ),
        valid=True,
        validation_state="authentication_confirmed",
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
    dedup.mark_failure.assert_awaited_once_with(result.credential, "rejected")
    save.assert_not_awaited()

    # commit runs only over final_verified — nothing to persist here.
    await commit_final_results(finalized.final_verified, dedup=dedup)
    dedup.cache_valid.assert_not_awaited()
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
    dedup.mark_failure.assert_awaited_once_with(result.credential, "transient")
    dedup.cache_valid.assert_not_awaited()
    save.assert_not_awaited()


async def test_transient_error_uses_transient_cache_outcome() -> None:
    result = _result(host="timeout.example")
    result.valid = False
    result.validation_state = "transient_error"
    dedup = AsyncMock()

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts=set(), suspicious_hosts=set()
    )

    assert finalized.rejected == [result]
    dedup.mark_failure.assert_awaited_once_with(result.credential, "transient")


async def test_empty_run_does_not_inherit_previous_verdicts():
    finalized = await finalize_results(
        [], dedup=AsyncMock(), no_auth_hosts={"old.example"}, suspicious_hosts={"old.example"}
    )

    assert finalized.final_verified == []
    assert finalized.rejected == []
    assert finalized.rate_limited_unconfirmed == []


async def test_final_verified_result_is_cached_and_saved(monkeypatch):
    result = _result(host="verified.example")
    # Authenticated state required for promotion (default discovered is not enough
    # once finalize_results checks valid+state more carefully).
    result.validation_state = "authentication_confirmed"
    dedup = AsyncMock()
    save = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", save)

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts=set(), suspicious_hosts=set()
    )

    # finalize_results promotes to final but defers caching/persistence so they
    # run after balance enrichment.
    assert finalized.final_verified == [result]
    dedup.cache_valid.assert_not_awaited()
    save.assert_not_awaited()

    # commit_final_results (called by the scanner post-balance) caches + saves.
    await commit_final_results(finalized.final_verified, dedup=dedup)
    dedup.cache_valid.assert_awaited_once_with(result)
    save.assert_awaited_once_with(result)


async def test_honeypot_error_not_repromoted_from_authenticated_state(monkeypatch):
    """Regression: filter_honeypots sets valid=False+error but leaves auth state.

    Prod bug: 2439 honeypot rejections were re-promoted to final_verified because
    AUTHENTICATED_STATES was checked before valid=False.
    """
    result = _result(host="bait.example")
    result.validation_state = "inference_verified"
    result.valid = True
    result.response_snippet = "hi" + ("\u200b" * 20)  # steganography bait
    dedup = AsyncMock()
    save = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", save)

    finalized = await finalize_results(
        [result], dedup=dedup, no_auth_hosts=set(), suspicious_hosts=set()
    )

    assert finalized.final_verified == []
    assert len(finalized.rejected) == 1
    assert finalized.rejected[0].valid is False
    assert "honeypot:" in (finalized.rejected[0].error or "")
    dedup.cache_valid.assert_not_awaited()
    save.assert_not_awaited()


async def test_no_auth_host_with_full_url_host_key(monkeypatch):
    """Host key must match verify_no_auth (host or apiurl when host empty)."""
    result = ValidationResult(
        credential=Credential(
            apikey="sk-proj-example-not-a-real-secret",
            apiurl="http://64.23.132.174:8443",
            host="http://64.23.132.174:8443",  # raw URL-as-host as seen in prod
        ),
        valid=True,
        validation_state="authentication_confirmed",
        status_code=200,
    )
    dedup = AsyncMock()
    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", AsyncMock())

    finalized = await finalize_results(
        [result],
        dedup=dedup,
        no_auth_hosts={"http://64.23.132.174:8443"},
        suspicious_hosts=set(),
    )
    assert finalized.final_verified == []
    assert finalized.rejected[0].valid is False
    assert "no-auth-host" in (finalized.rejected[0].error or "")
