from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from aipocket.core.credentials import CredentialBundle
from aipocket.core.models import Credential, ValidationResult
from aipocket.services.credential_policy import (
    EXCLUSION_REASON,
    filter_credentials_by_policy,
    filter_results_by_policy,
    is_google_direct_credential,
    normalize_credential_endpoint,
)

GOOGLE_URL = "https://generativelanguage.googleapis.com/v1beta"
GOOGLE_KEY = "AIzaSyD" + "a" * 32


def _google_credential(*, apiurl: str = GOOGLE_URL, provider_hint: str = "google") -> Credential:
    bundle = CredentialBundle.create(
        GOOGLE_KEY,
        provider_hint=provider_hint,
        endpoint_candidates=(apiurl,),
    )
    return Credential(apikey=GOOGLE_KEY, apiurl=apiurl, bundle=bundle)


def test_direct_google_is_excluded_by_host_bundle_and_key_shape() -> None:
    assert is_google_direct_credential(_google_credential()) is True
    assert is_google_direct_credential(_google_credential(apiurl="https://leak.example")) is True
    assert is_google_direct_credential(
        Credential(apikey=GOOGLE_KEY, apiurl="https://leak.example")
    ) is True
    assert EXCLUSION_REASON == "excluded:google_generative_language"


def test_direct_google_is_removed_before_credentials_or_results_continue() -> None:
    allowed = Credential(apikey="sk-provider-allowed", apiurl="https://relay.example/v1")
    direct = _google_credential()
    assert filter_credentials_by_policy([direct, allowed], stage="test") == [allowed]

    cached_valid = ValidationResult(
        credential=direct,
        valid=True,
        validation_state="final_verified",
    )
    allowed_result = ValidationResult(credential=allowed)
    assert filter_results_by_policy([cached_valid, allowed_result], stage="test") == [allowed_result]


@pytest.mark.asyncio
async def test_finalizer_never_caches_or_saves_cached_valid_google(monkeypatch) -> None:
    from aipocket.services.finalizer import commit_final_results, finalize_results

    direct = ValidationResult(
        credential=_google_credential(),
        valid=True,
        validation_state="final_verified",
    )
    dedup = AsyncMock()
    save = AsyncMock(return_value=True)
    monkeypatch.setattr("aipocket.services.finalizer.try_save", save)

    finalized = await finalize_results(
        [direct],
        dedup=dedup,
        no_auth_hosts=set(),
        suspicious_hosts=set(),
    )
    report = await commit_final_results([direct], dedup=dedup)
    from aipocket.services.high_value_writer import save_high_value_key, should_save
    assert should_save(direct) is False
    assert save_high_value_key(direct) is False

    assert finalized.final_verified == []
    assert finalized.rejected == []
    assert report.high_value_final == 0
    dedup.cache_valid.assert_not_awaited()
    save.assert_not_awaited()


def test_endpoint_normalization_preserves_d1_field_meanings() -> None:
    credential = Credential(
        apikey="sk-proj-" + "a" * 40,
        apiurl="https://api.openai.com/v1/chat/completions?debug=1#fragment",
        host="api.openai.com",
    )
    normalized = normalize_credential_endpoint(credential)
    assert normalized.apiurl == "https://api.openai.com/v1"
    assert normalized.host == "https://api.openai.com"
    assert normalized.leak_host == ""
