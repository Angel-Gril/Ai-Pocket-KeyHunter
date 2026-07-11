from __future__ import annotations

import pytest

from aipocket.core.models import Credential, ValidationResult
from aipocket.core.validation_state import (
    FAILURE_STATES,
    SUCCESS_PATH,
    ValidationState,
    apply_state,
    can_transition,
    is_final_positive,
    is_quarantined,
)
from aipocket.services.finalizer import FinalizedResults, finalize_results
from aipocket.services.high_value_writer import should_save


def test_legal_forward_transitions_along_success_path() -> None:
    for current, nxt in zip(SUCCESS_PATH, SUCCESS_PATH[1:], strict=False):
        assert can_transition(current, nxt) is True


def test_illegal_skips_and_reverse_transitions_are_rejected() -> None:
    assert can_transition("discovered", "final_verified") is False
    assert can_transition("authentication_confirmed", "discovered") is False
    assert can_transition("final_verified", "authentication_confirmed") is False


@pytest.mark.parametrize("failure", sorted(FAILURE_STATES))
def test_any_active_state_may_fail(failure: ValidationState) -> None:
    assert can_transition("authentication_confirmed", failure) is True
    assert can_transition("structurally_valid", failure) is True


def test_apply_state_rejects_illegal_transition() -> None:
    result = ValidationResult(
        credential=Credential(apikey="sk-test", apiurl="https://api.openai.com/v1"),
        validation_state="discovered",
    )
    with pytest.raises(ValueError, match="illegal-transition"):
        apply_state(result, "final_verified")


def test_valid_bool_is_derived_from_state_not_a_shortcut() -> None:
    result = ValidationResult(
        credential=Credential(apikey="sk-test", apiurl="https://api.openai.com/v1"),
        validation_state="discovered",
        valid=True,  # stale bool must not win over state
    )
    assert result.is_authenticated is False
    assert is_final_positive(result) is False

    apply_state(result, "structurally_valid")
    apply_state(result, "authentication_confirmed")
    assert result.is_authenticated is True
    assert result.valid is True


def test_rate_limited_unconfirmed_is_quarantined_not_final() -> None:
    result = ValidationResult(
        credential=Credential(apikey="sk-proj-x", apiurl="https://api.openai.com/v1"),
        validation_state="structurally_valid",
    )
    apply_state(result, "rate_limited_unconfirmed")
    assert is_quarantined(result) is True
    assert is_final_positive(result) is False
    assert should_save(result) is False


@pytest.mark.asyncio
async def test_finalizer_only_persists_final_verified(monkeypatch) -> None:
    saved: list[ValidationResult] = []
    cached: list[ValidationResult] = []

    class _Dedup:
        async def cache_valid(self, result: ValidationResult) -> None:
            cached.append(result)

        async def mark_rejected(self, credential: Credential) -> None:
            return None

        async def mark_transient(self, credential: Credential) -> None:
            return None

    async def _save(result: ValidationResult) -> None:
        saved.append(result)

    monkeypatch.setattr("aipocket.services.finalizer.save_final_high_value", _save)
    monkeypatch.setattr(
        "aipocket.services.finalizer.filter_honeypots",
        lambda results, **kwargs: results,
    )

    auth = ValidationResult(
        credential=Credential(apikey="sk-proj-a", apiurl="https://api.openai.com/v1"),
        validation_state="authentication_confirmed",
        valid=True,
        status_code=200,
    )
    limited = ValidationResult(
        credential=Credential(apikey="sk-proj-b", apiurl="https://api.openai.com/v1"),
        validation_state="rate_limited_unconfirmed",
        valid=True,
        suspicious=True,
        status_code=429,
    )
    rejected = ValidationResult(
        credential=Credential(apikey="sk-proj-c", apiurl="https://api.openai.com/v1"),
        validation_state="auth_rejected",
        valid=False,
        status_code=401,
    )

    finalized = await finalize_results(
        [auth, limited, rejected],
        dedup=_Dedup(),
        no_auth_hosts=set(),
        suspicious_hosts=set(),
    )

    assert isinstance(finalized, FinalizedResults)
    assert [r.validation_state for r in finalized.final_verified] == ["final_verified"]
    assert [r.validation_state for r in finalized.rate_limited_unconfirmed] == [
        "rate_limited_unconfirmed"
    ]
    assert [r.validation_state for r in finalized.rejected] == ["auth_rejected"]
    assert cached and cached[0].validation_state == "final_verified"
