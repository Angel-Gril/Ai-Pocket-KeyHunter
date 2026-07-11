from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from aipocket.core.models import ValidationResult

ValidationState = Literal[
    "discovered",
    "structurally_valid",
    "authentication_confirmed",
    "scope_confirmed",
    "inference_verified",
    "no_auth_disproved",
    "final_verified",
    "unsupported_context",
    "auth_rejected",
    "scope_unverified",
    "rate_limited_unconfirmed",
    "no_auth_endpoint",
    "provider_conflict",
    "transient_error",
]

SUCCESS_PATH: Final[tuple[ValidationState, ...]] = (
    "discovered",
    "structurally_valid",
    "authentication_confirmed",
    "scope_confirmed",
    "inference_verified",
    "no_auth_disproved",
    "final_verified",
)

FAILURE_STATES: Final[frozenset[ValidationState]] = frozenset(
    {
        "unsupported_context",
        "auth_rejected",
        "scope_unverified",
        "rate_limited_unconfirmed",
        "no_auth_endpoint",
        "provider_conflict",
        "transient_error",
    }
)

# States that prove authentication/scope enough for pre-final processing.
AUTHENTICATED_STATES: Final[frozenset[ValidationState]] = frozenset(
    {
        "authentication_confirmed",
        "scope_confirmed",
        "inference_verified",
        "no_auth_disproved",
        "final_verified",
    }
)

FINAL_POSITIVE_STATES: Final[frozenset[ValidationState]] = frozenset({"final_verified"})

QUARANTINE_STATES: Final[frozenset[ValidationState]] = frozenset({"rate_limited_unconfirmed"})

# Legal edges: forward success steps, optional skips for inference/scope, and failures.
_LEGAL: Final[dict[ValidationState, frozenset[ValidationState]]] = {
    "discovered": frozenset({"structurally_valid", *FAILURE_STATES}),
    "structurally_valid": frozenset(
        {
            "authentication_confirmed",
            "scope_confirmed",
            # Gateway probes may prove auth and inference in one messages/chat call.
            "inference_verified",
            *FAILURE_STATES,
        }
    ),
    "authentication_confirmed": frozenset(
        {
            "scope_confirmed",
            "inference_verified",
            "no_auth_disproved",
            "final_verified",
            *FAILURE_STATES,
        }
    ),
    "scope_confirmed": frozenset(
        {
            "inference_verified",
            "no_auth_disproved",
            "final_verified",
            *FAILURE_STATES,
        }
    ),
    "inference_verified": frozenset(
        {
            "no_auth_disproved",
            "final_verified",
            *FAILURE_STATES,
        }
    ),
    "no_auth_disproved": frozenset({"final_verified", *FAILURE_STATES}),
    "final_verified": frozenset(),
    **{state: frozenset() for state in FAILURE_STATES},
}


def can_transition(current: ValidationState, new: ValidationState) -> bool:
    if current == new:
        return True
    return new in _LEGAL.get(current, frozenset())


def apply_state(result: ValidationResult, new: ValidationState) -> ValidationResult:
    """Transition ``result.validation_state`` and sync derived ``valid``/``suspicious``."""
    current: ValidationState = result.validation_state  # type: ignore[assignment]
    if not can_transition(current, new):
        raise ValueError(f"illegal-transition:{current}->{new}")
    result.validation_state = new
    result.valid = new in AUTHENTICATED_STATES or new == "rate_limited_unconfirmed"
    if new == "rate_limited_unconfirmed":
        result.suspicious = True
        if not result.suspicious_reason:
            result.suspicious_reason = "rate_limited_unconfirmed"
    if new in {"auth_rejected", "no_auth_endpoint", "provider_conflict", "unsupported_context"}:
        result.valid = False
    return result


def is_authenticated(result: ValidationResult) -> bool:
    return result.validation_state in AUTHENTICATED_STATES


def is_final_positive(result: ValidationResult) -> bool:
    return result.validation_state in FINAL_POSITIVE_STATES


def is_quarantined(result: ValidationResult) -> bool:
    return result.validation_state in QUARANTINE_STATES or (
        result.suspicious and result.validation_state != "final_verified"
    )
