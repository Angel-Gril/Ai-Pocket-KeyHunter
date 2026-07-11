from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

CredentialKind = Literal["api_key", "token", "google_service_account"]
Confidence = Literal["high", "medium", "low", "ambiguous"]
ValidationState = Literal["discovered", "structurally_valid"]


class ControlledSecret(BaseModel):
    """In-memory secret whose normal serialization never exposes plaintext."""

    model_config = ConfigDict(frozen=True)
    _value: str = PrivateAttr()

    def __init__(self, value: str) -> None:
        super().__init__()
        self._value = value

    def reveal(self) -> str:
        return self._value


class CredentialContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization: str = ""
    project: str = ""
    workspace: str = ""
    azure_resource: str = ""
    deployment: str = ""
    api_version: str = ""
    location: str = ""
    service_account_email: str = ""


class CredentialEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    path: str = ""
    variable: str = ""
    pairing: str = ""


class CredentialBundle(BaseModel):
    """Structured credential candidate with controlled plaintext access."""

    model_config = ConfigDict(frozen=True)

    credential_kind: CredentialKind
    secret_value: ControlledSecret
    secret_fingerprint: str
    endpoint_candidates: tuple[str, ...] = ()
    provider_hint: str = "unknown"
    context: CredentialContext = Field(default_factory=CredentialContext)
    evidence: tuple[CredentialEvidence, ...] = ()
    confidence: Confidence = "medium"
    validation_state: ValidationState = "discovered"

    @classmethod
    def create(
        cls,
        secret: str,
        *,
        credential_kind: CredentialKind = "api_key",
        endpoint_candidates: tuple[str, ...] = (),
        provider_hint: str = "unknown",
        context: CredentialContext | None = None,
        evidence: tuple[CredentialEvidence, ...] = (),
        confidence: Confidence = "medium",
    ) -> CredentialBundle:
        return cls(
            credential_kind=credential_kind,
            secret_value=ControlledSecret(secret),
            secret_fingerprint=hashlib.sha256(secret.encode()).hexdigest(),
            endpoint_candidates=endpoint_candidates,
            provider_hint=provider_hint,
            context=context or CredentialContext(),
            evidence=evidence,
            confidence=confidence,
            validation_state="structurally_valid",
        )
