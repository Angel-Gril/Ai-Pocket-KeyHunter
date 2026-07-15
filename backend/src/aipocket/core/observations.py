from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from aipocket.core.models import Credential


class ExtractionMethod(StrEnum):
    REGEX = "regex"
    PROBER = "prober"
    GPT = "gpt"


@dataclass(frozen=True, slots=True)
class CredentialIdentity:
    secret_fingerprint: str
    endpoint: str


@dataclass(slots=True)
class CanonicalCredentialObservation:
    identity: CredentialIdentity
    credential: Credential
    method: ExtractionMethod
    primary_provenance: tuple[str, str]
    all_provenance: set[tuple[str, str]] = field(default_factory=set)


class ObservationRegistry:
    def __init__(self) -> None:
        self._observations: dict[CredentialIdentity, CanonicalCredentialObservation] = {}

    @property
    def observations(self) -> tuple[CanonicalCredentialObservation, ...]:
        return tuple(self._observations.values())

    def observe(
        self,
        credential: Credential,
        method: ExtractionMethod,
        provenance: tuple[tuple[str, str], ...],
    ) -> CanonicalCredentialObservation:
        identity = credential_identity(credential)
        existing = self._observations.get(identity)
        if existing is not None:
            existing.all_provenance.update(provenance)
            return existing
        if not provenance:
            raise ValueError("credential observation requires provenance")
        observation = CanonicalCredentialObservation(
            identity=identity,
            credential=credential,
            method=method,
            primary_provenance=provenance[0],
            all_provenance=set(provenance),
        )
        self._observations[identity] = observation
        return observation

    def get(self, credential: Credential) -> CanonicalCredentialObservation | None:
        identity = credential_identity(credential)
        hit = self._observations.get(identity)
        if hit is not None:
            return hit
        # Official-endpoint routing mutates apiurl/host while preserving the
        # original discovery endpoint in leak_host. Re-resolve against that
        # origin so post-validation metrics still attach to the observation.
        leak = (credential.leak_host or "").strip()
        if not leak:
            return None
        leak_endpoint = leak.rstrip("/").lower()
        if leak_endpoint == identity.endpoint:
            return None
        return self._observations.get(
            CredentialIdentity(identity.secret_fingerprint, leak_endpoint)
        )


def credential_identity(credential: Credential) -> CredentialIdentity:
    fingerprint = (
        credential.bundle.secret_fingerprint
        if credential.bundle is not None
        else hashlib.sha256(credential.apikey.encode()).hexdigest()
    )
    endpoint = (credential.apiurl or credential.host).strip().rstrip("/").lower()
    return CredentialIdentity(fingerprint, endpoint)
