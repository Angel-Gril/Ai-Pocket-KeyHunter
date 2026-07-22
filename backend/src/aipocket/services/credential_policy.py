from __future__ import annotations

import logging
from collections.abc import Iterable
from urllib.parse import urlsplit

from aipocket.core.models import Credential, ValidationResult
from aipocket.services.providers.endpoints import canonicalize_endpoint
from aipocket.services.providers.registry import provider_registry, resolve_provider

log = logging.getLogger(__name__)

_GOOGLE_DIRECT_HOST = "generativelanguage.googleapis.com"
_EXCLUSION_REASON = "excluded:google_generative_language"


def _hostname(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname
    except ValueError:
        return ""
    return (host or "").lower().rstrip(".")


def _authority(value: str) -> tuple[str, int | None]:
    raw = (value or "").strip()
    if not raw:
        return "", None
    try:
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return "", None
    if port in {80, 443}:
        port = None
    return host, port


def is_google_direct_credential(credential: Credential) -> bool:
    if _hostname(credential.apiurl) == _GOOGLE_DIRECT_HOST:
        return True
    if credential.bundle is not None:
        if credential.bundle.provider_hint == "google":
            return True
        if any(_hostname(url) == _GOOGLE_DIRECT_HOST for url in credential.bundle.endpoint_candidates):
            return True
    key_spec = provider_registry.match_key(credential.apikey)
    return key_spec is not None and key_spec.name == "google"


def is_google_direct_result(result: ValidationResult) -> bool:
    return is_google_direct_credential(result.credential)


def normalize_credential_endpoint(credential: Credential) -> Credential:
    """Apply the shared provider resolution and D1 endpoint field contract in place."""
    resolution = resolve_provider(apiurl=credential.apiurl, apikey=credential.apikey)
    provider = resolution.provider
    if (
        provider in {"unknown", "gateway", "ambiguous"}
        and credential.bundle is not None
        and credential.bundle.provider_hint not in {"", "unknown", "gateway", "ambiguous"}
    ):
        provider = credential.bundle.provider_hint

    raw_endpoint = credential.apiurl
    if not raw_endpoint and credential.bundle is not None and len(credential.bundle.endpoint_candidates) == 1:
        raw_endpoint = credential.bundle.endpoint_candidates[0]
    if not raw_endpoint:
        return credential

    original_discovery = credential.leak_host or credential.host
    endpoint = canonicalize_endpoint(raw_endpoint, provider=provider)
    if not endpoint.api_base:
        return credential
    if original_discovery and _authority(original_discovery) != _authority(endpoint.origin):
        credential.leak_host = original_discovery
    credential.apiurl = endpoint.api_base
    credential.host = endpoint.origin
    return credential


def apply_credential_policy(credential: Credential) -> Credential | None:
    if is_google_direct_credential(credential):
        return None
    return normalize_credential_endpoint(credential)


def filter_credentials_by_policy(
    credentials: Iterable[Credential],
    *,
    stage: str,
) -> list[Credential]:
    kept: list[Credential] = []
    excluded = 0
    for credential in credentials:
        accepted = apply_credential_policy(credential)
        if accepted is None:
            excluded += 1
        else:
            kept.append(accepted)
    if excluded:
        log.info("%s: %s count=%d", stage, _EXCLUSION_REASON, excluded)
    return kept


def filter_results_by_policy(
    results: Iterable[ValidationResult],
    *,
    stage: str,
) -> list[ValidationResult]:
    kept: list[ValidationResult] = []
    excluded = 0
    for result in results:
        if is_google_direct_result(result):
            excluded += 1
        else:
            kept.append(result)
    if excluded:
        log.info("%s: %s count=%d", stage, _EXCLUSION_REASON, excluded)
    return kept


EXCLUSION_REASON = _EXCLUSION_REASON
