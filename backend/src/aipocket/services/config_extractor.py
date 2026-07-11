from __future__ import annotations

import base64
import json
import re
import tomllib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import yaml

from aipocket.core.credentials import (
    Confidence,
    CredentialBundle,
    CredentialContext,
    CredentialEvidence,
)
from aipocket.core.key_patterns import KEY_PATTERNS, is_noise

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_SECRET_NAME_RE = re.compile(r"(?:api[_-]?key|token|secret|private[_-]?key)$", re.I)
_ENDPOINT_NAME_RE = re.compile(r"(?:base[_-]?url|api[_-]?url|endpoint|api[_-]?base)$", re.I)
_DEFAULTS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "google": "https://generativelanguage.googleapis.com",
    "vertex": "https://aiplatform.googleapis.com",
}


@dataclass(frozen=True, slots=True)
class _Entry:
    path: tuple[str, ...]
    name: str
    value: str
    order: int


def extract_config_bundles(content: str, *, format_hint: str = "") -> list[CredentialBundle]:
    """Parse a local config payload and deterministically pair secrets with endpoints."""
    entries = _parse_entries(content, format_hint.lower().lstrip("."))
    service_account = _google_service_account(entries)
    if service_account is not None:
        return [service_account]
    secrets = [entry for entry in entries if _is_secret(entry)]
    endpoints = [entry for entry in entries if _is_endpoint(entry)]
    return [_bundle_for(secret, endpoints, entries, format_hint) for secret in secrets]


def _parse_entries(content: str, hint: str) -> list[_Entry]:
    if hint in {"env", "dotenv"}:
        return _env_entries(content)
    try:
        if hint in {"json"}:
            data = json.loads(content)
        elif hint == "toml":
            data = tomllib.loads(content)
        else:
            data = yaml.safe_load(content)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError, UnicodeDecodeError):
        return _env_entries(content)
    entries = _flatten(data)
    if not entries:
        return _env_entries(content)
    if hint in {"kubernetes", "k8s"} or any(
        e.name == "kind" and e.value == "Secret" for e in entries
    ):
        return _decode_kubernetes(entries)
    return entries


def _env_entries(content: str) -> list[_Entry]:
    entries: list[_Entry] = []
    for order, line in enumerate(content.splitlines()):
        match = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*?)\s*$", line)
        if match:
            entries.append(_Entry((), match.group(1), match.group(2).strip("\"'"), order))
    return entries


def _flatten(
    data: Any, path: tuple[str, ...] = (), output: list[_Entry] | None = None
) -> list[_Entry]:
    result = output if output is not None else []
    if isinstance(data, dict):
        for name, value in data.items():
            _flatten(value, (*path, str(name)), result)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            _flatten(value, (*path, str(index)), result)
    elif data is not None and path:
        result.append(_Entry(path[:-1], path[-1], str(data), len(result)))
    return result


def _decode_kubernetes(entries: list[_Entry]) -> list[_Entry]:
    decoded: list[_Entry] = []
    for entry in entries:
        if entry.path and entry.path[-1] == "data":
            try:
                value = base64.b64decode(entry.value, validate=True).decode()
            except (ValueError, UnicodeDecodeError):
                value = entry.value
            decoded.append(_Entry(entry.path, entry.name, value, entry.order))
        else:
            decoded.append(entry)
    return decoded


def _is_secret(entry: _Entry) -> bool:
    if not _SECRET_NAME_RE.search(entry.name):
        return False
    if len(entry.value) < 15 or is_noise(entry.value):
        return False
    return (
        any(pattern.search(entry.value) for _, pattern in KEY_PATTERNS)
        or "PRIVATE KEY" in entry.value
        or len(entry.value) >= 20
    )


def _is_endpoint(entry: _Entry) -> bool:
    return bool(_ENDPOINT_NAME_RE.search(entry.name) and _URL_RE.fullmatch(entry.value.rstrip("/")))


def _prefix(name: str) -> str:
    upper = name.upper()
    for suffix in (
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_BASE_URL",
        "_API_URL",
        "_ENDPOINT",
        "_API_BASE",
    ):
        if upper.endswith(suffix):
            return upper[: -len(suffix)]
    return ""


def _provider(entry: _Entry) -> str:
    text = "_".join((*entry.path, entry.name)).lower()
    if "azure" in text and "openai" in text:
        return "azure_openai"
    for provider in ("openai", "anthropic", "google", "vertex"):
        if provider in text:
            return provider
    if entry.value.startswith("sk-ant-"):
        return "anthropic"
    if entry.value.startswith("AIza"):
        return "google"
    if entry.value.startswith("sk-"):
        return "openai"
    return "unknown"


def _bundle_for(
    secret: _Entry, endpoints: list[_Entry], entries: list[_Entry], source: str
) -> CredentialBundle:
    same_scope = [item for item in endpoints if secret.path and item.path == secret.path]
    prefix = _prefix(secret.name)
    prefixed = [item for item in endpoints if prefix and _prefix(item.name) == prefix]
    candidates = same_scope or prefixed
    pairing = "same_object" if same_scope else "prefix"
    if not candidates:
        distances = [abs(item.order - secret.order) for item in endpoints]
        nearest = min(distances, default=0)
        adjacent = [item for item in endpoints if abs(item.order - secret.order) <= nearest + 1]
        candidates = adjacent
        pairing = "adjacency"
    provider = _provider(secret)
    if not candidates and provider in _DEFAULTS:
        candidates = [_Entry((), "default", _DEFAULTS[provider], secret.order)]
        pairing = "default"
    urls = tuple(dict.fromkeys(item.value.rstrip("/") for item in candidates))
    confidence: Confidence = (
        "ambiguous"
        if len(urls) > 1
        else ("high" if pairing in {"same_object", "prefix"} else "medium")
    )
    context = _context(entries, urls)
    return CredentialBundle.create(
        secret.value,
        endpoint_candidates=urls,
        provider_hint=provider,
        context=context,
        evidence=(
            CredentialEvidence(
                source=source or "config",
                path=".".join(secret.path),
                variable=secret.name,
                pairing=pairing,
            ),
        ),
        confidence=confidence,
    )


def _context(entries: list[_Entry], urls: tuple[str, ...]) -> CredentialContext:
    values = {entry.name.upper(): entry.value for entry in entries}
    resource = ""
    if urls and ".openai.azure.com" in urls[0]:
        hostname = urlsplit(urls[0]).hostname
        resource = hostname.split(".")[0] if hostname else ""
    return CredentialContext(
        project=values.get("PROJECT_ID", ""),
        azure_resource=resource,
        deployment=values.get(
            "AZURE_OPENAI_DEPLOYMENT",
            values.get("AZURE_OPENAI_DEPLOYMENT_NAME", ""),
        ),
        api_version=values.get(
            "AZURE_OPENAI_API_VERSION",
            values.get("OPENAI_API_VERSION", ""),
        ),
        service_account_email=values.get("CLIENT_EMAIL", ""),
    )


def _google_service_account(entries: list[_Entry]) -> CredentialBundle | None:
    values = {entry.name: entry.value for entry in entries}
    if values.get("type") != "service_account" or "private_key" not in values:
        return None
    # Prefer explicit location fields; never serialize the private key into context.
    location = (
        values.get("location")
        or values.get("LOCATION")
        or values.get("VERTEX_LOCATION")
        or values.get("GOOGLE_CLOUD_LOCATION")
        or ""
    )
    return CredentialBundle.create(
        values["private_key"],
        credential_kind="google_service_account",
        endpoint_candidates=(_DEFAULTS["vertex"],),
        provider_hint="vertex",
        context=CredentialContext(
            project=values.get("project_id", ""),
            location=location,
            service_account_email=values.get("client_email", ""),
        ),
        evidence=(
            CredentialEvidence(source="json", variable="private_key", pairing="same_object"),
        ),
        confidence="high",
    )
