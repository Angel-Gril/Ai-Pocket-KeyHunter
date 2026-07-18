"""Parameterized contract tests for all provider discovery packs."""

from __future__ import annotations

import pytest

# Importing packs package registers all packs.
import aipocket.discovery.packs  # noqa: F401
from aipocket.core.key_patterns import KEY_PATTERNS
from aipocket.discovery.packs import list_packs
from aipocket.discovery.packs.base import ProviderDiscoveryPack

_PATTERN_IDS = {name for name, _ in KEY_PATTERNS}

REQUIRED_FIELDS = (
    "pack_id",
    "version",
    "commit_message_anchors",
    "code_content_anchors",
    "code_qualifier_groups",
    "seeded_history_policy",
    "path_hints",
    "extensions",
    "secret_pattern_ids",
    "variable_names",
    "endpoint_names",
    "official_domains",
    "default_endpoint",
    "config_formats",
    "issuer_rule",
    "capability_model_families",
    "noise_rules",
    "canary_fixture_ids",
)


def _all_packs() -> list[ProviderDiscoveryPack]:
    packs = list(list_packs())
    assert packs, "expected at least one registered pack"
    return packs


@pytest.mark.parametrize("pack", _all_packs(), ids=lambda p: p.pack_id)
def test_pack_required_fields_populated(pack: ProviderDiscoveryPack) -> None:
    for field in REQUIRED_FIELDS:
        value = getattr(pack, field)
        assert value, f"{pack.pack_id}.{field} must be non-empty"


@pytest.mark.parametrize("pack", _all_packs(), ids=lambda p: p.pack_id)
def test_pack_secret_pattern_ids_are_canonical(pack: ProviderDiscoveryPack) -> None:
    for pattern_id in pack.secret_pattern_ids:
        assert pattern_id in _PATTERN_IDS, (
            f"{pack.pack_id}: unknown secret_pattern_id {pattern_id!r}"
        )


@pytest.mark.parametrize("pack", _all_packs(), ids=lambda p: p.pack_id)
def test_pack_default_endpoint_is_https(pack: ProviderDiscoveryPack) -> None:
    assert pack.default_endpoint.startswith("https://")


@pytest.mark.parametrize("pack", _all_packs(), ids=lambda p: p.pack_id)
def test_pack_is_frozen_and_declarative(pack: ProviderDiscoveryPack) -> None:
    assert pack.__dataclass_params__.frozen  # type: ignore[attr-defined]
    # Packs must not expose HTTP / pool / storage hooks.
    for banned in ("fetch", "client", "pool", "store", "http", "session"):
        assert not hasattr(pack, banned)


def test_pack_ids_unique() -> None:
    ids = [p.pack_id for p in list_packs()]
    assert len(ids) == len(set(ids))


def test_expected_pack_set() -> None:
    ids = {p.pack_id for p in list_packs()}
    assert {
        "glm",
        "kimi",
        "qwen",
        "cohere",
        "replicate",
        "together",
        "fireworks",
        "deepseek",
        "openai",
        "anthropic",
        "azure_openai",
        "minimax",
    } <= ids


def test_commit_anchors_are_env_literals_not_phrases() -> None:
    """Spoken phrases yield near-zero commit_message hits; ENV names match leaks."""
    low_signal = (
        "rotate ",
        "remove leaked",
        "leaked key",
    )
    for pack in list_packs():
        for anchor in pack.commit_message_anchors:
            lower = anchor.lower()
            # Multi-term AND queries from R3 (".env X", "sk- X") are intentional.
            if lower.startswith(".env ") or lower.startswith("sk- "):
                continue
            # Allow domain-style anchors (api.x.com) and ENV/snake identifiers.
            if "." in anchor or "_" in anchor or anchor.isupper() or anchor.islower():
                continue
            for phrase in low_signal:
                assert phrase not in lower, (
                    f"{pack.pack_id} commit anchor looks like spoken phrase: {anchor!r}"
                )
