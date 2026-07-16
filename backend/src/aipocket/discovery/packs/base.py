"""Declarative provider discovery pack schema.

Packs describe *what to look for* on artifact sources (GitHub, etc.).
They never own HTTP loops, token pools, or storage, and do not duplicate
provider adapter / validation logic.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderDiscoveryPack:
    """Static discovery strategy for one provider vertical slice."""

    pack_id: str
    version: str
    commit_message_anchors: tuple[str, ...]
    code_content_anchors: tuple[str, ...]
    code_qualifier_groups: tuple[tuple[str, ...], ...]
    seeded_history_policy: str
    path_hints: tuple[str, ...]
    extensions: tuple[str, ...]
    secret_pattern_ids: tuple[str, ...]  # references KEY_PATTERNS names
    variable_names: tuple[str, ...]
    endpoint_names: tuple[str, ...]
    official_domains: tuple[str, ...]
    default_endpoint: str
    config_formats: tuple[str, ...]
    issuer_rule: str
    capability_model_families: tuple[str, ...]
    noise_rules: tuple[str, ...]
    balance_capability: bool
    canary_fixture_ids: tuple[str, ...]
