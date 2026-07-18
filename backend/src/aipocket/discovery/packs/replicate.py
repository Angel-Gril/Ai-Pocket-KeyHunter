"""Replicate discovery pack (declarative only).

GH Stream Hunter v10 R3: replicate_api_key / REPLICATE_API_KEY /
  .env replicate_api_key / sk- replicate_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

REPLICATE_OFFICIAL_ENDPOINT = "https://api.replicate.com/v1"

REPLICATE_PACK = ProviderDiscoveryPack(
    pack_id="replicate",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "replicate_api_key",
        "REPLICATE_API_KEY",
        ".env replicate_api_key",
        "sk- replicate_api_key",
        # --- supersets ---
        "REPLICATE_API_TOKEN",
        "api.replicate.com",
        ".env REPLICATE_API_TOKEN",
        ".env REPLICATE_API_KEY",
    ),
    code_content_anchors=(
        "REPLICATE_API_TOKEN",
        "REPLICATE_API_KEY",
        "replicate_api_key",
        "api.replicate.com",
        "r8_",
    ),
    code_qualifier_groups=(
        ("extension:env", "path:.env"),
        ("extension:yml", "extension:yaml", "path:config"),
        ("extension:json",),
        ("extension:toml",),
    ),
    seeded_history_policy="seed_on_code_hit",
    path_hints=(".env", "config", "settings", "secrets"),
    extensions=("env", "yml", "yaml", "json", "toml", "py", "ts", "js"),
    secret_pattern_ids=("replicate",),
    variable_names=("REPLICATE_API_TOKEN", "REPLICATE_API_KEY", "REPLICATE_TOKEN"),
    endpoint_names=("REPLICATE_BASE_URL", "REPLICATE_API_URL", "BASE_URL", "API_URL"),
    official_domains=("replicate.com",),
    default_endpoint=REPLICATE_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "exclusive r8_ key_shape + official domain auth → replicate; "
        "generic_token_on_gateway stays gateway"
    ),
    capability_model_families=("replicate",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("replicate_official_env", "replicate_placeholder_noise"),
)

register_pack(REPLICATE_PACK)
