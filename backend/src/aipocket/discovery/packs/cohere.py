"""Cohere discovery pack (declarative only).

GH Stream Hunter v10 R3: cohere_api_key / COHERE_API_KEY /
  .env cohere_api_key / sk- cohere_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

COHERE_OFFICIAL_ENDPOINT = "https://api.cohere.com/v1"

COHERE_PACK = ProviderDiscoveryPack(
    pack_id="cohere",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "cohere_api_key",
        "COHERE_API_KEY",
        ".env cohere_api_key",
        "sk- cohere_api_key",
        # --- supersets ---
        "CO_API_KEY",
        "api.cohere.com",
        "api.cohere.ai",
        ".env COHERE_API_KEY",
    ),
    code_content_anchors=(
        "COHERE_API_KEY",
        "CO_API_KEY",
        "cohere_api_key",
        "api.cohere.com",
        "api.cohere.ai",
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
    secret_pattern_ids=("sk_key",),
    variable_names=("COHERE_API_KEY", "CO_API_KEY", "COHERE_KEY"),
    endpoint_names=("COHERE_BASE_URL", "COHERE_API_URL", "BASE_URL", "API_URL"),
    official_domains=("cohere.com", "cohere.ai"),
    default_endpoint=COHERE_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "official_domain_auth → cohere; "
        "generic_token_on_gateway stays gateway; "
        "command/cohere models set served_model_families"
    ),
    capability_model_families=("cohere", "command"),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("cohere_official_env", "cohere_placeholder_noise"),
)

register_pack(COHERE_PACK)
