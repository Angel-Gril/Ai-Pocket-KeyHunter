"""MiniMax discovery pack (declarative only).

GH Stream Hunter v10 R3: minimax_api_key / MINIMAX_API_KEY / .env minimax_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

MINIMAX_OFFICIAL_ENDPOINT = "https://api.minimax.io/v1"

MINIMAX_PACK = ProviderDiscoveryPack(
    pack_id="minimax",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "minimax_api_key",
        "MINIMAX_API_KEY",
        ".env minimax_api_key",
        # --- supersets ---
        "MINIMAX_GROUP_ID",
        "api.minimax.chat",
        ".env MINIMAX_API_KEY",
        "sk- minimax_api_key",
        "sk- MINIMAX_API_KEY",
    ),
    code_content_anchors=(
        "MINIMAX_API_KEY",
        "MINIMAX_GROUP_ID",
        "MINIMAX_API_HOST",
        "minimax_api_key",
        "api.minimax.chat",
        "api.minimaxi.com",
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
    variable_names=(
        "MINIMAX_API_KEY",
        "MINIMAX_KEY",
        "MINIMAX_TOKEN",
    ),
    endpoint_names=(
        "MINIMAX_BASE_URL",
        "MINIMAX_API_HOST",
        "MINIMAX_API_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("minimax.chat", "minimaxi.com", "minimax.io"),
    default_endpoint=MINIMAX_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "official_domain_auth → minimax; "
        "generic_token_on_gateway stays gateway"
    ),
    capability_model_families=("minimax",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("minimax_official_env", "minimax_placeholder_noise"),
)

register_pack(MINIMAX_PACK)
