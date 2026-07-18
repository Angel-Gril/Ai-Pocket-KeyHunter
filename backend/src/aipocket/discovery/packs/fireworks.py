"""Fireworks AI discovery pack (declarative only).

GH Stream Hunter v10 R3: fireworks_api_key / FIREWORKS_API_KEY /
  .env fireworks_api_key / sk- fireworks_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

FIREWORKS_OFFICIAL_ENDPOINT = "https://api.fireworks.ai/inference/v1"

FIREWORKS_PACK = ProviderDiscoveryPack(
    pack_id="fireworks",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "fireworks_api_key",
        "FIREWORKS_API_KEY",
        ".env fireworks_api_key",
        "sk- fireworks_api_key",
        # --- supersets ---
        "FIREWORKS_AI_API_KEY",
        "api.fireworks.ai",
        ".env FIREWORKS_API_KEY",
    ),
    code_content_anchors=(
        "FIREWORKS_API_KEY",
        "FIREWORKS_AI_API_KEY",
        "fireworks_api_key",
        "api.fireworks.ai",
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
    variable_names=("FIREWORKS_API_KEY", "FIREWORKS_AI_API_KEY", "FIREWORKS_KEY"),
    endpoint_names=("FIREWORKS_BASE_URL", "FIREWORKS_API_URL", "BASE_URL", "API_URL"),
    official_domains=("fireworks.ai",),
    default_endpoint=FIREWORKS_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=("official_domain_auth → fireworks; generic_token_on_gateway stays gateway"),
    capability_model_families=("fireworks",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("fireworks_official_env", "fireworks_placeholder_noise"),
)

register_pack(FIREWORKS_PACK)
