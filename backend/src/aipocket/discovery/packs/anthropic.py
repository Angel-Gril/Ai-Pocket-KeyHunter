"""Anthropic / Claude discovery pack (declarative only).

GH Stream Hunter v10 R3: anthropic_base_url / ANTHROPIC_BASE_URL / CLAUDE_API_KEY
  + .env anthropic_base_url / .env CLAUDE_API_KEY.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

ANTHROPIC_OFFICIAL_ENDPOINT = "https://api.anthropic.com"

ANTHROPIC_PACK = ProviderDiscoveryPack(
    pack_id="anthropic",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "anthropic_base_url",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_API_KEY",
        "claude_api_key",
        ".env anthropic_base_url",
        ".env CLAUDE_API_KEY",
        # --- supersets ---
        "ANTHROPIC_API_KEY",
        "api.anthropic.com",
        ".env ANTHROPIC_API_KEY",
        "sk- ANTHROPIC_API_KEY",
        "sk- CLAUDE_API_KEY",
    ),
    code_content_anchors=(
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "anthropic_base_url",
        "api.anthropic.com",
        "sk-ant-",
    ),
    code_qualifier_groups=(
        ("extension:env", "path:.env"),
        ("extension:yml", "extension:yaml", "path:config"),
        ("extension:json",),
        ("extension:toml",),
        ("extension:py",),
    ),
    seeded_history_policy="seed_on_code_hit",
    path_hints=(".env", "config", "settings", "secrets"),
    extensions=("env", "yml", "yaml", "json", "toml", "py", "ts", "js"),
    secret_pattern_ids=("anthropic", "sk_key"),
    variable_names=(
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_KEY",
        "CLAUDE_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
    ),
    endpoint_names=(
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_URL",
        "CLAUDE_BASE_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("anthropic.com",),
    default_endpoint=ANTHROPIC_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "sk-ant- or official anthropic.com → anthropic; "
        "generic token on gateway stays gateway"
    ),
    capability_model_families=("anthropic", "claude"),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=("anthropic_official_env", "anthropic_placeholder_noise"),
)

register_pack(ANTHROPIC_PACK)
