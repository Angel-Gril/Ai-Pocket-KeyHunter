"""LongCat discovery pack (declarative only)."""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

LONGCAT_OFFICIAL_ENDPOINT = "https://api.longcat.chat/openai"

LONGCAT_PACK = ProviderDiscoveryPack(
    pack_id="longcat",
    version="1",
    commit_message_anchors=(
        "LONGCAT_API_KEY",
        "LONGCAT_BASE_URL",
        "api.longcat.chat/openai",
        "api.longcat.chat/anthropic",
    ),
    code_content_anchors=(
        "LONGCAT_API_KEY",
        "LONGCAT_BASE_URL",
        "api.longcat.chat/openai",
        "api.longcat.chat/anthropic",
    ),
    code_qualifier_groups=(
        ("extension:env", "path:.env"),
        ("extension:yml", "extension:yaml", "path:config"),
        ("extension:json", "extension:toml"),
    ),
    seeded_history_policy="seed_on_code_hit",
    path_hints=(".env", "config", "settings", "secrets"),
    extensions=("env", "yml", "yaml", "json", "toml", "py", "ts", "js"),
    secret_pattern_ids=("sk_key",),
    variable_names=("LONGCAT_API_KEY", "LONGCAT_KEY", "LONGCAT_TOKEN"),
    endpoint_names=("LONGCAT_BASE_URL", "LONGCAT_API_URL", "BASE_URL", "API_URL"),
    official_domains=("api.longcat.chat",),
    default_endpoint=LONGCAT_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule="exact_official_domain_auth → longcat; generic_token_elsewhere stays gateway",
    capability_model_families=("longcat",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("longcat_openai_env", "longcat_anthropic_env"),
)

register_pack(LONGCAT_PACK)
