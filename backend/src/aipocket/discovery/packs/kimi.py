"""Kimi / Moonshot discovery pack (declarative only)."""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

KIMI_OFFICIAL_ENDPOINT = "https://api.moonshot.cn/v1"

KIMI_PACK = ProviderDiscoveryPack(
    pack_id="kimi",
    version="1",
    commit_message_anchors=(
        "kimi api key",
        "moonshot",
        "rotate moonshot",
        "remove leaked key",
    ),
    code_content_anchors=(
        "MOONSHOT_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_API_BASE",
        "api.moonshot.cn",
        "platform.moonshot.cn",
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
        "MOONSHOT_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_KEY",
        "KIMI_KEY",
    ),
    endpoint_names=(
        "MOONSHOT_BASE_URL",
        "MOONSHOT_API_BASE",
        "KIMI_BASE_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("moonshot.cn",),
    default_endpoint=KIMI_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "official_domain_auth → kimi; "
        "generic_token_on_gateway stays gateway; "
        "kimi/moonshot models set served_model_families"
    ),
    capability_model_families=("kimi", "moonshot"),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=("kimi_official_env", "kimi_placeholder_noise"),
)

register_pack(KIMI_PACK)
