"""DeepSeek discovery pack (declarative only).

Aligned with GH Stream Hunter v10 R3 commit queries:
  deepseek_api_endpoint, DEEPSEEK_BASE_URL, .env variants.
Extra anchors (API key env names, official host) are intentional supersets.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

DEEPSEEK_OFFICIAL_ENDPOINT = "https://api.deepseek.com"

DEEPSEEK_PACK = ProviderDiscoveryPack(
    pack_id="deepseek",
    version="2",
    # Order: reference-script terms first (budget slices from the front).
    commit_message_anchors=(
        # --- gh_stream_v10_r3 single terms ---
        "deepseek_api_endpoint",
        "DEEPSEEK_API_ENDPOINT",
        "DEEPSEEK_BASE_URL",
        "deepseek_base_url",
        # --- gh_stream_v10_r3 .env AND queries ---
        ".env deepseek_api_endpoint",
        ".env DEEPSEEK_BASE_URL",
        # --- supersets ---
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_API_BASE",
        "api.deepseek.com",
        ".env DEEPSEEK_API_KEY",
        "sk- DEEPSEEK_API_KEY",
        "sk- deepseek_api_endpoint",
    ),
    code_content_anchors=(
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_API_BASE",
        "DEEPSEEK_API_ENDPOINT",
        "deepseek_api_endpoint",
        "api.deepseek.com",
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
    secret_pattern_ids=("sk_key",),
    variable_names=(
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_KEY",
        "DEEPSEEK_TOKEN",
        "DS_API_KEY",
    ),
    endpoint_names=(
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_API_BASE",
        "DEEPSEEK_API_ENDPOINT",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("deepseek.com", "deepseek.ai"),
    default_endpoint=DEEPSEEK_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "official_domain_auth → deepseek; "
        "generic sk- on gateway stays gateway; "
        "deepseek-* models set served_model_families"
    ),
    capability_model_families=("deepseek",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=("deepseek_official_env", "deepseek_placeholder_noise"),
)

register_pack(DEEPSEEK_PACK)
