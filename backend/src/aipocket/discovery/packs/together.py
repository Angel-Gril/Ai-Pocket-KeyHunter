"""Together AI discovery pack (declarative only).

GH Stream Hunter v10 R3: together_api_key / TOGETHER_API_KEY / .env together_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

TOGETHER_OFFICIAL_ENDPOINT = "https://api.together.xyz/v1"

TOGETHER_PACK = ProviderDiscoveryPack(
    pack_id="together",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "together_api_key",
        "TOGETHER_API_KEY",
        ".env together_api_key",
        # --- supersets ---
        "TOGETHER_AI_API_KEY",
        "api.together.xyz",
        "api.together.ai",
        ".env TOGETHER_API_KEY",
        "sk- together_api_key",
        "sk- TOGETHER_API_KEY",
    ),
    code_content_anchors=(
        "TOGETHER_API_KEY",
        "TOGETHER_AI_API_KEY",
        "together_api_key",
        "api.together.xyz",
        "api.together.ai",
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
    variable_names=("TOGETHER_API_KEY", "TOGETHER_AI_API_KEY", "TOGETHER_KEY"),
    endpoint_names=("TOGETHER_BASE_URL", "TOGETHER_API_URL", "BASE_URL", "API_URL"),
    official_domains=("together.xyz", "together.ai"),
    default_endpoint=TOGETHER_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=("official_domain_auth → together; generic_token_on_gateway stays gateway"),
    capability_model_families=("together",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("together_official_env", "together_placeholder_noise"),
)

register_pack(TOGETHER_PACK)
