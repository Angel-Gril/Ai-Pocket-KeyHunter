"""OpenAI discovery pack (declarative only).

GH Stream Hunter v10 R3: openai_api_base / OPENAI_API_BASE / .env openai_api_base.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

OPENAI_OFFICIAL_ENDPOINT = "https://api.openai.com/v1"

OPENAI_PACK = ProviderDiscoveryPack(
    pack_id="openai",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "openai_api_base",
        "OPENAI_API_BASE",
        ".env openai_api_base",
        # --- supersets ---
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "api.openai.com",
        ".env OPENAI_API_KEY",
        "sk- OPENAI_API_KEY",
        "sk- openai_api_base",
    ),
    code_content_anchors=(
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
        "openai_api_base",
        "api.openai.com",
        "sk-proj-",
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
    secret_pattern_ids=("openai_proj", "sk_key"),
    variable_names=(
        "OPENAI_API_KEY",
        "OPENAI_KEY",
        "OPENAI_TOKEN",
    ),
    endpoint_names=(
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_API_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("openai.com", "oai.azure.com"),
    default_endpoint=OPENAI_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "sk-proj-/sk-admin-/official openai.com → openai; "
        "generic sk- on gateway stays gateway"
    ),
    capability_model_families=("openai", "gpt"),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=("openai_official_env", "openai_placeholder_noise"),
)

register_pack(OPENAI_PACK)
