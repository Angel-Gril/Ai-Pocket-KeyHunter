"""Azure OpenAI discovery pack (declarative only).

GH Stream Hunter v10 R3: azure_openai_api_key / AZURE_OPENAI_API_KEY / .env azure_openai_api_key.
"""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

AZURE_OPENAI_PACK = ProviderDiscoveryPack(
    pack_id="azure_openai",
    version="2",
    commit_message_anchors=(
        # --- gh_stream_v10_r3 ---
        "azure_openai_api_key",
        "AZURE_OPENAI_API_KEY",
        ".env azure_openai_api_key",
        # --- supersets ---
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_KEY",
        "openai.azure.com",
        ".env AZURE_OPENAI_ENDPOINT",
        ".env AZURE_OPENAI_API_KEY",
    ),
    code_content_anchors=(
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_KEY",
        "AZURE_OPENAI_DEPLOYMENT",
        "OPENAI_API_TYPE",
        "azure_openai_api_key",
        "openai.azure.com",
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
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_KEY",
        "AZURE_OPENAI_APIKEY",
    ),
    endpoint_names=(
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_BASE",
        "AZURE_OPENAI_API_BASE",
        "OPENAI_API_BASE",
        "BASE_URL",
    ),
    official_domains=("openai.azure.com", "cognitiveservices.azure.com"),
    default_endpoint="https://api.openai.com/v1",
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "openai.azure.com host + api-key header style → azure_openai; "
        "do not force-validate azure keys against platform.openai.com"
    ),
    capability_model_families=("azure_openai", "openai"),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=False,
    canary_fixture_ids=("azure_openai_official_env", "azure_openai_placeholder_noise"),
)

register_pack(AZURE_OPENAI_PACK)
