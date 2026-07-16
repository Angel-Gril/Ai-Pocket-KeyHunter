"""Qwen / DashScope discovery pack (declarative only)."""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

QWEN_OFFICIAL_ENDPOINT = "https://dashscope.aliyuncs.com/compatible-mode/v1"

QWEN_PACK = ProviderDiscoveryPack(
    pack_id="qwen",
    version="1",
    commit_message_anchors=(
        "qwen api key",
        "dashscope",
        "tongyi",
        "rotate qwen",
        "remove leaked key",
    ),
    code_content_anchors=(
        "DASHSCOPE_API_KEY",
        "QWEN_API_KEY",
        "dashscope.aliyuncs.com",
        "compatible-mode/v1",
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
        "DASHSCOPE_API_KEY",
        "QWEN_API_KEY",
        "DASHSCOPE_KEY",
        "QWEN_KEY",
    ),
    endpoint_names=(
        "DASHSCOPE_BASE_URL",
        "DASHSCOPE_API_BASE",
        "QWEN_BASE_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("dashscope.aliyuncs.com", "dashscope.aliyun.com"),
    default_endpoint=QWEN_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "official_domain_auth → qwen; "
        "generic_token_on_gateway stays gateway; "
        "qwen-* models set served_model_families"
    ),
    capability_model_families=("qwen",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=("qwen_official_env", "qwen_placeholder_noise"),
)

register_pack(QWEN_PACK)
