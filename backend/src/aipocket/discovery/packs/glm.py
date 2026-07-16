"""GLM / Zhipu / BigModel discovery pack (WS-D vertical slice)."""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import register_pack

GLM_OFFICIAL_ENDPOINT = "https://open.bigmodel.cn/api/paas/v4"

GLM_PACK = ProviderDiscoveryPack(
    pack_id="glm",
    version="1",
    commit_message_anchors=(
        "glm api key",
        "zhipu",
        "bigmodel",
        "rotate glm",
        "remove leaked key",
    ),
    code_content_anchors=(
        "GLM_API_KEY",
        "ZHIPUAI_API_KEY",
        "BIGMODEL_API_KEY",
        "ZHIPU_API_KEY",
        "open.bigmodel.cn",
        "api.zhipuai.cn",
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
    secret_pattern_ids=("glm", "glm_jwt", "sk_key"),
    variable_names=(
        "GLM_API_KEY",
        "GLM_KEY",
        "ZHIPUAI_API_KEY",
        "ZHIPU_API_KEY",
        "BIGMODEL_API_KEY",
        "ZHIPUAI_KEY",
    ),
    endpoint_names=(
        "GLM_BASE_URL",
        "GLM_API_URL",
        "ZHIPU_BASE_URL",
        "BIGMODEL_BASE_URL",
        "BASE_URL",
        "API_URL",
    ),
    official_domains=("bigmodel.cn", "zhipuai.cn", "zhipuai.com"),
    default_endpoint=GLM_OFFICIAL_ENDPOINT,
    config_formats=("env", "json", "yaml", "toml"),
    issuer_rule=(
        "exclusive_key_shape_or_official_domain_auth; "
        "generic_token_on_gateway stays gateway; "
        "glm-* models only set served_model_families"
    ),
    capability_model_families=("glm",),
    noise_rules=("placeholder", "example", "your_key", "changeme"),
    balance_capability=True,
    canary_fixture_ids=(
        "glm_official_dual_segment",
        "glm_jwt_with_variable",
        "glm_placeholder_noise",
        "glm_gateway_sk_with_models",
    ),
)

register_pack(GLM_PACK)
