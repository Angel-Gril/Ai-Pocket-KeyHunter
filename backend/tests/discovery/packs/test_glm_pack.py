"""GLM vertical-slice pack + canary fixture tests."""

from __future__ import annotations

from pathlib import Path

import aipocket.discovery.packs  # noqa: F401
from aipocket.core.key_patterns import is_noise
from aipocket.discovery.packs import get_pack
from aipocket.services.config_extractor import extract_config_bundles
from aipocket.services.providers.issuer import decide_issuer

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "packs" / "glm"

# Canary dual-segment key (documented format, not a live secret).
GLM_CANARY_KEY = "f7638a0d932046079d9900bda54cdde9.79EtThsVS0IEdssm"
GLM_OFFICIAL = "https://open.bigmodel.cn/api/paas/v4"
GATEWAY_SK = "sk-canarygatewaytoken1234567890abcdef"


def test_glm_pack_registered() -> None:
    pack = get_pack("glm")
    assert pack.pack_id == "glm"
    assert pack.default_endpoint == GLM_OFFICIAL
    assert pack.balance_capability is True
    assert "glm" in pack.secret_pattern_ids
    assert "glm" in pack.capability_model_families
    assert "open.bigmodel.cn" in pack.code_content_anchors


def test_official_dual_segment_env_canary() -> None:
    content = (FIXTURES / "official_dual_segment.env").read_text()
    bundles = extract_config_bundles(content, format_hint="env")
    assert len(bundles) == 1
    b = bundles[0]
    assert b.secret_value.reveal() == GLM_CANARY_KEY
    assert b.provider_hint == "glm"
    assert b.endpoint_candidates == (GLM_OFFICIAL,)
    # Discovery-only: issuer stays unknown without auth
    decision = decide_issuer(
        apikey=b.secret_value.reveal(),
        apiurl=b.endpoint_candidates[0],
        validation_provider="glm",
        auth_confirmed=False,
        provider_hint=b.provider_hint,
        variable_names=tuple(e.variable for e in b.evidence),
    )
    assert decision.credential_issuer == "unknown"

    # After official auth → issuer=glm via exclusive key shape
    authed = decide_issuer(
        apikey=b.secret_value.reveal(),
        apiurl=b.endpoint_candidates[0],
        validation_provider="glm",
        auth_confirmed=True,
        provider_hint=b.provider_hint,
        variable_names=tuple(e.variable for e in b.evidence),
        models_available=["glm-5.1", "glm-4-flash"],
    )
    assert authed.credential_issuer == "glm"
    assert "key_shape" in authed.issuer_evidence
    assert "glm" in authed.served_model_families


def test_official_dual_segment_json_canary() -> None:
    content = (FIXTURES / "official_dual_segment.json").read_text()
    bundles = extract_config_bundles(content, format_hint="json")
    assert len(bundles) == 1
    assert bundles[0].provider_hint == "glm"
    assert bundles[0].endpoint_candidates == (GLM_OFFICIAL,)


def test_jwt_with_glm_variable_is_candidate() -> None:
    content = (FIXTURES / "jwt_with_variable.env").read_text()
    bundles = extract_config_bundles(content, format_hint="env")
    assert len(bundles) == 1
    b = bundles[0]
    assert b.provider_hint == "glm"
    assert GLM_OFFICIAL in b.endpoint_candidates
    # JWT is not exclusive shape → issuer only after official domain auth
    before = decide_issuer(
        apikey=b.secret_value.reveal(),
        apiurl=GLM_OFFICIAL,
        validation_provider="glm",
        auth_confirmed=False,
        provider_hint="glm",
        variable_names=("GLM_API_KEY",),
    )
    assert before.credential_issuer == "unknown"
    after = decide_issuer(
        apikey=b.secret_value.reveal(),
        apiurl=GLM_OFFICIAL,
        validation_provider="glm",
        auth_confirmed=True,
        provider_hint="glm",
        variable_names=("GLM_API_KEY",),
    )
    assert after.credential_issuer == "glm"
    assert (
        "official_domain" in after.issuer_evidence or "validated_endpoint" in after.issuer_evidence
    )


def test_placeholder_noise_rejected() -> None:
    content = (FIXTURES / "placeholder_noise.env").read_text()
    # is_noise should catch placeholder; extractor may yield zero secrets
    for line in content.splitlines():
        if "API_KEY=" in line:
            val = line.split("=", 1)[1].strip()
            assert is_noise(val)
    bundles = extract_config_bundles(content, format_hint="env")
    assert bundles == []


def test_yaml_placeholder_noise_rejected() -> None:
    content = (FIXTURES / "placeholder_noise.yaml").read_text()
    bundles = extract_config_bundles(content, format_hint="yaml")
    assert bundles == []


def test_gateway_sk_with_glm_models_capability_only() -> None:
    content = (FIXTURES / "gateway_sk_with_models.env").read_text()
    bundles = extract_config_bundles(content, format_hint="env")
    assert len(bundles) == 1
    b = bundles[0]
    # Generic sk without strong provider name → not glm issuer from discovery
    assert b.provider_hint != "glm" or b.provider_hint in {"openai", "unknown", "gateway"}

    decision = decide_issuer(
        apikey=GATEWAY_SK,
        apiurl="https://newapi.example.com/v1",
        validation_provider="gateway",
        auth_confirmed=True,
        models_available=["gpt-4o-mini", "glm-5.1", "glm-4-flash"],
        provider_hint=b.provider_hint,
    )
    assert decision.credential_issuer == "gateway"
    assert "glm" in decision.served_model_families
    # Model families must not rewrite issuer
    assert decision.credential_issuer != "glm"


def test_glm_default_endpoint_when_no_url() -> None:
    content = f"ZHIPUAI_API_KEY={GLM_CANARY_KEY}\n"
    bundles = extract_config_bundles(content, format_hint="env")
    assert len(bundles) == 1
    assert bundles[0].provider_hint == "glm"
    assert bundles[0].endpoint_candidates == (GLM_OFFICIAL,)
