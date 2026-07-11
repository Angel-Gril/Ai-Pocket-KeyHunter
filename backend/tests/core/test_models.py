from __future__ import annotations

from aipocket.core.models import Credential, ProviderInfo, ScanRunResult, ValidationResult


def test_credential_defaults():
    c = Credential(apikey="sk-test", apiurl="https://api.example.com")
    assert c.source_type == "fingerprint"
    assert c.source == ""
    assert c.product == ""


def test_credential_source_type_literal():
    c = Credential(apikey="k", apiurl="u", source_type="header")
    assert c.source_type == "header"


def test_validation_result_defaults():
    c = Credential(apikey="k", apiurl="u")
    v = ValidationResult(credential=c)
    assert v.valid is False
    assert v.tier == ""
    assert v.rate_limit_headers == {}
    assert v.validated_at != ""


def test_scan_run_result_serializes():
    c = Credential(apikey="k", apiurl="u")
    v = ValidationResult(credential=c, valid=True, status_code=200, tier="tier5")
    r = ScanRunResult(
        started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:01:00",
        total_hosts=10,
        total_credentials=1,
        total_valid=1,
        queries_used=["q1"],
        results=[v],
    )
    data = r.model_dump()
    assert data["total_valid"] == 1
    assert data["results"][0]["credential"]["apikey"] == "k"
    js = r.model_dump_json()
    assert "tier5" in js


def test_credential_invalid_source_type_rejected():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Credential(apikey="k", apiurl="u", source_type="invalid")  # type: ignore[arg-type]


def test_provider_info_accepts_complete_registry_vocabulary():
    providers = {
        "openai",
        "anthropic",
        "deepseek",
        "kimi",
        "glm",
        "qwen",
        "siliconflow",
        "google",
        "groq",
        "openrouter",
        "azure_openai",
        "vertex",
        "gemini",
        "gateway",
        "ambiguous",
        "unknown",
    }
    for provider in providers:
        assert ProviderInfo(provider=provider).provider == provider  # type: ignore[arg-type]


def test_provider_info_rejects_unknown_provider_name():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ProviderInfo(provider="not-a-provider")  # type: ignore[arg-type]
