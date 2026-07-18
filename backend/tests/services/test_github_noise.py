"""Tests for GitHub artifact path noise filtering."""

from __future__ import annotations

from aipocket.services.github_noise import is_noise_artifact_path


def test_keeps_real_env_files():
    assert is_noise_artifact_path(".env") is False
    assert is_noise_artifact_path("backend/.env") is False
    assert is_noise_artifact_path(".env.example") is False
    assert is_noise_artifact_path("config/settings.py") is False
    # Service name containing "example" as a word prefix should not be dropped.
    assert is_noise_artifact_path("services/example_service/config.py") is False
    assert is_noise_artifact_path("src/example_service.py") is False


def test_skips_catalog_and_example_noise():
    assert is_noise_artifact_path("extensions/fireworks/openclaw.plugin.json")
    assert is_noise_artifact_path("scripts/lib/official-external-provider-catalog.json")
    assert is_noise_artifact_path("config.example.toml")
    assert is_noise_artifact_path("docs/provider-catalog.json")
    assert is_noise_artifact_path("README.md")
    assert is_noise_artifact_path("examples/demo.env")
    assert is_noise_artifact_path("fixtures/keys.json")
