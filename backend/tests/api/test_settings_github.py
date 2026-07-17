"""Settings API: GitHub tokens masking + connectivity check."""

from __future__ import annotations

import httpx
import respx

from aipocket.api.settings_io import check_github, current_view


def test_current_view_masks_github_tokens(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_tokens", "ghp_abcdefghijklmnop")
    monkeypatch.setattr(
        "aipocket.core.config.settings.github_api_base_url", "https://api.github.com"
    )
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", True)
    view = current_view()
    assert "****" in view.github_tokens
    assert "ghp_abcdefghijklmnop" not in view.github_tokens
    assert view.github_api_base_url == "https://api.github.com"


def test_check_github_disabled(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", False)
    r = check_github()
    assert r.status == "disabled"


def test_check_github_no_tokens(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", True)
    monkeypatch.setattr("aipocket.core.config.settings.github_tokens", "")
    r = check_github()
    assert r.status == "invalid"
    assert "GITHUB_TOKENS" in r.message


def test_check_github_requires_pg(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", True)
    monkeypatch.setattr("aipocket.core.config.settings.github_tokens", "ghp_testtoken")
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    r = check_github()
    assert r.status == "invalid"
    assert "DATABASE_URL" in r.message


@respx.mock
def test_check_github_ok(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", True)
    monkeypatch.setattr("aipocket.core.config.settings.github_tokens", "ghp_testtoken")
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x/y")
    monkeypatch.setattr(
        "aipocket.core.config.settings.github_api_base_url", "https://api.github.com"
    )
    respx.get("https://api.github.com/rate_limit").mock(
        return_value=httpx.Response(
            200,
            json={
                "resources": {
                    "core": {"remaining": 4000},
                    "search": {"remaining": 20},
                    "code_search": {"remaining": 8},
                }
            },
        )
    )
    r = check_github()
    assert r.status == "ok"
    assert r.core_remaining == 4000
    assert r.search_remaining == 20
    assert r.code_search_remaining == 8


@respx.mock
def test_check_github_auth_fail(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.github_hunter_enabled", True)
    monkeypatch.setattr("aipocket.core.config.settings.github_tokens", "ghp_bad")
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x/y")
    monkeypatch.setattr(
        "aipocket.core.config.settings.github_api_base_url", "https://api.github.com"
    )
    respx.get("https://api.github.com/rate_limit").mock(
        return_value=httpx.Response(401, json={"message": "bad"})
    )
    r = check_github()
    assert r.status == "invalid"
