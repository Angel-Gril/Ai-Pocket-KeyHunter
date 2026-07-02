"""Tests for high_value_writer — real-time persistence of official keys."""

from __future__ import annotations

import json

import pytest

from aipocket.config import Settings
from aipocket.high_value_writer import (
    is_alive_status,
    is_high_value_key,
    load_all,
    reset_session,
    save_high_value_key,
    should_save,
    try_save,
)
from aipocket.models import Credential, ValidationResult


@pytest.fixture(autouse=True)
def _reset_dedup():
    """Reset dedup set before each test."""
    reset_session()
    yield
    reset_session()


@pytest.fixture
def _patch_results_dir(tmp_path, monkeypatch):
    """Point settings.results_dir to a temp dir."""
    monkeypatch.setattr(
        "aipocket.high_value_writer.settings",
        Settings(results_dir=str(tmp_path)),
    )
    return tmp_path


class TestIsHighValueKey:
    def test_openai_proj(self):
        assert is_high_value_key("sk-proj-abc123xyz456def789") is True

    def test_openai_admin(self):
        assert is_high_value_key("sk-admin-abc123xyz456def789") is True

    def test_openai_svcacct(self):
        assert is_high_value_key("sk-svcacct-abc123xyz456def789") is True

    def test_anthropic(self):
        assert is_high_value_key("sk-ant-api03-foobar123456") is True

    def test_regular_sk(self):
        assert is_high_value_key("sk-random1234567890") is False

    def test_openrouter(self):
        assert is_high_value_key("sk-or-v1-abc123def456") is False

    def test_empty(self):
        assert is_high_value_key("") is False


class TestIsAliveStatus:
    def test_200(self):
        assert is_alive_status(200) is True

    def test_429(self):
        assert is_alive_status(429) is True

    def test_401(self):
        assert is_alive_status(401) is False

    def test_403(self):
        assert is_alive_status(403) is False

    def test_none(self):
        assert is_alive_status(None) is False


class TestShouldSave:
    def _make_result(self, apikey: str, status_code: int | None) -> ValidationResult:
        cred = Credential(apikey=apikey, apiurl="https://api.openai.com/v1")
        return ValidationResult(credential=cred, status_code=status_code)

    def test_openai_proj_200(self):
        r = self._make_result("sk-proj-valid123456789", 200)
        assert should_save(r) is True

    def test_openai_proj_429(self):
        r = self._make_result("sk-proj-ratelimited123", 429)
        assert should_save(r) is True

    def test_anthropic_200(self):
        r = self._make_result("sk-ant-api03-valid12345", 200)
        assert should_save(r) is True

    def test_openai_proj_401(self):
        r = self._make_result("sk-proj-dead12345", 401)
        assert should_save(r) is False

    def test_regular_sk_200(self):
        r = self._make_result("sk-generic12345678901", 200)
        assert should_save(r) is False


class TestSaveHighValueKey:
    def test_writes_jsonl(self, _patch_results_dir, tmp_path):
        cred = Credential(
            apikey="sk-proj-test1234567890abc",
            apiurl="https://api.openai.com/v1",
            source="openai_proj",
        )
        result = ValidationResult(
            credential=cred,
            status_code=200,
            valid=True,
            tier="tier5",
        )
        assert save_high_value_key(result) is True

        path = tmp_path / "high_value_keys" / "keys.jsonl"
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8").strip())
        assert data["apikey"] == "sk-proj-test1234567890abc"
        assert data["status_code"] == 200
        assert data["valid"] is True

    def test_deduplicates(self, _patch_results_dir, tmp_path):
        cred = Credential(
            apikey="sk-proj-dupkey1234567890",
            apiurl="https://api.openai.com/v1",
        )
        r = ValidationResult(credential=cred, status_code=200, valid=True)

        assert save_high_value_key(r) is True
        assert save_high_value_key(r) is False  # duplicate

        path = tmp_path / "high_value_keys" / "keys.jsonl"
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 1

    def test_appends_multiple(self, _patch_results_dir, tmp_path):
        keys = ["sk-proj-aaa1234567890", "sk-ant-bbb1234567890"]
        for key in keys:
            cred = Credential(apikey=key, apiurl="https://api.openai.com/v1")
            r = ValidationResult(credential=cred, status_code=200, valid=True)
            save_high_value_key(r)

        path = tmp_path / "high_value_keys" / "keys.jsonl"
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 2


class TestTrySave:
    def test_saves_qualifying(self, _patch_results_dir, tmp_path):
        cred = Credential(
            apikey="sk-proj-qualifying123456",
            apiurl="https://api.openai.com/v1",
        )
        r = ValidationResult(credential=cred, status_code=429, valid=False)
        try_save(r)

        path = tmp_path / "high_value_keys" / "keys.jsonl"
        assert path.exists()

    def test_skips_non_qualifying(self, _patch_results_dir, tmp_path):
        cred = Credential(
            apikey="sk-generic-key12345678",
            apiurl="https://api.openai.com/v1",
        )
        r = ValidationResult(credential=cred, status_code=200, valid=True)
        try_save(r)

        path = tmp_path / "high_value_keys" / "keys.jsonl"
        assert not path.exists()


class TestLoadAll:
    def test_loads_entries(self, _patch_results_dir, tmp_path):
        d = tmp_path / "high_value_keys"
        d.mkdir()
        path = d / "keys.jsonl"
        entries = [
            {"apikey": "sk-proj-one", "status_code": 200},
            {"apikey": "sk-ant-two", "status_code": 429},
        ]
        path.write_text(
            "\n".join(json.dumps(e) for e in entries) + "\n",
            encoding="utf-8",
        )

        loaded = load_all()
        assert len(loaded) == 2
        assert loaded[0]["apikey"] == "sk-proj-one"
        assert loaded[1]["apikey"] == "sk-ant-two"

    def test_empty_file(self, _patch_results_dir, tmp_path):
        d = tmp_path / "high_value_keys"
        d.mkdir()
        (d / "keys.jsonl").write_text("", encoding="utf-8")
        assert load_all() == []

    def test_missing_file(self, _patch_results_dir):
        assert load_all() == []
