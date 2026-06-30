from __future__ import annotations

import pytest

from aipocket.config import Settings


def test_keys_parsed_from_comma_string(monkeypatch):
    monkeypatch.setenv("FOFA_KEYS", "key1, key2 ,  key3  ")
    s = Settings()
    assert s.keys == ["key1", "key2", "key3"]


def test_empty_keys_stripped(monkeypatch):
    monkeypatch.setenv("FOFA_KEYS", "  ,  ,  ")
    s = Settings()
    assert s.keys == []


def test_results_path_creates_dir(tmp_path, monkeypatch):
    target = tmp_path / "out"
    monkeypatch.setenv("RESULTS_DIR", str(target))
    s = Settings()
    assert s.results_path == target
    assert target.exists()


def test_defaults(monkeypatch):
    monkeypatch.delenv("FOFA_KEYS", raising=False)
    s = Settings()
    assert s.fofa_base_url == "https://fofoapi.com"
    assert s.fofa_page_size == 100
    assert s.scheduler_enabled is False


def test_no_keys_raises_on_access():
    from aipocket.fofa_client import FofaClient
    with pytest.raises(RuntimeError):
        FofaClient(keys=[])
