from __future__ import annotations

import json

import pytest

from aipocket.config import Settings
from aipocket.models import Credential, ScanRunResult, ValidationResult
from aipocket.writer import write_result


@pytest.fixture
def sample_result():
    c1 = Credential(apikey="sk-proj-valid123", apiurl="https://api.a.com", source="openai")
    c2 = Credential(apikey="sk-bad", apiurl="https://api.b.com")
    return ScanRunResult(
        started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:01:00",
        total_hosts=5,
        total_credentials=2,
        total_valid=1,
        queries_used=["q1", "q2"],
        results=[
            ValidationResult(credential=c1, valid=True, status_code=200, tier="tier5", model_available="gpt-4o-mini"),
            ValidationResult(credential=c2, valid=False, error="connect"),
        ],
    )


async def test_write_result_creates_files(tmp_path, sample_result, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    full_path = await write_result(sample_result)

    assert full_path.exists()
    assert full_path.suffix == ".json"
    data = json.loads(full_path.read_text())
    assert data["total_valid"] == 1
    assert data["total_credentials"] == 2
    assert len(data["results"]) == 2


async def test_write_result_creates_valid_file(tmp_path, sample_result, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    await write_result(sample_result)

    valid_files = list(tmp_path.glob("valid_*.json"))
    assert len(valid_files) == 1
    valid_data = json.loads(valid_files[0].read_text())
    assert valid_data["total_valid"] == 1
    assert len(valid_data["credentials"]) == 1
    assert valid_data["credentials"][0]["credential"]["apikey"] == "sk-proj-valid123"


async def test_write_result_updates_latest(tmp_path, sample_result, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    await write_result(sample_result)

    latest_valid = tmp_path / "latest_valid.json"
    latest_full = tmp_path / "latest_scan.json"
    assert latest_valid.exists()
    assert latest_full.exists()
    latest_data = json.loads(latest_valid.read_text())
    assert latest_data["total_valid"] == 1


async def test_write_result_empty_results(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))
    empty = ScanRunResult(
        started_at="t0",
        finished_at="t1",
        total_hosts=0,
        total_credentials=0,
        total_valid=0,
        queries_used=[],
        results=[],
    )
    p = await write_result(empty)
    data = json.loads(p.read_text())
    assert data["total_valid"] == 0
