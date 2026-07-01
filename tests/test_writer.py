from __future__ import annotations

import json

import pytest

from aipocket.config import Settings
from aipocket.models import Credential, ScanRunResult, ValidationResult
from aipocket.writer import write_raw_hits, write_result


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


async def test_write_result_writes_into_run_dir(tmp_path, sample_result, monkeypatch):
    # Per-run folders: scan_*.json + valid_*.json live inside run_*/, no root-level
    # latest_*.json anymore.
    from aipocket.writer import new_run_dir

    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    run_dir = new_run_dir(tmp_path)
    full_path = await write_result(sample_result, run_dir=run_dir)

    # Files land inside the run_* folder.
    assert full_path.parent == run_dir
    assert run_dir.parent == tmp_path
    assert run_dir.name.startswith("run_")
    # No root-level latest symlinks/files anymore.
    assert not (tmp_path / "latest_valid.json").exists()
    assert not (tmp_path / "latest_scan.json").exists()


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


async def test_write_result_strips_unicode_line_separators(tmp_path, monkeypatch):
    # U+2028 (LINE SEPARATOR) 会让 VSCode 的 JSON 语言服务报 unusual line terminators
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))
    c = Credential(
        apikey="sk-x",
        apiurl="https://a.com",
        source="openai",
        raw_context="title=中文标题\u2028 Behind every AI",
    )
    result = ScanRunResult(
        started_at="t0",
        finished_at="t1",
        total_hosts=1,
        total_credentials=1,
        total_valid=1,
        queries_used=["q"],
        results=[ValidationResult(credential=c, valid=True, status_code=200)],
    )
    p = await write_result(result)

    raw = p.read_bytes()
    assert "\u2028".encode("utf-8") not in raw
    assert "\u2029".encode("utf-8") not in raw

    data = json.loads(p.read_text())
    ctx = data["results"][0]["credential"]["raw_context"]
    assert "\u2028" not in ctx
    assert "中文标题" in ctx


def test_write_raw_hits_strips_unicode_line_separators(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))
    hits = [
        {
            "title": "Behind every AI:\u2028a human expert 中文",
            "cert": "Signature:\n  AA:BB\u2029CC",
        }
    ]
    p = write_raw_hits(hits)

    raw = p.read_bytes()
    assert "\u2028".encode("utf-8") not in raw
    assert "\u2029".encode("utf-8") not in raw

    data = json.loads(p.read_text())
    assert "中文" in data["hits"][0]["title"]
    assert data["hits"][0]["title"].count(" ") >= 1
