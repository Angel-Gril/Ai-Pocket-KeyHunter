from __future__ import annotations

import json

import pytest

from aipocket.config import Settings
from aipocket.models import Credential, ScanRunResult, ValidationResult
from aipocket.writer import write_raw_hits, write_result, load_latest, new_run_dir


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

    full_path = write_result(sample_result)

    assert full_path.exists()
    assert full_path.suffix == ".jsonl"
    lines = [ln for ln in full_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # First line = metadata, then one line per result
    assert len(lines) == 3  # 1 metadata + 2 results
    metadata = json.loads(lines[0])
    assert metadata["total_valid"] == 1
    assert metadata["total_credentials"] == 2
    # Second line = first result
    r1 = json.loads(lines[1])
    assert r1["credential"]["apikey"] == "sk-proj-valid123"
    assert r1["valid"] is True


async def test_write_result_creates_valid_file(tmp_path, sample_result, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    write_result(sample_result)

    valid_files = list(tmp_path.glob("valid_*.jsonl"))
    assert len(valid_files) == 1
    lines = [ln for ln in valid_files[0].read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1  # only 1 valid result
    entry = json.loads(lines[0])
    assert entry["credential"]["apikey"] == "sk-proj-valid123"


async def test_write_result_writes_into_run_dir(tmp_path, sample_result, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    run_dir = new_run_dir(tmp_path)
    full_path = write_result(sample_result, run_dir=run_dir)

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
    p = write_result(empty)
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # Only metadata line, no results
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["total_valid"] == 0


async def test_write_result_strips_unicode_line_separators(tmp_path, monkeypatch):
    # U+2028 (LINE SEPARATOR) must be sanitized in JSONL output
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
    p = write_result(result)

    raw = p.read_bytes()
    assert "\u2028".encode("utf-8") not in raw
    assert "\u2029".encode("utf-8") not in raw

    # Parse the result line (second line)
    lines = p.read_text(encoding="utf-8").splitlines()
    result_line = json.loads(lines[1])
    ctx = result_line["credential"]["raw_context"]
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

    # Each line is one hit
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert "中文" in data["title"]
    assert data["title"].count(" ") >= 1


async def test_load_latest_returns_valid_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))

    # Create a run dir with valid_*.jsonl
    run_dir = tmp_path / "run_2026_01_01_00-00-00"
    run_dir.mkdir()
    valid_path = run_dir / "valid_20260101T000000Z.jsonl"
    entry = {"credential": {"apikey": "sk-proj-test123", "apiurl": "https://api.openai.com"}, "valid": True}
    valid_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    result = load_latest()
    assert result is not None
    assert len(result) == 1
    assert result[0]["credential"]["apikey"] == "sk-proj-test123"


async def test_load_latest_returns_none_when_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.writer.settings", Settings(results_dir=str(tmp_path)))
    assert load_latest() is None
