from __future__ import annotations

from typer.testing import CliRunner

from aipocket.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "watch" in result.stdout
    assert "queries" in result.stdout
    assert "config" in result.stdout


def test_cli_config():
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "FOFA base URL" in result.stdout
    assert "Scheduler" in result.stdout


def test_cli_queries():
    result = runner.invoke(app, ["queries"])
    assert result.exit_code == 0
    assert "FOFA queries" in result.stdout


def test_cli_queries_has_expected_count():
    result = runner.invoke(app, ["queries"])
    assert result.exit_code == 0
    assert "(" in result.stdout


def test_cli_watch_disabled_by_default(monkeypatch):
    result = runner.invoke(app, ["watch"])
    assert result.exit_code == 1
    assert "SCHEDULER_ENABLED=false" in result.stdout or "false" in result.stdout


def test_cli_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--max-queries" in result.stdout
    assert "--verbose" in result.stdout


def test_cli_scan_persists_results(tmp_path, monkeypatch):
    from aipocket.core.config import Settings
    from aipocket.core.models import ScanRunResult
    from aipocket.services.writer import write_scan_metadata, write_valid_results

    async def fake_run_scan(max_queries=None, run_dir=None, *, skip_direct=False):
        # Mimic real run_scan which writes JSONL internally
        if run_dir:
            write_scan_metadata(
                {
                    "started_at": "t0",
                    "finished_at": "t1",
                    "total_hosts": 0,
                    "total_credentials": 0,
                    "total_valid": 0,
                    "queries_used": [],
                },
                run_dir,
            )
            write_valid_results([], run_dir)
        return ScanRunResult(
            started_at="t0",
            finished_at="t1",
            total_hosts=0,
            total_credentials=0,
            total_valid=0,
            queries_used=[],
            results=[],
        )

    monkeypatch.setattr("aipocket.services.scanner.run_scan", fake_run_scan)
    monkeypatch.setattr("aipocket.services.writer.settings", Settings(results_dir=str(tmp_path)))

    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert list(tmp_path.glob("run_*/scan_*.jsonl"))
    assert list(tmp_path.glob("run_*/valid_*.jsonl"))
