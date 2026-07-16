"""Tests for GPT-failed batch inspect/retry + PG append semantics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aipocket.core.models import Credential, ValidationResult


def _write_failed_batch(run_dir: Path, name: str, hits: list[dict], batch_idx: int = 1) -> Path:
    path = run_dir / name
    lines = [json.dumps({"batch_idx": batch_idx, "total_hits": len(hits), "dumped_at": "t"})]
    lines.extend(json.dumps(h) for h in hits)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def run_root(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    run_id = "run_2026_07_15_14-44-29"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    return run_id, run_dir


class TestInspectGptFailed:
    def test_counts_hits_across_files(self, run_root):
        from aipocket.services.retry_gpt_failed import inspect_gpt_failed

        run_id, run_dir = run_root
        _write_failed_batch(
            run_dir,
            "gpt_failed_batch_20260715T222504Z_78.jsonl",
            [{"host": "a.com", "body": "x"}, {"host": "b.com", "body": "y"}],
            batch_idx=78,
        )
        _write_failed_batch(
            run_dir,
            "gpt_failed_batch_20260715T222550Z_111.jsonl",
            [{"host": "c.com", "body": "z"}],
            batch_idx=111,
        )
        # Archived / done files must be ignored (glob only matches *.jsonl).
        (run_dir / "gpt_failed_batch_old.jsonl.done").write_text("{}", encoding="utf-8")

        summary = inspect_gpt_failed(run_id)
        assert summary.failed_hits == 3
        assert len(summary.failed_files) == 2
        assert summary.has_failures
        by_name = {f.name: f.hits for f in summary.failed_files}
        assert by_name["gpt_failed_batch_20260715T222504Z_78.jsonl"] == 2

    def test_empty_run(self, run_root):
        from aipocket.services.retry_gpt_failed import inspect_gpt_failed

        run_id, _ = run_root
        summary = inspect_gpt_failed(run_id)
        assert summary.failed_hits == 0
        assert not summary.has_failures

    def test_invalid_run_id(self, run_root):
        from aipocket.services.retry_gpt_failed import inspect_gpt_failed

        with pytest.raises(ValueError):
            inspect_gpt_failed("../etc/passwd")


class TestRetryGptFailedService:
    @pytest.mark.asyncio
    async def test_append_path_pg_and_archive(self, run_root, monkeypatch):
        from aipocket.services import retry_gpt_failed as mod

        run_id, run_dir = run_root
        _write_failed_batch(
            run_dir,
            "gpt_failed_batch_t_1.jsonl",
            [{"host": "leak.example", "body": "sk-proj-aaaaaaaaaaaaaaaaaaaaaa"}],
            batch_idx=1,
        )

        cred = Credential(
            apikey="sk-proj-aaaaaaaaaaaaaaaaaaaaaa",
            apiurl="https://api.openai.com",
            host="api.openai.com",
        )
        result = ValidationResult(credential=cred, valid=True, status_code=200)

        async def fake_gpt(hits):
            from aipocket.services.analyzer import GPTExtractionReport

            return GPTExtractionReport(
                credentials=(cred,),
                successful_entry_ids=frozenset({"retry-0"}),
                failed_entry_ids=frozenset(),
            )

        async def fake_validate(creds):
            return [result]

        async def fake_enrich(results, **kwargs):
            return results

        async def fake_commit(results, **kwargs):
            from aipocket.services.finalizer import FinalCommitReport

            return FinalCommitReport(high_value_final=0)

        monkeypatch.setattr(mod, "extract_credentials", lambda hits: [])
        monkeypatch.setattr(mod, "extract_with_gpt", fake_gpt)
        monkeypatch.setattr(mod, "validate_all", fake_validate)
        monkeypatch.setattr(mod, "_load_existing_identities", lambda rid: set())
        monkeypatch.setattr("aipocket.services.honeypot.filter_honeypots", lambda r, **k: r)
        monkeypatch.setattr("aipocket.services.balance.enrich_results", fake_enrich)
        monkeypatch.setattr("aipocket.services.finalizer.commit_final_results", fake_commit)
        monkeypatch.setattr("aipocket.services.dedup.get_dedup_store", lambda: object())

        # PG enabled → append_results_pg is required path.
        monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x/y")
        appended: list[tuple] = []

        def fake_append_pg(rid, valid, suspicious):
            appended.append((rid, list(valid), list(suspicious)))

        monkeypatch.setattr(mod, "append_results_pg", fake_append_pg)
        # PG on + dual_write off → write_jsonl is False (no JSONL side path).
        monkeypatch.setattr("aipocket.core.config.settings.pg_dual_write", False)

        report = await mod.retry_gpt_failed(run_id)
        assert report.valid_appended == 1
        assert report.suspicious_appended == 0
        assert len(appended) == 1
        assert appended[0][0] == run_id
        assert appended[0][1][0].credential.apikey == cred.apikey
        # Source failed file archived.
        assert not (run_dir / "gpt_failed_batch_t_1.jsonl").exists()
        assert any(p.name.endswith(".done") for p in run_dir.iterdir())
        assert "PostgreSQL" in report.message

    @pytest.mark.asyncio
    async def test_dedup_skips_already_stored(self, run_root, monkeypatch):
        from aipocket.services import retry_gpt_failed as mod

        run_id, run_dir = run_root
        _write_failed_batch(
            run_dir,
            "gpt_failed_batch_t_2.jsonl",
            [{"host": "x", "body": "y"}],
        )
        cred = Credential(apikey="sk-already", apiurl="https://a.com")
        result = ValidationResult(credential=cred, valid=True, status_code=200)

        async def fake_gpt(hits):
            from aipocket.services.analyzer import GPTExtractionReport

            return GPTExtractionReport((cred,), frozenset(), frozenset())

        async def fake_validate(creds):
            return [result]

        monkeypatch.setattr(mod, "extract_credentials", lambda hits: [])
        monkeypatch.setattr(mod, "extract_with_gpt", fake_gpt)
        monkeypatch.setattr(mod, "validate_all", fake_validate)
        monkeypatch.setattr(
            mod, "_load_existing_identities", lambda rid: {("sk-already", "https://a.com")}
        )
        monkeypatch.setattr("aipocket.services.honeypot.filter_honeypots", lambda r, **k: r)
        monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x/y")

        called = []
        monkeypatch.setattr(mod, "append_results_pg", lambda *a, **k: called.append(a))

        report = await mod.retry_gpt_failed(run_id)
        assert report.valid_appended == 0
        assert called == []
        assert "already stored" in report.message
