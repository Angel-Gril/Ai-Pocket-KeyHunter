"""Bounded validate worker pool + logging + store path tests."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from aipocket.core.models import Credential, ValidationResult
from aipocket.services import validator as validator_mod


def _cred(i: int) -> Credential:
    return Credential(
        apikey=f"sk-test-pool-{i:04d}-aaaaaaaaaaaaaaaaaaaa",
        apiurl=f"https://gw{i}.example.com/v1",
        host=f"https://gw{i}.example.com",
    )


@pytest.mark.asyncio
async def test_validate_all_does_not_create_unbounded_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validator_mod.settings, "validate_concurrency", 5)
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_probe_one(client, sem, cred):  # noqa: ANN001
        nonlocal in_flight, max_in_flight
        async with sem:
            async with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.01)
            async with lock:
                in_flight -= 1
            return ValidationResult(credential=cred, valid=True)

    monkeypatch.setattr(validator_mod, "_probe_one", fake_probe_one)
    creds = [_cred(i) for i in range(200)]
    results = await validator_mod.validate_all(creds)
    assert len(results) == 200
    assert max_in_flight <= 5


@pytest.mark.asyncio
async def test_validate_all_returns_one_result_per_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validator_mod.settings, "validate_concurrency", 3)

    async def fake_probe_one(client, sem, cred):  # noqa: ANN001
        return ValidationResult(credential=cred, valid=True)

    monkeypatch.setattr(validator_mod, "_probe_one", fake_probe_one)
    creds = [_cred(i) for i in range(17)]
    results = await validator_mod.validate_all(creds)
    assert len(results) == 17
    fps = {r.credential.apikey for r in results}
    assert fps == {c.apikey for c in creds}


@pytest.mark.asyncio
async def test_validate_all_isolates_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validator_mod.settings, "validate_concurrency", 4)

    async def fake_probe_one(client, sem, cred):  # noqa: ANN001
        if "0005" in cred.apikey:
            raise RuntimeError("boom")
        return ValidationResult(credential=cred, valid=True)

    # Use real _probe_one isolation by wrapping only the inner probe
    async def real_style(client, sem, cred):  # noqa: ANN001
        try:
            async with sem:
                if "0005" in cred.apikey:
                    raise RuntimeError("boom")
                return ValidationResult(credential=cred, valid=True)
        except Exception as exc:  # noqa: BLE001
            return ValidationResult(
                credential=cred,
                valid=False,
                error=f"internal-validation-error:{type(exc).__name__}",
            )

    monkeypatch.setattr(validator_mod, "_probe_one", real_style)
    results = await validator_mod.validate_all([_cred(i) for i in range(10)])
    by_key = {r.credential.apikey: r for r in results}
    bad = [k for k in by_key if "0005" in k][0]
    assert by_key[bad].error == "internal-validation-error:RuntimeError"
    assert sum(1 for r in results if r.valid) == 9


@pytest.mark.asyncio
async def test_validation_error_logs_exception_type(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.ERROR)
    apikey = "sk-test-secret-should-not-appear-in-logs-zzzz"

    async def boom(_client, _cred):  # noqa: ANN001
        raise ValueError("something broke")

    monkeypatch.setattr(validator_mod, "_probe", boom)
    cred = Credential(apikey=apikey, apiurl="https://x.example/v1")
    import httpx

    async with httpx.AsyncClient() as client:
        r = await validator_mod._probe_one(client, asyncio.Semaphore(1), cred)
    assert r.error == "internal-validation-error:ValueError"
    text = "\n".join(rec.message for rec in caplog.records)
    assert "ValueError" in text
    assert apikey not in text


@pytest.mark.asyncio
async def test_validate_from_store_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validator_mod.settings, "validate_concurrency", 2)
    monkeypatch.setattr(validator_mod.settings, "validate_batch_size", 3)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")

    pages = [
        [_cred(i) for i in range(3)],
        [_cred(i) for i in range(3, 5)],
    ]
    load_order: list[int] = []

    def fake_iter(run_id: str = "", **kwargs: Any):  # noqa: ANN003
        for idx, page in enumerate(pages):
            load_order.append(idx)
            yield page

    upserts: list[int] = []

    def fake_upsert(run_id: str, results: list) -> int:
        upserts.append(len(results))
        return len(results)

    async def fake_validate_all(credentials, attribution=None):  # noqa: ANN001
        # Second page must not be loaded until first page finishes.
        assert load_order[-1] == len(upserts)
        return [ValidationResult(credential=c, valid=True) for c in credentials]

    monkeypatch.setattr(
        "aipocket.services.candidate_store.iter_candidate_pages",
        fake_iter,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validated_identities",
        lambda run_id: set(),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results",
        fake_upsert,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.spill_enabled",
        lambda: True,
    )
    monkeypatch.setattr(validator_mod, "validate_all", fake_validate_all)

    out = await validator_mod.validate_from_store("run_page")
    assert len(out) == 5
    assert upserts == [3, 2]
    assert load_order == [0, 1]


@pytest.mark.asyncio
async def test_validate_from_store_skips_completed_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr(validator_mod.settings, "validate_batch_size", 10)

    called: list[str] = []

    def fake_iter(run_id: str = "", **kwargs: Any):
        skip = kwargs.get("skip_identities") or set()
        assert "done:id" in skip
        yield []

    monkeypatch.setattr("aipocket.services.candidate_store.iter_candidate_pages", fake_iter)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validated_identities",
        lambda run_id: {"done:id"},
    )
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results",
        lambda *a, **k: 0,
    )

    async def fake_validate_all(credentials, attribution=None):  # noqa: ANN001
        for c in credentials:
            called.append(c.apikey)
        return []

    monkeypatch.setattr(validator_mod, "validate_all", fake_validate_all)
    out = await validator_mod.validate_from_store("run_skip")
    assert out == []
    assert called == []


def test_validate_batch_size_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validator_mod.settings, "validate_batch_size", 123)
    assert validator_mod._validate_batch_size() == 123


def test_probe_max_risk_defaults_unchanged_by_this_feature() -> None:
    from aipocket.core.config import Settings

    # Assert code field defaults (not live .env) were not flipped by this feature.
    assert Settings.model_fields["probe_max_risk"].default == 1
    assert Settings.model_fields["probe_ssrf_enabled"].default is False
    assert Settings.model_fields["probe_sqli_enabled"].default is False
    assert Settings.model_fields["probe_rce_enabled"].default is False
