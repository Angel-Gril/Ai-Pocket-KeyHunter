"""Unit tests for the web API layer."""

from __future__ import annotations

import json

import pytest

from aipocket.api import masking


# ---------------------------------------------------------------------------
# masking
# ---------------------------------------------------------------------------
def test_mask_apikey_openai_project():
    assert masking.mask_apikey("sk-proj-abcdefghijklmnop") == "sk-proj-****mnop"


def test_mask_apikey_anthropic():
    m = masking.mask_apikey("sk-ant-api03-ABCDEFGHIJKLMN")
    assert m.startswith("sk-ant-") and m.endswith("KLMN") and "****" in m


def test_mask_apikey_google():
    assert masking.mask_apikey("AIzaSyD1234567890abcd").startswith("AIza")
    assert masking.mask_apikey("AIzaSyD1234567890abcd").endswith("abcd")


def test_mask_apikey_short_fully_masked():
    assert masking.mask_apikey("short") == "****"
    assert masking.mask_apikey("") == ""


def test_mask_apikey_generic():
    assert masking.mask_apikey("randomtokenvalue1234") == "rand****1234"


def test_mask_keys_csv():
    out = masking.mask_keys_csv("sk-proj-aaaaaaaaaaaa, sk-proj-bbbbbbbbbbbb")
    assert out == "sk-proj-****aaaa, sk-proj-****bbbb"


# ---------------------------------------------------------------------------
# auth token round-trip
# ---------------------------------------------------------------------------
def test_issue_and_verify_token(monkeypatch):
    from aipocket.api import deps as auth

    monkeypatch.setattr("aipocket.core.config.settings.web_password", "secret-pw")
    monkeypatch.setattr("aipocket.core.config.settings.web_jwt_secret", "jwt-secret-value")
    monkeypatch.setattr("aipocket.core.config.settings.web_token_ttl", 3600)

    assert auth.verify_password("secret-pw") is True
    assert auth.verify_password("wrong") is False

    token, ttl = auth.issue_token()
    assert ttl == 3600
    payload = auth._decode(token)
    assert payload["sub"] == "web-user"


# ---------------------------------------------------------------------------
# results_reader
# ---------------------------------------------------------------------------
def _write_run(root, run_id, valid_rows, susp_rows=None):
    run = root / run_id
    run.mkdir(parents=True)
    vf = run / "valid_20260706T000000Z.jsonl"
    with vf.open("w", encoding="utf-8") as f:
        for r in valid_rows:
            f.write(json.dumps(r) + "\n")
    if susp_rows:
        sf = run / "suspicious_20260706T000000Z.jsonl"
        with sf.open("w", encoding="utf-8") as f:
            for r in susp_rows:
                f.write(json.dumps(r) + "\n")
    (run / "run.log").write_text("log line 1\nlog line 2\n", encoding="utf-8")
    return run


def _rec(apikey, apiurl="https://api.openai.com", valid=True, backend="fofa"):
    return {
        "credential": {
            "apikey": apikey,
            "apiurl": apiurl,
            "host": "api.openai.com",
            "backend": backend,
        },
        "valid": valid,
        "status_code": 200,
        "provider_info": {"provider": "openai"},
    }


@pytest.fixture
def results_root(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    return tmp_path


def test_list_runs_grouped_by_day(results_root):
    from aipocket.api import results_reader

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-aaaaaaaaaaaa")])
    _write_run(results_root, "run_2026_07_06_12-00-00", [_rec("sk-proj-bbbbbbbbbbbb")])
    _write_run(results_root, "run_2026_07_05_09-00-00", [_rec("sk-proj-cccccccccccc")])

    days = results_reader.list_runs()
    assert [d["day"] for d in days] == ["2026-07-06", "2026-07-05"]
    # newest run first within the day
    assert days[0]["runs"][0]["run_id"] == "run_2026_07_06_12-00-00"
    assert days[0]["runs"][0]["valid_count"] == 1


def test_list_runs_extended_fields(results_root):
    from aipocket.api import results_reader

    run = _write_run(
        results_root,
        "run_2026_07_06_10-00-00",
        [
            _rec("sk-proj-aaaaaaaaaaaa", backend="fofa"),
            _rec("sk-proj-bbbbbbbbbbbb", backend="shodan"),
        ],
    )
    (run / "scan_20260706T000000Z.jsonl").write_text(
        json.dumps(
            {
                "raw_hits": 9,
                "unique_targets": 3,
                "candidates": 2,
                "active_requests": 2,
                "final_verified": 2,
                "suspicious": 0,
                "high_value_final": 1,
            }
        )
        + "\n{}\n{}\n",
        encoding="utf-8",
    )
    # global high-value log; the entry's saved_at falls after this run's start
    hv = results_root / "high_value_keys"
    hv.mkdir(parents=True)
    (hv / "keys.jsonl").write_text(
        json.dumps({"apikey": "sk-proj-aaaaaaaaaaaa", "saved_at": "2026-07-06T10:05:00+00:00"})
        + "\n",
        encoding="utf-8",
    )

    entry = results_reader.list_runs()[0]["runs"][0]
    assert entry["raw_hits"] == 9
    assert entry["unique_targets"] == 3
    assert entry["candidates"] == 2
    assert entry["active_requests"] == 2
    assert entry["final_verified"] == 2
    assert entry["suspicious"] == 0
    assert entry["high_value_final"] == 1
    assert "hits" not in entry
    assert entry["sources"] == ["fofa", "shodan"]
    # backward-compatible keys still present
    assert entry["valid_count"] == 2
    assert entry["has_log"] is True


def test_load_run_records_masks_apikey(results_root):
    from aipocket.api import results_reader

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-abcdefghijklmnop")])
    recs = results_reader.load_run_records("run_2026_07_06_10-00-00", "valid")
    assert recs[0]["credential"]["apikey"] == "sk-proj-****mnop"


def test_reveal_apikey_by_masked(results_root):
    from aipocket.api import results_reader

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-abcdefghijklmnop")])
    found = results_reader.reveal_apikey(
        "run_2026_07_06_10-00-00", "valid", masked="sk-proj-****mnop"
    )
    assert found["apikey"] == "sk-proj-abcdefghijklmnop"


def test_reveal_apikey_by_index(results_root):
    from aipocket.api import results_reader

    _write_run(
        results_root,
        "run_2026_07_06_10-00-00",
        [_rec("sk-proj-first1234567"), _rec("sk-proj-second234567")],
    )
    found = results_reader.reveal_apikey("run_2026_07_06_10-00-00", "valid", index=1)
    assert found["apikey"] == "sk-proj-second234567"


def test_run_id_rejects_path_traversal(results_root):
    from aipocket.api import results_reader
    from aipocket.api.errors import ApiError

    with pytest.raises(ApiError):
        results_reader.load_run_records("../../etc", "valid")
    with pytest.raises(ApiError):
        results_reader.read_run_log("run_../../secret")


def test_read_run_log(results_root):
    from aipocket.api import results_reader

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-abcdefghijkl")])
    assert "log line 1" in results_reader.read_run_log("run_2026_07_06_10-00-00")


# ---------------------------------------------------------------------------
# exporter
# ---------------------------------------------------------------------------
def test_export_selected_json():
    from aipocket.api.exporter import build_export
    from aipocket.api.schemas import ExportRequest, KeyRef

    req = ExportRequest(
        dataset="selected",
        format="json",
        keys=[KeyRef(apikey="sk-proj-plaintext123", apiurl="https://x")],
    )
    content, media, name = build_export(req)
    assert media == "application/json" and name.endswith(".json")
    data = json.loads(content)
    assert data[0]["apikey"] == "sk-proj-plaintext123"


def test_export_run_csv(results_root):
    from aipocket.api.exporter import build_export
    from aipocket.api.schemas import ExportRequest

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-plaintextabc")])
    req = ExportRequest(dataset="run", format="csv", run_id="run_2026_07_06_10-00-00")
    content, media, name = build_export(req)
    assert media == "text/csv" and name.endswith(".csv")
    text = content.decode()
    assert "apikey" in text.splitlines()[0]
    assert "sk-proj-plaintextabc" in text  # plaintext in export


def test_export_selected_by_indices(results_root):
    """Selected export reads plaintext server-side by index (no client round-trip)."""
    from aipocket.api.exporter import build_export
    from aipocket.api.schemas import ExportRequest

    _write_run(
        results_root,
        "run_2026_07_06_10-00-00",
        [_rec("sk-proj-first1234567"), _rec("sk-proj-second234567")],
    )
    req = ExportRequest(
        dataset="selected",
        format="json",
        run_id="run_2026_07_06_10-00-00",
        indices=[1],
    )
    content, _media, _name = build_export(req)
    data = json.loads(content)
    assert len(data) == 1
    assert data[0]["apikey"] == "sk-proj-second234567"


def test_load_all_records_dedup_newest_wins(results_root):
    """Cross-run aggregation keeps one row per apikey from the newest run."""
    from aipocket.api import masking, results_reader

    _write_run(
        results_root,
        "run_2026_07_06_10-00-00",
        [
            _rec("sk-proj-sharedkey12345", apiurl="https://old.example"),
            _rec("sk-proj-only-old-key99"),
            _rec("sk-proj-sharedkey12345", apiurl="https://old-dup.example"),  # same-run dup
        ],
    )
    _write_run(
        results_root,
        "run_2026_07_07_12-00-00",
        [
            _rec("sk-proj-sharedkey12345", apiurl="https://new.example"),
            _rec("sk-proj-only-new-key88"),
        ],
    )

    plain = results_reader.load_all_records_plain("valid")
    keys = {(r["credential"]["apikey"], r["credential"]["apiurl"]) for r in plain}
    assert keys == {
        ("sk-proj-sharedkey12345", "https://new.example"),
        ("sk-proj-only-new-key88", "https://api.openai.com"),
        ("sk-proj-only-old-key99", "https://api.openai.com"),
    }
    shared = next(r for r in plain if r["credential"]["apikey"] == "sk-proj-sharedkey12345")
    assert shared["source_run_id"] == "run_2026_07_07_12-00-00"
    assert shared["source_index"] == 0

    masked = results_reader.load_all_records("valid")
    assert all("****" in r["credential"]["apikey"] for r in masked)
    assert masking.mask_apikey("sk-proj-sharedkey12345") in {
        r["credential"]["apikey"] for r in masked
    }


def test_export_all_dataset(results_root):
    from aipocket.api.exporter import build_export
    from aipocket.api.schemas import ExportRequest

    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-exportallkey1")])
    _write_run(
        results_root,
        "run_2026_07_07_12-00-00",
        [_rec("sk-proj-exportallkey1"), _rec("sk-proj-exportallkey2")],
    )
    content, media, name = build_export(ExportRequest(dataset="all", format="json", kind="valid"))
    assert media == "application/json" and name.endswith(".json")
    data = json.loads(content)
    assert len(data) == 2
    assert {row["apikey"] for row in data} == {"sk-proj-exportallkey1", "sk-proj-exportallkey2"}

    # Subset by indices into the deduped list
    content2, _, _ = build_export(
        ExportRequest(dataset="all", format="json", kind="valid", indices=[0])
    )
    assert len(json.loads(content2)) == 1


# ---------------------------------------------------------------------------
# scan_manager state machine
# ---------------------------------------------------------------------------
def test_scan_manager_initial_state():
    from aipocket.api.scan_manager import ScanManager

    mgr = ScanManager()
    st = mgr.status()
    assert st["state"] == "idle"
    assert st["run_id"] is None


def test_scan_manager_log_buffer_does_not_parse_progress_from_prose():
    from aipocket.api.scan_manager import ScanManager

    mgr = ScanManager()
    mgr._ingest_log("12:00:00 [INFO] aipocket.scanner: Total hits: 42 (sources: fofa)")
    mgr._ingest_log("12:00:01 [INFO] aipocket.scanner: Validating 7 credentials (concurrency=20)")
    mgr._ingest_log(
        "12:00:02 [INFO] aipocket.high_value_writer: high_value_key saved: sk-proj-abcd…  status=200"
    )
    lines, last = mgr.logs_since(0)
    assert len(lines) == 3
    assert last == 3
    st = mgr.status()
    assert st["progress"] == {
        "raw_hits": 0,
        "unique_targets": 0,
        "candidates": 0,
        "active_requests": 0,
        "final_verified": 0,
        "suspicious": 0,
        "high_value_final": 0,
    }
    # since filter
    lines2, _ = mgr.logs_since(1)
    assert len(lines2) == 2


@pytest.mark.asyncio
async def test_scan_manager_preserves_explicit_zero_metrics(tmp_path, monkeypatch):
    from aipocket.api.scan_manager import ScanManager
    from aipocket.core.models import Credential, ScanRunResult, ValidationResult

    result = ScanRunResult(
        started_at="2026-07-06T10:00:00+00:00",
        finished_at="2026-07-06T10:01:00+00:00",
        sources=["fofa"],
        total_hosts=9,
        total_credentials=8,
        total_valid=7,
        queries_used=["q"],
        results=[ValidationResult(credential=Credential(apikey="sk-test"), suspicious=True)],
        raw_hits=[{"host": "example.com"}],
    )

    async def fake_run_scan(**_kwargs):
        return result

    monkeypatch.setattr("aipocket.services.scanner.run_scan", fake_run_scan)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    mgr = ScanManager()
    mgr._run_dir = tmp_path

    await mgr._run("fofa")

    assert mgr.status()["progress"] == {
        "raw_hits": 0,
        "unique_targets": 0,
        "candidates": 0,
        "active_requests": 0,
        "final_verified": 0,
        "suspicious": 0,
        "high_value_final": 0,
    }


@pytest.mark.asyncio
async def test_scan_manager_stop_when_idle_raises():
    from aipocket.api.scan_manager import ScanManager

    mgr = ScanManager()
    with pytest.raises(RuntimeError):
        await mgr.stop()


# ---------------------------------------------------------------------------
# End-to-end via TestClient — auth gating + a couple of read endpoints
# ---------------------------------------------------------------------------
@pytest.fixture
def client(results_root, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.web_password", "pw-123")
    monkeypatch.setattr("aipocket.core.config.settings.web_jwt_secret", "jwt-secret-xyz")
    from fastapi.testclient import TestClient

    from aipocket.api.app import create_app

    return TestClient(create_app())


def _login(client) -> dict[str, str]:
    r = client.post("/api/auth/login", json={"password": "pw-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_health_is_unauthenticated(client):
    assert client.get("/api/health").json() == {"ok": True}


def test_runs_requires_auth(client):
    assert client.get("/api/runs").status_code == 401


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", json={"password": "nope"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_login_rate_limited_after_repeated_failures(client):
    from aipocket.api import deps as auth

    auth.reset_login_failures("testclient")  # isolate from other tests
    try:
        for _ in range(auth._LOGIN_MAX_FAILURES):
            assert client.post("/api/auth/login", json={"password": "nope"}).status_code == 401
        blocked = client.post("/api/auth/login", json={"password": "nope"})
        assert blocked.status_code == 429
        assert blocked.json()["error"]["code"] == "rate_limited"
    finally:
        auth.reset_login_failures("testclient")  # don't block later tests


def test_runs_after_login(client, results_root):
    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-abcdefghijkl")])
    headers = _login(client)
    r = client.get("/api/runs", headers=headers)
    assert r.status_code == 200
    days = r.json()["days"]
    assert days[0]["day"] == "2026-07-06"


def test_run_valid_masked_then_reveal(client, results_root):
    _write_run(results_root, "run_2026_07_06_10-00-00", [_rec("sk-proj-abcdefghijklmnop")])
    headers = _login(client)

    listed = client.get("/api/runs/run_2026_07_06_10-00-00/valid", headers=headers).json()
    masked = listed["results"][0]["credential"]["apikey"]
    assert masked == "sk-proj-****mnop"

    revealed = client.post(
        "/api/key/reveal",
        headers=headers,
        json={"run_id": "run_2026_07_06_10-00-00", "masked": masked, "kind": "valid"},
    )
    assert revealed.status_code == 200
    assert revealed.json()["apikey"] == "sk-proj-abcdefghijklmnop"


def test_scan_status_idle(client):
    headers = _login(client)
    r = client.get("/api/scan/status", headers=headers)
    assert r.status_code == 200
    assert r.json()["state"] == "idle"


def test_gpt_failed_status_and_retry_start(client, results_root, monkeypatch):
    """GET pending failed batches; POST starts background job (mocked worker)."""
    import asyncio
    import json

    run_id = "run_2026_07_15_14-44-29"
    run = results_root / run_id
    run.mkdir(parents=True)
    failed = run / "gpt_failed_batch_20260715T222504Z_78.jsonl"
    failed.write_text(
        json.dumps({"batch_idx": 78, "total_hits": 1, "dumped_at": "t"})
        + "\n"
        + json.dumps({"host": "x.com", "body": "sk-test"})
        + "\n",
        encoding="utf-8",
    )
    (run / "run.log").write_text("log\n", encoding="utf-8")

    headers = _login(client)
    status = client.get(f"/api/runs/{run_id}/gpt-failed", headers=headers)
    assert status.status_code == 200
    body = status.json()
    assert body["failed_hits"] == 1
    assert body["failed_files"] == 1
    assert body["retry"]["state"] == "idle"

    # Hold the worker open so a concurrent POST hits 409 while running.
    # threading.Event is safe across TestClient's background event loop.
    import threading

    release = threading.Event()

    async def _blocked_ok(run_id_arg: str):
        from aipocket.services.retry_gpt_failed import RetryGptFailedReport

        while not release.is_set():
            await asyncio.sleep(0.05)
        return RetryGptFailedReport(
            run_id=run_id_arg,
            failed_files=1,
            failed_hits=1,
            credentials_found=0,
            message="mocked ok",
        )

    monkeypatch.setattr("aipocket.api.retry_manager.retry_gpt_failed", _blocked_ok)

    started = client.post(f"/api/runs/{run_id}/retry-gpt-failed", headers=headers)
    assert started.status_code == 200, started.text
    assert started.json()["state"] == "running"
    assert started.json()["run_id"] == run_id

    conflict = client.post(f"/api/runs/{run_id}/retry-gpt-failed", headers=headers)
    assert conflict.status_code == 409

    # Release the background task so the TestClient lifespan can shut down cleanly.
    release.set()


def test_gpt_failed_retry_no_files_404(client, results_root):
    run_id = "run_2026_07_15_10-00-00"
    run = results_root / run_id
    run.mkdir(parents=True)
    (run / "run.log").write_text("log\n", encoding="utf-8")
    headers = _login(client)
    r = client.post(f"/api/runs/{run_id}/retry-gpt-failed", headers=headers)
    assert r.status_code == 404


def test_settings_masks_keys(client, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "abcdefghijklmnop")
    headers = _login(client)
    r = client.get("/api/settings", headers=headers)
    assert r.status_code == 200
    assert "****" in r.json()["fofa_keys"]
