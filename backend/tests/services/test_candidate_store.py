"""Unit tests for scan candidate spill serialize / deserialize / SQL shape."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.core.credentials import CredentialBundle, CredentialEvidence
from aipocket.core.models import Credential, ValidationResult
from aipocket.services import candidate_store as cs


class FakeCursor:
    def __init__(self, conn: FakeConnection):
        self._conn = conn
        self._result: list[dict[str, Any]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        self._conn.executed.append((sql, params))
        self._result = self._conn.responses.get("default", [])
        return self

    def executemany(self, sql: str, rows: list[Any]) -> None:
        self._conn.executed.append((sql, None))
        self._conn.executemany_rows.append((sql, list(rows)))

    def fetchone(self) -> dict[str, Any] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._result)


class FakeConnection:
    def __init__(self, pool: FakePool):
        self._pool = pool
        self.executed = pool.executed
        self.executemany_rows = pool.executemany_rows
        self.responses = pool.responses

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def transaction(self) -> FakeConnection:
        return self

    def execute(self, sql: str, params: Any = None) -> FakeCursor:
        cur = FakeCursor(self)
        cur.execute(sql, params)
        return cur

    def commit(self) -> None:
        self._pool.commits += 1


class FakePool:
    def __init__(self) -> None:
        self.executed: list[tuple] = []
        self.executemany_rows: list[tuple] = []
        self.responses: dict[str, list[dict[str, Any]]] = {}
        self.commits = 0

    def connection(self) -> FakeConnection:
        return FakeConnection(self)


@pytest.fixture
def enable_pg(monkeypatch: pytest.MonkeyPatch) -> FakePool:
    pool = FakePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    # settings.pg_enabled is a property — patch via database_url is enough if
    # property checks truthy url. Confirm:
    assert cs.spill_enabled()
    return pool


def test_serialize_roundtrip_plain_credential() -> None:
    cred = Credential(
        apikey="sk-test-plain-1234567890abcdef",
        apiurl="https://api.example.com/v1",
        host="https://api.example.com",
        backend="fofa",
        source="header",
    )
    data = cs.serialize_credential(cred)
    assert "bundle" not in data or data.get("bundle") is None
    restored = cs.deserialize_credential(data)
    assert restored.apikey == cred.apikey
    assert restored.apiurl == cred.apiurl
    assert restored.bundle is None


def test_serialize_roundtrip_github_bundle() -> None:
    secret = "sk-or-v1-" + "a" * 40
    bundle = CredentialBundle.create(
        secret,
        endpoint_candidates=("https://openrouter.ai/api/v1",),
        provider_hint="openrouter",
        evidence=(
            CredentialEvidence(
                source="github",
                path="config.env",
                query_id="q1",
                pack_id="openrouter",
                repository_full_name="acme/app",
                commit_sha="deadbeef",
                source_kind="blob",
            ),
        ),
        confidence="high",
    )
    cred = Credential(
        apikey=secret,
        apiurl="https://openrouter.ai/api/v1",
        backend="github",
        source="github",
        product="openrouter",
        bundle=bundle,
    )
    data = cs.serialize_credential(cred)
    assert data["bundle"]["secret"] == secret
    assert data["bundle"]["evidence"][0]["repository_full_name"] == "acme/app"
    restored = cs.deserialize_credential(data)
    assert restored.apikey == secret
    assert restored.bundle is not None
    assert restored.bundle.secret_value.reveal() == secret
    assert restored.bundle.provider_hint == "openrouter"
    assert restored.bundle.evidence[0].pack_id == "openrouter"
    assert restored.bundle.evidence[0].repository_full_name == "acme/app"


def test_upsert_candidates_emits_sql(enable_pg: FakePool) -> None:
    cred = Credential(apikey="sk-abc", apiurl="https://x", backend="shodan")
    n = cs.upsert_candidates("run_test", cs.STAGE_REGEX, [cred], method="regex")
    assert n == 1
    assert enable_pg.executemany_rows
    sql, rows = enable_pg.executemany_rows[0]
    assert "INSERT INTO scan_candidates" in sql
    assert "ON CONFLICT (run_id, identity) DO NOTHING" in sql
    assert rows[0][0] == "run_test"
    assert rows[0][1] == "regex"


def test_upsert_github_observations(enable_pg: FakePool) -> None:
    from aipocket.discovery.base import ArtifactProvenance, CredentialSourceObservation

    secret = "sk-gh-" + "b" * 40
    bundle = CredentialBundle.create(
        secret,
        endpoint_candidates=("https://api.openai.com/v1",),
        evidence=(
            CredentialEvidence(
                source="github",
                pack_id="openai",
                query_id="pack:openai",
                repository_full_name="org/repo",
            ),
        ),
    )
    cred = Credential(
        apikey=secret,
        apiurl="https://api.openai.com/v1",
        backend="github",
        source="github",
        bundle=bundle,
    )
    obs = CredentialSourceObservation(
        bundle=bundle,
        credential=cred,
        provenance=ArtifactProvenance(
            repository_id="1",
            repository_full_name="org/repo",
            commit_sha="abc",
            object_sha="",
            file_path=".env",
            source_kind="blob",
            query_id="pack:openai",
            pack_id="openai",
            lane="code",
        ),
        query_id="pack:openai",
        pack_id="openai",
        lane="code",
        coverage_mode="complete",
    )
    n = cs.upsert_github_observations("run_gh", [obs])
    assert n == 1
    _sql, rows = enable_pg.executemany_rows[0]
    # source, query_id, pack_id, lane columns
    assert rows[0][6] == "github"
    assert rows[0][7] == "pack:openai"
    assert rows[0][8] == "openai"
    assert rows[0][9] == "code"


def test_mark_orphan_runs(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"run_id": "run_old"}]
    # FakeCursor.fetchall used after execute RETURNING
    n = cs.mark_orphan_runs_interrupted("process_restart")
    assert n == 1
    assert any("interrupted" in (sql or "") for sql, _ in enable_pg.executed)


def test_spill_disabled_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert not cs.spill_enabled()
    assert cs.upsert_candidates("r", "regex", [Credential(apikey="x")]) == 0
    assert cs.load_candidates("r") == []
    assert cs.count_candidates("r") == 0
    assert list(cs.iter_candidate_pages("r")) == []
    assert cs.insert_probe_events("r", outcomes=[{}]) == 0
    assert cs.load_probe_outcomes("r") == []
    assert cs.upsert_validation_results("r", []) == 0
    assert cs.load_validated_identities("r") == set()
    assert cs.load_validation_results("r") == []
    assert cs.upsert_github_observations("r", []) == 0


def test_upsert_candidates_noop_empty_run_or_creds(enable_pg: FakePool) -> None:
    cred = Credential(apikey="sk-x", apiurl="https://x")
    assert cs.upsert_candidates("", cs.STAGE_REGEX, [cred]) == 0
    assert cs.upsert_candidates("run", cs.STAGE_REGEX, []) == 0
    assert not enable_pg.executemany_rows


def test_upsert_candidates_with_provenance(enable_pg: FakePool) -> None:
    creds = [
        Credential(apikey="sk-a", apiurl="https://a"),
        Credential(apikey="sk-b", apiurl="https://b"),
    ]
    provenance = [
        ("github", "q1", "openai", "code"),
        ("github", "q2", "anthropic", "commit"),
    ]
    n = cs.upsert_candidates(
        "run_p",
        cs.STAGE_GITHUB,
        creds,
        provenance=provenance,
    )
    assert n == 2
    _sql, rows = enable_pg.executemany_rows[0]
    assert rows[0][6:10] == ("github", "q1", "openai", "code")
    assert rows[1][6:10] == ("github", "q2", "anthropic", "commit")


def test_deserialize_credential_fills_apikey_from_bundle() -> None:
    secret = "sk-from-bundle-" + "c" * 32
    data = {
        "apiurl": "https://api.openai.com/v1",
        "backend": "github",
        "bundle": {
            "secret": secret,
            "credential_kind": "api_key",
            "endpoint_candidates": ["https://api.openai.com/v1"],
            "provider_hint": "openai",
            "context": {},
            "evidence": [],
            "confidence": "high",
        },
    }
    cred = cs.deserialize_credential(data)
    assert cred.apikey == secret
    assert cred.bundle is not None


def test_iter_candidate_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "sk-page-" + "d" * 40
    rec = cs.serialize_credential(Credential(apikey=secret, apiurl="https://p.example/v1"))
    pages = [
        [{"id": i, "identity": f"id{i}", "record": rec} for i in range(1, 4)],
        [{"id": i, "identity": f"id{i}", "record": rec} for i in range(4, 6)],
    ]
    call = {"n": 0}

    class PageCursor(FakeCursor):
        def execute(self, sql: str, params: Any = None) -> FakeCursor:
            self._conn.executed.append((sql, params))
            idx = call["n"]
            call["n"] += 1
            self._result = pages[idx] if idx < len(pages) else []
            return self

    class PageConn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return PageCursor(self)

    class PagePool(FakePool):
        def connection(self) -> FakeConnection:
            return PageConn(self)

    pool = PagePool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.config.settings.validate_batch_size", 3)
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)

    got = list(
        cs.iter_candidate_pages(
            "run_page",
            stages=[cs.STAGE_REGEX],
            skip_identities={"done:id"},
            batch_size=3,
        )
    )
    assert len(got) == 2
    assert len(got[0]) == 3
    assert len(got[1]) == 2
    assert all(isinstance(c, Credential) for c in got[0])
    # SQL includes skip + stage filters
    sql0, params0 = pool.executed[0]
    assert "stage = ANY" in sql0 or "ANY" in sql0
    assert "NOT (identity = ANY" in sql0
    assert "run_page" in params0


def test_iter_candidate_pages_skips_corrupt_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    good = cs.serialize_credential(Credential(apikey="sk-good-" + "e" * 32, apiurl="https://g"))

    class Cur(FakeCursor):
        def execute(self, sql: str, params: Any = None) -> FakeCursor:
            self._result = [
                {"id": 1, "identity": "bad", "record": {"apikey": None}},  # may fail
                {"id": 2, "identity": "ok", "record": good},
            ]
            return self

    class Conn(FakeConnection):
        def cursor(self) -> FakeCursor:
            return Cur(self)

    class Pool(FakePool):
        def connection(self) -> FakeConnection:
            return Conn(self)

    pool = Pool()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: pool)
    pages = list(cs.iter_candidate_pages("run_c", batch_size=10))
    # at least the good one should load (bad may or may not depending on model)
    flat = [c for p in pages for c in p]
    assert any(c.apikey.startswith("sk-good-") for c in flat)


def test_iter_candidate_pages_empty(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = []
    assert list(cs.iter_candidate_pages("run_empty", batch_size=5)) == []


def test_load_candidates_aggregates_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = [
        Credential(apikey="sk-1", apiurl="https://a"),
        Credential(apikey="sk-2", apiurl="https://b"),
    ]

    def fake_iter(run_id: str = "", **kwargs: Any):
        yield creds

    monkeypatch.setattr(cs, "iter_candidate_pages", fake_iter)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    out = cs.load_candidates("run_l")
    assert len(out) == 2


def test_count_candidates(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"n": 99}]
    assert cs.count_candidates("run_c", stages=[cs.STAGE_REGEX, cs.STAGE_GPT]) == 99
    enable_pg.responses["default"] = []
    assert cs.count_candidates("run_c") == 0


def test_insert_probe_events_and_load(enable_pg: FakePool) -> None:
    from types import SimpleNamespace

    outcome = SimpleNamespace(
        identity_hash="abc",
        status=SimpleNamespace(value="ok"),
        request_count=3,
        prober="generic",
        reason="",
    )
    finding = SimpleNamespace(
        vuln_class=SimpleNamespace(value="unauth_read"),
        product="dify",
        target_origin="https://x",
        spec_id="s1",
        cve_ids=["CVE-1"],
        confirmed=True,
        severity="high",
        summary="found",
        evidence={},
        credentials=[],
    )
    node = SimpleNamespace(
        spec_id="s1",
        vuln_class=SimpleNamespace(value="unauth_read"),
        risk_level=1,
        status=SimpleNamespace(value="hit"),
        requests_used=2,
        reason="",
        credentials_found=1,
    )
    n = cs.insert_probe_events(
        "run_probe",
        outcomes=[outcome],
        findings=[finding],
        node_outcomes=[node],
    )
    assert n == 3
    assert enable_pg.executemany_rows
    sql, rows = enable_pg.executemany_rows[0]
    assert "INSERT INTO scan_probe_events" in sql
    assert {r[1] for r in rows} == {"outcome", "finding", "node_outcome"}

    # load_probe_outcomes
    enable_pg.responses["default"] = [
        {"record": {"identity_hash": "abc", "status": "ok"}},
        {"record": "skip-me"},
    ]
    outs = cs.load_probe_outcomes("run_probe")
    assert outs == [{"identity_hash": "abc", "status": "ok"}]


def test_insert_probe_events_empty(enable_pg: FakePool) -> None:
    assert cs.insert_probe_events("run_p") == 0
    assert not enable_pg.executemany_rows


def test_validation_results_upsert_and_skip_set(enable_pg: FakePool) -> None:
    from aipocket.core.models import ValidationResult

    results = [
        ValidationResult(
            credential=Credential(
                apikey=f"sk-val-{i:02d}-" + "f" * 32,
                apiurl=f"https://v{i}.example/v1",
            ),
            valid=i % 2 == 0,
            validation_state="authentication_confirmed" if i % 2 == 0 else "auth_rejected",
            error="" if i % 2 == 0 else "denied",
        )
        for i in range(10)
    ]
    n = cs.upsert_validation_results("run_vr", results)
    assert n == 10
    sql, rows = enable_pg.executemany_rows[0]
    assert "INSERT INTO scan_validation_results" in sql
    assert "ON CONFLICT (run_id, identity)" in sql
    assert len(rows) == 10

    # skip set from load_validated_identities
    enable_pg.responses["default"] = [{"identity": rows[i][1]} for i in range(10)]
    skip = cs.load_validated_identities("run_vr")
    assert len(skip) == 10


def test_upsert_validation_results_skips_missing_credential(enable_pg: FakePool) -> None:
    from types import SimpleNamespace

    assert cs.upsert_validation_results("run_v", [SimpleNamespace(credential=None)]) == 0
    assert not enable_pg.executemany_rows


def test_serialize_deserialize_validation_result() -> None:
    from aipocket.core.models import ValidationResult

    secret = "sk-ser-" + "g" * 40
    bundle = CredentialBundle.create(
        secret,
        endpoint_candidates=("https://api.openai.com/v1",),
        evidence=(
            CredentialEvidence(
                source="github",
                pack_id="openai",
                query_id="q",
                repository_full_name="o/r",
            ),
        ),
    )
    result = ValidationResult(
        credential=Credential(
            apikey=secret,
            apiurl="https://api.openai.com/v1",
            backend="github",
            bundle=bundle,
        ),
        valid=True,
        validation_state="authentication_confirmed",
        tier="tier5",
    )
    data = cs.serialize_validation_result(result)
    assert data["credential"]["bundle"]["secret"] == secret
    restored = cs.deserialize_validation_result(data)
    assert restored.valid is True
    assert restored.credential.apikey == secret
    assert restored.credential.bundle is not None
    assert restored.credential.bundle.secret_value.reveal() == secret


def test_load_validation_results(enable_pg: FakePool) -> None:
    from aipocket.core.models import ValidationResult

    cred = Credential(apikey="sk-load-" + "h" * 32, apiurl="https://l.example/v1")
    rec = cs.serialize_validation_result(
        ValidationResult(credential=cred, valid=True, validation_state="authentication_confirmed")
    )
    enable_pg.responses["default"] = [
        {"record": rec},
        {"record": {"broken": True}},  # corrupt → skipped
    ]
    out = cs.load_validation_results("run_lr")
    assert len(out) == 1
    assert out[0].valid is True

    enable_pg.responses["default"] = [{"record": rec}]
    only_valid = cs.load_validation_results("run_lr", valid_only=True)
    assert len(only_valid) == 1
    sql, params = enable_pg.executed[-1]
    assert "valid = TRUE" in sql


def test_load_validated_identities_empty_rows(enable_pg: FakePool) -> None:
    enable_pg.responses["default"] = [{"identity": ""}, {"identity": "keep:me"}]
    assert cs.load_validated_identities("run_i") == {"keep:me"}


def test_mark_orphan_runs_noop_without_pg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert cs.mark_orphan_runs_interrupted() == 0


def test_mark_orphan_runs_handles_db_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class BoomPool:
        def connection(self):
            raise RuntimeError("db down")

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: BoomPool())
    assert cs.mark_orphan_runs_interrupted() == 0


def test_direct_google_never_enters_candidate_or_validation_spill(enable_pg: FakePool) -> None:
    key = "AIzaSyD" + "a" * 32
    credential = Credential(
        apikey=key,
        apiurl="https://generativelanguage.googleapis.com/v1beta",
    )
    result = ValidationResult(
        credential=credential,
        valid=True,
        validation_state="final_verified",
    )

    assert cs.upsert_candidates("run_google", "extracted", [credential]) == 0
    assert cs.upsert_validation_results("run_google", [result]) == 0
    assert enable_pg.executemany_rows == []
