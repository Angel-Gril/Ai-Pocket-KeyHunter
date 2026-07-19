"""Unit tests for scan candidate spill serialize / deserialize / SQL shape."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.core.credentials import CredentialBundle, CredentialEvidence
from aipocket.core.models import Credential
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
