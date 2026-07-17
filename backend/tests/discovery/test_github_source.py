"""Tests for GitHubSource discovery adapter."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from aipocket.core.config import Settings
from aipocket.core.request_ledger import RequestLedger, current_ledger
from aipocket.core.scan_policy import policy_from_mode
from aipocket.discovery.base import SourceBudgets
from aipocket.discovery.github_source import GitHubSource, resolve_packs
from aipocket.discovery.registry import SourceRegistry, merge_fetch_results
from aipocket.services.github_queries import GitHubPackView, build_code_snapshot_shards
from aipocket.services.github_work_queue import reset_memory_store

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "github"
CANARY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb"

MINI_PACK = GitHubPackView(
    pack_id="glm",
    commit_message_anchors=("glm api key",),
    code_content_anchors=("GLM_API_KEY",),
    code_qualifier_groups=(("extension:env",),),
    path_hints=(".env",),
    extensions=("env",),
    default_endpoint="https://open.bigmodel.cn/api/paas/v4",
)


@pytest.fixture(autouse=True)
def _mem_queue():
    reset_memory_store()
    yield
    reset_memory_store()


@pytest.fixture
def ledger():
    lg = RequestLedger(run_id="run_gh_src")
    token = current_ledger.set(lg)
    yield lg
    current_ledger.reset(token)


def _cfg(**kwargs) -> Settings:
    base = dict(
        github_hunter_enabled=True,
        github_tokens="ghp_test_token_0001",
        database_url="postgresql://test:test@localhost/test",
        github_api_base_url="https://api.github.com",
        github_commit_query_budget=2,
        github_code_query_budget=2,
        github_max_pages_per_shard=1,
        github_search_page_size=100,
        github_lookback_hours=24,
        github_file_history_enabled=False,
        github_artifact_concurrency=2,
        github_blob_fallback_budget=10,
    )
    base.update(kwargs)
    return Settings(**base)


def test_is_configured_requires_tokens_and_pg():
    src = GitHubSource(settings=_cfg(github_tokens="", database_url=""))
    assert src.is_configured() is False
    src2 = GitHubSource(settings=_cfg(github_tokens="t", database_url=""))
    # Settings with empty database_url → pg_enabled False
    assert src2.is_configured() is False
    src3 = GitHubSource(settings=_cfg())
    assert src3.is_configured() is True
    src4 = GitHubSource(settings=_cfg(github_hunter_enabled=False))
    assert src4.is_configured() is False


def test_configuration_error_lists_missing():
    src = GitHubSource(
        settings=_cfg(github_tokens="", database_url="", github_hunter_enabled=False)
    )
    msg = src.configuration_error()
    assert "GITHUB_TOKENS" in msg
    assert "DATABASE_URL" in msg
    assert "GITHUB_HUNTER_ENABLED" in msg


def test_resolve_packs_uses_registry():
    packs = resolve_packs(["glm"])
    assert packs
    assert any(getattr(p, "pack_id", None) == "glm" for p in packs)
    all_packs = resolve_packs(["all"])
    assert len(all_packs) >= 1
    unknown = resolve_packs(["does-not-exist-xyz"])
    # Falls back to registered glm or default
    assert isinstance(unknown, list)


@pytest.mark.asyncio
async def test_no_packs_returns_error(monkeypatch):
    src = GitHubSource(settings=_cfg(), packs=[], strict=True)
    result = await src.fetch(
        budgets=SourceBudgets(),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    assert result.errors
    assert "pack" in result.errors[0].lower()


@pytest.mark.asyncio
async def test_skip_when_not_configured_source_all():
    src = GitHubSource(settings=_cfg(github_tokens=""), strict=False)
    result = await src.fetch(
        budgets=SourceBudgets(),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    assert result.source == "github"
    assert result.host_hits == ()
    assert result.credential_observations == ()
    assert result.errors == ()


@pytest.mark.asyncio
async def test_fail_closed_when_strict_and_not_configured():
    src = GitHubSource(settings=_cfg(github_tokens=""), strict=True)
    result = await src.fetch(
        budgets=SourceBudgets(),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    assert result.errors
    assert "GITHUB_TOKENS" in result.errors[0] or "not configured" in result.errors[0].lower()


@pytest.mark.asyncio
@respx.mock
async def test_fetch_returns_credential_observations_only(ledger, monkeypatch):
    # is_configured reads the injected Settings (pg via database_url).
    # Durable queue/checkpoint modules read the process-wide settings singleton;
    # keep DATABASE_URL empty there so unit tests use the in-memory work store.
    cfg = _cfg()
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_work_queue.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_checkpoint.settings.database_url", "")

    canary_item = json.loads((FIX / "commit_message_canary.json").read_text())
    patch = (FIX / "patch_canary.diff").read_text()

    respx.get("https://api.github.com/search/commits").mock(
        return_value=httpx.Response(
            200,
            json={"total_count": 1, "incomplete_results": False, "items": [canary_item]},
            headers={"X-RateLimit-Resource": "search", "X-RateLimit-Remaining": "20"},
        )
    )
    respx.get("https://api.github.com/search/code").mock(
        return_value=httpx.Response(
            200,
            json={"total_count": 0, "incomplete_results": False, "items": []},
            headers={"X-RateLimit-Resource": "code_search", "X-RateLimit-Remaining": "10"},
        )
    )
    respx.get(url__regex=r"https://api\.github\.com/repos/.*/commits/.*").mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": canary_item["sha"],
                "commit": {"message": canary_item["commit"]["message"]},
                "files": [
                    {
                        "filename": ".env",
                        "status": "modified",
                        "sha": "blob1",
                        "patch": patch,
                    }
                ],
            },
            headers={"X-RateLimit-Resource": "core", "X-RateLimit-Remaining": "100"},
        )
    )

    src = GitHubSource(settings=cfg, packs=[MINI_PACK])
    result = await src.fetch(
        budgets=SourceBudgets(github_commit=1, github_code=1),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    assert result.host_hits == ()
    assert result.source == "github"
    # Should have extracted canary from message and/or patch.
    assert len(result.credential_observations) >= 1
    for obs in result.credential_observations:
        assert obs.lane in {"commit_message", "code_snapshot", "seeded_file_history"}
        assert obs.pack_id == "glm"
        assert obs.credential.backend == "github"
        assert obs.provenance.repository_full_name
        # Host fields empty — not a host hit.
        assert obs.credential.host == ""
        secret = obs.bundle.secret_value.reveal()
        assert secret == CANARY or secret.startswith("aaaa")

    # Registry merge must not put github payloads into host_hits.
    hosts, obs, sources, hits_by, *_ = merge_fetch_results([result])
    assert hosts == []
    assert len(obs) >= 1
    assert hits_by.get("github", 0) == len(obs)


@pytest.mark.asyncio
async def test_registry_skips_unconfigured_github_on_all(monkeypatch):
    cfg = _cfg(github_tokens="")
    monkeypatch.setattr("aipocket.discovery.registry.default_settings", cfg)
    monkeypatch.setattr("aipocket.discovery.github_source.default_settings", cfg)
    reg = SourceRegistry.default(cfg)
    resolved = reg.resolve(requested={"all"}, settings=cfg)
    names = {s.name for s in resolved}
    assert "github" not in names


def test_resolve_packs_returns_glm():
    packs = resolve_packs(["glm"])
    assert packs
    assert packs[0].pack_id == "glm"
    assert packs[0].commit_message_anchors


@pytest.mark.asyncio
async def test_seeded_history_lane_exercised(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_work_queue.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_checkpoint.settings.database_url", "")

    class FakeClient:
        async def list_commits(self, owner, repo, **kw):
            return [{"sha": "deadbeef01", "commit": {"message": "rotate glm"}}]

        async def aclose(self):
            return None

    src = GitHubSource(
        settings=_cfg(github_file_history_enabled=True),
        packs=[MINI_PACK],
        client=FakeClient(),
    )
    obs, usage, cps, errs = await src._run_seeded_history_lane(
        FakeClient(),
        MINI_PACK,
        seeds=[
            {
                "owner": "o",
                "repo": "r",
                "path": ".env",
                "repo_id": "1",
                "seed_origin": "code_snapshot",
                "public": True,
            }
        ],
        run_id="run_x",
        mode="incremental",
    )
    assert usage
    assert isinstance(obs, list)


@pytest.mark.asyncio
async def test_process_work_items_with_message_hint(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_work_queue.settings.database_url", "")

    class FakeClient:
        async def get_commit(self, *a, **k):
            return {
                "sha": "abc1234567",
                "commit": {"message": f"key {CANARY}"},
                "files": [],
            }

        async def get_blob(self, *a, **k):
            raise RuntimeError("no")

    from aipocket.services.github_work_queue import ArtifactWorkItem

    item = ArtifactWorkItem(
        repo_id="1",
        repository_full_name="o/r",
        commit_sha="abc1234567",
        source_kind="commit_message",
        pack_id="glm",
        lane="commit_message",
        run_id="r",
        query_id="q",
    )
    src = GitHubSource(settings=_cfg(), packs=[MINI_PACK], client=FakeClient())
    obs, errs = await src._process_work_items(
        FakeClient(),
        [item],
        packs=[MINI_PACK],
        message_hints={"abc1234567": f"msg {CANARY}"},
    )
    assert isinstance(obs, list)
    assert isinstance(errs, list)


@pytest.mark.asyncio
async def test_fetch_empty_search_with_injected_client(monkeypatch, ledger):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_work_queue.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.github_checkpoint.settings.database_url", "")

    class Page:
        items = ()
        incomplete_results = False
        total_count = 0
        etag = ""
        not_modified = False

    class FakeClient:
        async def search_commits(self, *a, **k):
            return Page()

        async def search_code(self, *a, **k):
            return Page()

        async def aclose(self):
            return None

    src = GitHubSource(settings=_cfg(), packs=[MINI_PACK], client=FakeClient())
    result = await src.fetch(
        budgets=SourceBudgets(github_commit=1, github_code=1),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    assert result.source == "github"
    assert result.host_hits == ()


@pytest.mark.asyncio
async def test_registry_explicit_github_passes_strict_configuration_error(monkeypatch):
    cfg = _cfg(github_tokens="")
    source = GitHubSource(settings=cfg)
    registry = SourceRegistry({"github": source})
    resolved = registry.resolve(requested={"github"}, settings=cfg)
    results = await registry.fetch_all(
        resolved,
        budgets=SourceBudgets(),
        mode="incremental",
        strict_sources=frozenset({"github"}),
    )
    assert results[0].errors
    assert merge_fetch_results(results)[2] == []


@pytest.mark.asyncio
async def test_private_search_items_never_queue_or_fetch(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    queued: list = []
    fetched: list = []

    class Page:
        items = (
            {
                "sha": "private-sha",
                "path": ".env",
                "repository": {"id": 1, "full_name": "private/repo", "private": True},
            },
        )
        incomplete_results = False
        total_count = 1
        etag = ""
        not_modified = False

    class FakeClient:
        async def search_code(self, *_args, **_kwargs):
            return Page()

        async def get_blob(self, *_args, **_kwargs):
            fetched.append(True)
            raise AssertionError("private artifact must not be fetched")

    monkeypatch.setattr(
        "aipocket.discovery.github_source.upsert_work_rows",
        lambda rows, conn=None: queued.extend(rows) or len(rows),
    )
    shard = build_code_snapshot_shards(MINI_PACK, page_budget=1)[0]
    source = GitHubSource(settings=_cfg(), packs=[MINI_PACK], client=FakeClient())
    observations, *_rest = await source._search_shard(FakeClient(), shard, run_id="run_private")
    assert observations == []
    assert queued == []
    assert fetched == []


@pytest.mark.asyncio
async def test_code_snapshot_checkpoint_always_restarts_page_one(monkeypatch):
    pages: list[int] = []

    class Existing:
        cursor_state = {"page": 7}
        etag = "page-one-etag"

    class Page:
        items = ()
        incomplete_results = False
        total_count = 0
        etag = "next-etag"
        not_modified = False

    class FakeClient:
        async def search_code(self, _q, *, page, **_kwargs):
            pages.append(page)
            return Page()

    shard = build_code_snapshot_shards(MINI_PACK, page_budget=1)[0]
    source = GitHubSource(settings=_cfg(), packs=[MINI_PACK], client=FakeClient())
    result = await source._search_shard(FakeClient(), shard, run_id="run_page_one")
    assert pages == [1]
    assert result[2][-1].cursor_state["page"] == 1


@pytest.mark.asyncio
async def test_terminal_failure_status_is_not_overwritten(monkeypatch):
    from aipocket.services.github_artifacts import ArtifactFetchResult
    from aipocket.services.github_work_queue import ArtifactWorkItem

    item = ArtifactWorkItem(
        repo_id="1",
        repository_full_name="public/repo",
        commit_sha="abc123",
        source_kind="commit_message",
        pack_id="glm",
        lane="commit_message",
        run_id="run_terminal",
        query_id="q",
    )

    async def fake_fetch(*_args, **_kwargs):
        return ArtifactFetchResult(
            work=item,
            status="budget_exhausted",
            error_class="blob_fallback_budget",
        )

    monkeypatch.setattr("aipocket.discovery.github_source.fetch_and_extract", fake_fetch)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    source = GitHubSource(settings=_cfg(), packs=[MINI_PACK], client=object())
    await source._process_work_items(object(), [item], packs=[MINI_PACK], message_hints={})
    assert item.work_status == "budget_exhausted"
    assert item.last_error_class == "blob_fallback_budget"
