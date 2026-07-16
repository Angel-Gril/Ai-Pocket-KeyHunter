"""Tests for artifact fetch priority and extraction (respx)."""

from __future__ import annotations

import base64
from pathlib import Path

import httpx
import pytest
import respx

from aipocket.clients.github import GitHubClient
from aipocket.core.config import Settings
from aipocket.core.request_ledger import RequestLedger, current_ledger
from aipocket.services.github_artifacts import BlobBudget, fetch_and_extract
from aipocket.services.github_queries import GitHubPackView
from aipocket.services.github_work_queue import ArtifactWorkItem

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "github"
CANARY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb"

PACK = GitHubPackView(
    pack_id="glm",
    path_hints=(".env", "config"),
    extensions=("env", "yml", "json"),
    default_endpoint="https://open.bigmodel.cn/api/paas/v4",
)


def _settings() -> Settings:
    return Settings(
        github_tokens="tok",
        github_api_base_url="https://api.github.com",
        github_max_commit_files=3000,
        github_max_blob_bytes=1_048_576,
        github_blob_fallback_budget=100,
    )


@pytest.fixture
def ledger():
    lg = RequestLedger(run_id="run_art")
    token = current_ledger.set(lg)
    yield lg
    current_ledger.reset(token)


def _work(**kwargs) -> ArtifactWorkItem:
    base = dict(
        repo_id="1",
        repository_full_name="canary-org/canary-repo",
        commit_sha="cafebabe00000000000000000000000000000000",
        file_path=".env",
        source_kind="patch",
        pack_id="glm",
        query_id="q1",
        lane="commit_message",
    )
    base.update(kwargs)
    return ArtifactWorkItem(**base)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_priority_message_then_patch(ledger):
    patch = (FIX / "patch_canary.diff").read_text()
    respx.get(
        "https://api.github.com/repos/canary-org/canary-repo/commits/cafebabe00000000000000000000000000000000"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": "cafebabe00000000000000000000000000000000",
                "commit": {"message": "rotate key"},
                "files": [
                    {
                        "filename": ".env",
                        "status": "modified",
                        "sha": "blob1",
                        "patch": patch,
                    }
                ],
            },
        )
    )
    async with GitHubClient(tokens=["tok"], ledger=ledger, settings=_settings()) as client:
        result = await fetch_and_extract(
            client,
            _work(),
            message_hint=f"note {CANARY} in message",
            pack=PACK,
        )
    assert result.status == "ok"
    fps = {s.bundle.secret_fingerprint for s in result.secrets}
    assert len(fps) >= 1
    # Both message and patch may contribute but fingerprint-deduped.
    assert any(s.source_kind == "commit_message" for s in result.secrets)
    assert any(s.source_kind == "patch" for s in result.secrets)
    assert any(s.change_side == "added" for s in result.secrets)
    # Secret only via reveal — not in work row.
    assert CANARY not in str(result.work.to_row())


@pytest.mark.asyncio
@respx.mock
async def test_blob_fallback_when_no_patch(ledger):
    content = (FIX / "blob_canary.env").read_text()
    b64 = base64.b64encode(content.encode()).decode()
    respx.get(
        "https://api.github.com/repos/canary-org/canary-repo/commits/cafebabe00000000000000000000000000000000"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": "cafebabe00000000000000000000000000000000",
                "commit": {"message": "add env"},
                "files": [
                    {
                        "filename": ".env",
                        "status": "added",
                        "sha": "blobsha1",
                        "patch": None,
                    }
                ],
            },
        )
    )
    respx.get("https://api.github.com/repos/canary-org/canary-repo/git/blobs/blobsha1").mock(
        return_value=httpx.Response(
            200,
            json={"sha": "blobsha1", "size": len(content), "encoding": "base64", "content": b64},
        )
    )
    budget = BlobBudget(remaining=10)
    async with GitHubClient(tokens=["tok"], ledger=ledger, settings=_settings()) as client:
        result = await fetch_and_extract(client, _work(), pack=PACK, blob_budget=budget)
    assert result.blobs_fetched == 1
    assert budget.remaining == 9
    assert any(s.source_kind == "blob" for s in result.secrets)
    assert any(s.bundle.secret_value.reveal() == CANARY for s in result.secrets)


@pytest.mark.asyncio
@respx.mock
async def test_budget_exhausted_status(ledger):
    respx.get(
        "https://api.github.com/repos/canary-org/canary-repo/commits/cafebabe00000000000000000000000000000000"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": "cafebabe00000000000000000000000000000000",
                "commit": {"message": "x"},
                "files": [
                    {"filename": ".env", "status": "added", "sha": "b1", "patch": None},
                ],
            },
        )
    )
    budget = BlobBudget(remaining=0)
    async with GitHubClient(tokens=["tok"], ledger=ledger, settings=_settings()) as client:
        result = await fetch_and_extract(client, _work(), pack=PACK, blob_budget=budget)
    assert result.status == "budget_exhausted"


@pytest.mark.asyncio
@respx.mock
async def test_source_gone_on_404(ledger):
    respx.get(
        "https://api.github.com/repos/canary-org/canary-repo/commits/cafebabe00000000000000000000000000000000"
    ).mock(return_value=httpx.Response(404, json={"message": "Not Found"}))
    async with GitHubClient(tokens=["tok"], ledger=ledger, settings=_settings()) as client:
        result = await fetch_and_extract(client, _work(), pack=PACK)
    assert result.status == "source_gone"
