"""Offline respx tests for GitHubClient — no real network."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
import respx

from aipocket.clients.github import (
    GitHubAuthError,
    GitHubClient,
    GitHubSourceGone,
)
from aipocket.core.config import Settings
from aipocket.core.request_ledger import RequestLedger, current_ledger

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "github"
CANARY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb"


def _settings(**kwargs) -> Settings:
    base = {
        "github_tokens": "ghp_testtoken0001,ghp_testtoken0002",
        "github_api_base_url": "https://api.github.com",
        "github_api_version": "2022-11-28",
        "github_request_timeout": 5.0,
        "github_search_page_size": 100,
        "github_max_blob_bytes": 1_048_576,
    }
    base.update(kwargs)
    return Settings(**base)


@pytest.fixture
def ledger():
    lg = RequestLedger(run_id="run_gh_test")
    token = current_ledger.set(lg)
    yield lg
    current_ledger.reset(token)


def _rate_headers(resource: str = "core", remaining: int = 4999) -> dict[str, str]:
    return {
        "X-RateLimit-Resource": resource,
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": "9999999999",
        "X-RateLimit-Limit": "5000",
    }


@pytest.mark.asyncio
@respx.mock
async def test_headers_and_ledger_on_rate_limit(ledger):
    route = respx.get("https://api.github.com/rate_limit").mock(
        return_value=httpx.Response(
            200,
            json={
                "resources": {
                    "core": {"remaining": 100, "reset": 9999999999},
                    "search": {"remaining": 20, "reset": 9999999999},
                    "code_search": {"remaining": 5, "reset": 9999999999},
                }
            },
            headers=_rate_headers("core", 100),
        )
    )
    async with GitHubClient(
        tokens=["ghp_testtoken0001"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        data = await client.rate_limit()
        assert "resources" in data
    assert route.called
    req = route.calls[0].request
    assert req.headers["Authorization"] == "Bearer ghp_testtoken0001"
    assert req.headers["Accept"] == "application/vnd.github+json"
    assert req.headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "aipocket" in req.headers["User-Agent"].lower()

    rows = ledger.drain()
    assert len(rows) == 1
    assert rows[0].endpoint_class == "/rate_limit"
    assert rows[0].source == "github"
    assert rows[0].status_code == 200
    # Never log tokens.
    blob = json.dumps([r.to_row() for r in rows])
    assert "ghp_testtoken" not in blob
    assert "Bearer" not in blob


@pytest.mark.asyncio
@respx.mock
async def test_search_commits_and_etag_304(ledger):
    canary_item = json.loads((FIX / "commit_message_canary.json").read_text())
    respx.get("https://api.github.com/search/commits").mock(
        side_effect=[
            httpx.Response(
                200,
                json={"total_count": 1, "incomplete_results": False, "items": [canary_item]},
                headers={**_rate_headers("search", 29), "ETag": '"etag-v1"'},
            ),
            httpx.Response(304, headers={**_rate_headers("search", 28), "ETag": '"etag-v1"'}),
        ]
    )
    async with GitHubClient(
        tokens=["ghp_testtoken0001"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        page1 = await client.search_commits("glm api key")
        assert page1.total_count == 1
        assert len(page1.items) == 1
        assert page1.etag == '"etag-v1"'
        page2 = await client.search_commits("glm api key", etag=page1.etag)
        assert page2.not_modified is True
        assert page2.items == ()

    rows = ledger.drain()
    assert len(rows) == 2
    assert rows[0].status_code == 200
    assert rows[1].status_code == 304
    assert all(r.rate_resource == "search" for r in rows)
    assert all(r.endpoint_class == "/search/commits" for r in rows)
    # Canary secret must not appear in ledger.
    for r in rows:
        assert CANARY not in json.dumps(r.to_row())


@pytest.mark.asyncio
@respx.mock
async def test_search_code_uses_code_search_resource(ledger):
    respx.get("https://api.github.com/search/code").mock(
        return_value=httpx.Response(
            200,
            json={"total_count": 0, "incomplete_results": False, "items": []},
            headers=_rate_headers("code_search", 9),
        )
    )
    async with GitHubClient(
        tokens=["ghp_testtoken0001"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        page = await client.search_code("GLM_API_KEY extension:env")
        assert page.total_count == 0
    rows = ledger.drain()
    assert rows[0].rate_resource == "code_search"
    assert rows[0].endpoint_class == "/search/code"


@pytest.mark.asyncio
@respx.mock
async def test_auth_401_marks_token_dead_then_retries(ledger):
    respx.get("https://api.github.com/rate_limit").mock(
        side_effect=[
            httpx.Response(401, json={"message": "Bad credentials"}),
            httpx.Response(
                200,
                json={"resources": {"core": {"remaining": 50, "reset": 9999999999}}},
                headers=_rate_headers("core", 50),
            ),
        ]
    )
    async with GitHubClient(
        tokens=["bad_token", "good_token"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        data = await client.rate_limit()
        assert "resources" in data
        assert "bad_token" in client.pool.dead
        assert "good_token" not in client.pool.dead


@pytest.mark.asyncio
@respx.mock
async def test_repo_404_does_not_kill_token(ledger):
    respx.get("https://api.github.com/repos/gone/repo/commits/abc123").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    async with GitHubClient(
        tokens=["keep_me"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        with pytest.raises(GitHubSourceGone):
            await client.get_commit("gone", "repo", "abc123")
        assert "keep_me" not in client.pool.dead


@pytest.mark.asyncio
@respx.mock
async def test_secondary_rate_limit_defers_until_cooldown(ledger):
    respx.get("https://api.github.com/rate_limit").mock(
        return_value=httpx.Response(
            403,
            json={"message": "You have exceeded a secondary rate limit"},
            headers={"Retry-After": "10", **_rate_headers("core", 0)},
        )
    )
    from aipocket.clients.github import GitHubRateLimitedError

    async with GitHubClient(
        tokens=["tok1"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        with pytest.raises(GitHubRateLimitedError) as exc_info:
            await client.rate_limit()
        assert exc_info.value.retry_after >= 59
        assert client.pool.pick("search") is None
    assert len(ledger.drain()) == 1


@pytest.mark.asyncio
@respx.mock
async def test_get_blob_base64_decode(ledger):
    content = (FIX / "blob_canary.env").read_text()
    b64 = base64.b64encode(content.encode()).decode()
    respx.get("https://api.github.com/repos/o/r/git/blobs/deadbeef").mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": "deadbeef",
                "size": len(content),
                "encoding": "base64",
                "content": b64,
            },
            headers=_rate_headers("core", 100),
        )
    )
    async with GitHubClient(
        tokens=["tok"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        blob = await client.get_blob("o", "r", "deadbeef")
        assert CANARY in blob.content
        assert blob.truncated is False
    rows = ledger.drain()
    assert rows[0].endpoint_class == "/repos/{owner}/{repo}/git/blobs/{sha}"
    assert rows[0].stage == "artifact_fetch"
    assert CANARY not in json.dumps(rows[0].to_row())


@pytest.mark.asyncio
@respx.mock
async def test_get_commit_files(ledger):
    patch = (FIX / "patch_canary.diff").read_text()
    respx.get("https://api.github.com/repos/o/r/commits/cafebabe").mock(
        return_value=httpx.Response(
            200,
            json={
                "sha": "cafebabe",
                "html_url": "https://github.com/o/r/commit/cafebabe",
                "commit": {"message": "fix env"},
                "files": [
                    {
                        "filename": ".env",
                        "status": "modified",
                        "sha": "blob1",
                        "patch": patch,
                        "additions": 1,
                        "deletions": 1,
                        "changes": 2,
                    }
                ],
            },
            headers=_rate_headers("core", 100),
        )
    )
    async with GitHubClient(
        tokens=["tok"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        detail = await client.get_commit("o", "r", "cafebabe")
        assert detail.message == "fix env"
        assert len(detail.files) == 1
        assert detail.files[0].patch is not None
        assert CANARY in detail.files[0].patch


@pytest.mark.asyncio
@respx.mock
async def test_list_commits(ledger):
    respx.get("https://api.github.com/repos/o/r/commits").mock(
        return_value=httpx.Response(
            200,
            json=[{"sha": "s1"}, {"sha": "s2"}],
            headers=_rate_headers("core", 100),
        )
    )
    async with GitHubClient(
        tokens=["tok"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        commits = await client.list_commits("o", "r", path=".env", since="2026-01-01T00:00:00Z")
        assert len(commits) == 2


@pytest.mark.asyncio
@respx.mock
async def test_all_tokens_dead_raises(ledger):
    respx.get("https://api.github.com/rate_limit").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    async with GitHubClient(
        tokens=["only"],
        ledger=ledger,
        settings=_settings(),
    ) as client:
        with pytest.raises(GitHubAuthError):
            await client.rate_limit()


@pytest.mark.asyncio
@respx.mock
async def test_search_request_records_query_and_pack_attribution(ledger):
    respx.get("https://api.github.com/search/code").mock(
        return_value=httpx.Response(
            200,
            json={"total_count": 0, "incomplete_results": False, "items": []},
            headers=_rate_headers("code_search", 9),
        )
    )
    async with GitHubClient(tokens=["tok"], ledger=ledger, settings=_settings()) as client:
        await client.search_code(
            "GLM_API_KEY",
            query_id="cs-stable",
            pack_id="glm",
        )
    rows = ledger.drain()
    assert rows[0].query_id == "cs-stable"
    assert rows[0].pack_id == "glm"
