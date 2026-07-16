"""Async GitHub REST client with instrumented transport + quota-aware tokens.

Every physical HTTP attempt lands in :class:`RequestLedger`. Tokens and secret
bodies are never logged or written into ledger fields.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from aipocket.clients.github_token_pool import GitHubTokenPool
from aipocket.core.config import Settings
from aipocket.core.config import settings as default_settings
from aipocket.core.request_ledger import RateResource, RequestLedger
from aipocket.services.http_transport import InstrumentedTransport, LedgerContext

log = logging.getLogger(__name__)

_DEFAULT_API_VERSION = "2022-11-28"
_USER_AGENT = "aipocket"
_ACCEPT = "application/vnd.github+json"

# Secondary rate-limit body markers (GitHub docs).
_SECONDARY_MARKERS = (
    "secondary rate limit",
    "abuse detection",
    "you have exceeded a secondary rate limit",
)


class GitHubAuthError(RuntimeError):
    """All tokens dead or unauthenticated."""


class GitHubAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_class: str = "",
        body_hash: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_class = error_class
        self.body_hash = body_hash


class GitHubRateLimitedError(GitHubAPIError):
    """No token may issue this request before its cooldown/reset deadline."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("rate_limited_deferred", error_class="rate_limited")
        self.retry_after = max(0.0, retry_after)


class GitHubSourceGone(GitHubAPIError):
    """Repo/commit/blob no longer available (404/409) — do not kill token."""


@dataclass(frozen=True, slots=True)
class SearchPage:
    total_count: int
    incomplete_results: bool
    items: tuple[dict[str, Any], ...]
    etag: str = ""
    status_code: int = 200
    not_modified: bool = False


@dataclass(frozen=True, slots=True)
class CommitFile:
    filename: str
    status: str
    sha: str
    patch: str | None
    additions: int = 0
    deletions: int = 0
    changes: int = 0
    previous_filename: str = ""


@dataclass(frozen=True, slots=True)
class CommitDetail:
    sha: str
    message: str
    html_url: str
    files: tuple[CommitFile, ...]
    owner: str
    repo: str
    repository_id: str = ""
    repository_full_name: str = ""
    etag: str = ""
    not_modified: bool = False
    # True when files list may be incomplete (paginated or truncated by API).
    files_truncated: bool = False


@dataclass(frozen=True, slots=True)
class Blob:
    sha: str
    size: int
    content: str  # decoded text (may be empty for binary)
    encoding: str
    truncated: bool = False
    etag: str = ""
    not_modified: bool = False


@dataclass(slots=True)
class GitHubClient:
    """Thin async wrapper around api.github.com with ledger + token pool."""

    tokens: list[str]
    ledger: RequestLedger | None = None
    settings: Settings | None = None
    _pool: GitHubTokenPool | None = field(default=None, init=False, repr=False)
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)
    _transport: InstrumentedTransport | None = field(default=None, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.tokens:
            raise ValueError("GitHub tokens required")
        cfg = self.settings or default_settings
        object.__setattr__(self, "settings", cfg)
        self._pool = GitHubTokenPool(self.tokens)
        timeout = float(cfg.github_request_timeout)
        self._client = httpx.AsyncClient(
            base_url=cfg.github_api_base_url.rstrip("/"),
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        )
        self._transport = InstrumentedTransport(
            ledger=self.ledger,
            defaults=LedgerContext(stage="discovery", source="github"),
            client=self._client,
        )

    @property
    def pool(self) -> GitHubTokenPool:
        assert self._pool is not None
        return self._pool

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._client is not None:
            await self._client.aclose()

    async def __aenter__(self) -> GitHubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ API
    async def rate_limit(self) -> dict[str, Any]:
        resp = await self._request(
            "GET",
            "/rate_limit",
            resource="core",
            stage="discovery",
            endpoint_class="/rate_limit",
        )
        data = resp.json()
        # Seed pool remaining from the resources block.
        resources = data.get("resources") if isinstance(data, dict) else None
        if isinstance(resources, dict):
            token = resp.extensions.get("aipocket_token") or ""
            for name in ("core", "search", "code_search"):
                block = resources.get(name) or {}
                if not isinstance(block, dict):
                    continue
                # Fake header-shaped update.
                fake = {
                    "x-ratelimit-resource": name,
                    "x-ratelimit-remaining": str(block.get("remaining", 0)),
                    "x-ratelimit-reset": str(block.get("reset", 0)),
                }
                if token:
                    self.pool.update_from_headers(token, fake)
        return data if isinstance(data, dict) else {}

    async def search_commits(
        self,
        q: str,
        *,
        page: int = 1,
        per_page: int | None = None,
        etag: str = "",
        query_id: str = "",
        pack_id: str = "",
    ) -> SearchPage:
        cfg = self.settings or default_settings
        params = {
            "q": q,
            "page": page,
            "per_page": per_page or cfg.github_search_page_size,
        }
        resp = await self._request(
            "GET",
            "/search/commits",
            resource="search",
            stage="discovery",
            endpoint_class="/search/commits",
            params=params,
            etag=etag or None,
            query_id=query_id,
            pack_id=pack_id,
        )
        return self._parse_search_page(resp)

    async def search_code(
        self,
        q: str,
        *,
        page: int = 1,
        per_page: int | None = None,
        etag: str = "",
        query_id: str = "",
        pack_id: str = "",
    ) -> SearchPage:
        cfg = self.settings or default_settings
        params = {
            "q": q,
            "page": page,
            "per_page": per_page or cfg.github_search_page_size,
        }
        resp = await self._request(
            "GET",
            "/search/code",
            resource="code_search",
            stage="discovery",
            endpoint_class="/search/code",
            params=params,
            etag=etag or None,
            query_id=query_id,
            pack_id=pack_id,
        )
        return self._parse_search_page(resp)

    async def get_commit(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        page: int = 1,
        per_page: int = 100,
        etag: str = "",
    ) -> CommitDetail:
        """Fetch commit detail; *page* paginates the files list (≤100/page)."""
        path = f"/repos/{owner}/{repo}/commits/{sha}"
        resp = await self._request(
            "GET",
            path,
            resource="core",
            stage="artifact_fetch",
            endpoint_class="/repos/{owner}/{repo}/commits/{sha}",
            params={"page": page, "per_page": per_page},
            etag=etag or None,
            owner=owner,
            repo=repo,
        )
        if resp.status_code == 304:
            return CommitDetail(
                sha=sha,
                message="",
                html_url="",
                files=(),
                owner=owner,
                repo=repo,
                etag=etag,
                not_modified=True,
            )
        data = resp.json()
        return self._parse_commit(data, owner=owner, repo=repo, etag=_resp_etag(resp))

    async def list_commits(
        self,
        owner: str,
        repo: str,
        *,
        path: str = "",
        since: str = "",
        until: str = "",
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if path:
            params["path"] = path
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/commits",
            resource="core",
            stage="artifact_fetch",
            endpoint_class="/repos/{owner}/{repo}/commits",
            params=params,
            owner=owner,
            repo=repo,
        )
        data = resp.json()
        return data if isinstance(data, list) else []

    async def get_blob(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        etag: str = "",
        max_bytes: int | None = None,
    ) -> Blob:
        cfg = self.settings or default_settings
        limit = max_bytes if max_bytes is not None else cfg.github_max_blob_bytes
        resp = await self._request(
            "GET",
            f"/repos/{owner}/{repo}/git/blobs/{sha}",
            resource="core",
            stage="artifact_fetch",
            endpoint_class="/repos/{owner}/{repo}/git/blobs/{sha}",
            etag=etag or None,
            owner=owner,
            repo=repo,
        )
        if resp.status_code == 304:
            return Blob(
                sha=sha,
                size=0,
                content="",
                encoding="",
                etag=etag,
                not_modified=True,
            )
        data = resp.json()
        size = int(data.get("size") or 0)
        encoding = str(data.get("encoding") or "")
        raw = data.get("content") or ""
        truncated = False
        text = ""
        if size > limit:
            truncated = True
            text = ""
        elif encoding == "base64" and isinstance(raw, str):
            try:
                # GitHub base64 payloads may contain newlines.
                decoded = base64.b64decode(raw.replace("\n", ""), validate=False)
                if len(decoded) > limit:
                    truncated = True
                    text = ""
                else:
                    text = decoded.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — binary / corrupt
                truncated = True
                text = ""
        elif isinstance(raw, str):
            text = raw if len(raw) <= limit else ""
            truncated = len(raw) > limit
        return Blob(
            sha=str(data.get("sha") or sha),
            size=size,
            content=text,
            encoding=encoding,
            truncated=truncated,
            etag=_resp_etag(resp),
        )

    # --------------------------------------------------------------- internal
    async def _request(
        self,
        method: str,
        path: str,
        *,
        resource: RateResource,
        stage: str,
        endpoint_class: str,
        params: dict[str, Any] | None = None,
        etag: str | None = None,
        owner: str = "",
        repo: str = "",
        max_attempts: int = 5,
        query_id: str = "",
        pack_id: str = "",
    ) -> httpx.Response:
        assert self._transport is not None and self._pool is not None
        cfg = self.settings or default_settings
        api_version = cfg.github_api_version or _DEFAULT_API_VERSION
        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            token = self.pool.pick(resource)
            if token is None:
                retry_after = self.pool.retry_after(resource)
                if retry_after is not None:
                    raise GitHubRateLimitedError(retry_after)
                raise GitHubAuthError("No live GitHub tokens available")
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": _ACCEPT,
                "X-GitHub-Api-Version": api_version,
                "User-Agent": _USER_AGENT,
            }
            if etag:
                headers["If-None-Match"] = etag

            try:
                resp = await self._transport.request(
                    method,
                    path,
                    stage=stage,  # type: ignore[arg-type]
                    endpoint_class=endpoint_class,
                    rate_resource=resource,
                    attempt=attempt,
                    headers=headers,
                    params=params,
                    query_id=query_id,
                    pack_id=pack_id,
                )
            except httpx.TimeoutException:
                last_error = GitHubAPIError("timeout", error_class="timeout")
                log.warning("GitHub %s %s timeout (attempt %d)", method, endpoint_class, attempt)
                await asyncio.sleep(min(2 ** (attempt - 1), 8))
                continue
            except httpx.TransportError as exc:
                last_error = GitHubAPIError("network", error_class="network")
                log.warning(
                    "GitHub %s %s network error: %s", method, endpoint_class, type(exc).__name__
                )
                await asyncio.sleep(min(2 ** (attempt - 1), 8))
                continue

            # Stash token for rate_limit seeding (never logged).
            resp.extensions["aipocket_token"] = token
            self.pool.update_from_headers(token, resp.headers)

            if resp.status_code == 304:
                return resp

            if resp.status_code == 401:
                self.pool.mark_dead(token, "auth 401")
                last_error = GitHubAuthError("token rejected (401)")
                continue

            if resp.status_code in (404, 409) and owner:
                # Repo/commit gone — do not kill token.
                raise GitHubSourceGone(
                    f"source gone {owner}/{repo} HTTP {resp.status_code}",
                    status_code=resp.status_code,
                    error_class="source_gone",
                )

            if resp.status_code in (403, 429):
                body_snip = (resp.text or "")[:300].lower()
                secondary = any(m in body_snip for m in _SECONDARY_MARKERS)
                wait = self.pool.apply_rate_limit_response(
                    token,
                    resource=resource,
                    headers=resp.headers,
                    secondary=secondary,
                )
                log.warning(
                    "GitHub rate limited (%s) resource=%s wait=%.1fs secondary=%s",
                    resp.status_code,
                    resource,
                    wait,
                    secondary,
                )
                # Try another ready token immediately. If every token is cooling,
                # the next loop returns a typed deferred result instead of retrying early.
                last_error = GitHubRateLimitedError(wait)
                continue

            if resp.status_code == 422:
                # Unsupported qualifier / validation — secret-safe hash only.
                q_hash = ""
                if params and "q" in params:
                    q_hash = hashlib.sha256(str(params["q"]).encode()).hexdigest()[:16]
                log.error(
                    "GitHub 422 on %s query_hash=%s (unsupported qualifier or validation)",
                    endpoint_class,
                    q_hash or "-",
                )
                raise GitHubAPIError(
                    "validation_failed",
                    status_code=422,
                    error_class="unsupported_qualifier",
                    body_hash=q_hash,
                )

            if resp.status_code >= 500:
                last_error = GitHubAPIError(
                    f"server_{resp.status_code}",
                    status_code=resp.status_code,
                    error_class="server_error",
                )
                await asyncio.sleep(min(2 ** (attempt - 1), 8))
                continue

            if resp.status_code >= 400:
                raise GitHubAPIError(
                    f"http_{resp.status_code}",
                    status_code=resp.status_code,
                    error_class="client_error",
                )

            return resp

        if last_error:
            raise last_error
        raise GitHubAPIError("exhausted_attempts", error_class="exhausted")

    @staticmethod
    def _parse_search_page(resp: httpx.Response) -> SearchPage:
        if resp.status_code == 304:
            return SearchPage(
                total_count=0,
                incomplete_results=False,
                items=(),
                etag=_resp_etag(resp),
                status_code=304,
                not_modified=True,
            )
        data = resp.json() if resp.content else {}
        if not isinstance(data, dict):
            data = {}
        items = data.get("items") or []
        if not isinstance(items, list):
            items = []
        return SearchPage(
            total_count=int(data.get("total_count") or 0),
            incomplete_results=bool(data.get("incomplete_results")),
            items=tuple(i for i in items if isinstance(i, dict)),
            etag=_resp_etag(resp),
            status_code=resp.status_code,
        )

    @staticmethod
    def _parse_commit(
        data: dict[str, Any],
        *,
        owner: str,
        repo: str,
        etag: str,
    ) -> CommitDetail:
        commit_obj = data.get("commit") if isinstance(data.get("commit"), dict) else {}
        message = str(commit_obj.get("message") or data.get("message") or "")
        files_raw = data.get("files") or []
        files: list[CommitFile] = []
        if isinstance(files_raw, list):
            for f in files_raw:
                if not isinstance(f, dict):
                    continue
                files.append(
                    CommitFile(
                        filename=str(f.get("filename") or ""),
                        status=str(f.get("status") or ""),
                        sha=str(f.get("sha") or ""),
                        patch=f.get("patch") if isinstance(f.get("patch"), str) else None,
                        additions=int(f.get("additions") or 0),
                        deletions=int(f.get("deletions") or 0),
                        changes=int(f.get("changes") or 0),
                        previous_filename=str(f.get("previous_filename") or ""),
                    )
                )
        repo_meta = data.get("repository") if isinstance(data.get("repository"), dict) else {}
        full_name = str(repo_meta.get("full_name") or f"{owner}/{repo}")
        repo_id = str(repo_meta.get("id") or "")
        return CommitDetail(
            sha=str(data.get("sha") or ""),
            message=message,
            html_url=str(data.get("html_url") or ""),
            files=tuple(files),
            owner=owner,
            repo=repo,
            repository_id=repo_id,
            repository_full_name=full_name,
            etag=etag,
            files_truncated=len(files) >= 100,  # may need pagination
        )


def _resp_etag(resp: httpx.Response) -> str:
    return str(resp.headers.get("etag") or resp.headers.get("ETag") or "")
