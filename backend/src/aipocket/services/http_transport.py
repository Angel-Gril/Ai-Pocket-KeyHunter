"""Instrumented HTTP helpers — one RequestLedger row per physical attempt."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

import httpx

from aipocket.core.request_ledger import (
    LedgerStage,
    RateResource,
    RequestLedger,
    get_current_ledger,
    get_current_query_attribution,
    make_entry,
)

# Increment only after every required scan HTTP exit participates in this transport.
# Version 1 covers discovery, GitHub artifacts, probing, validation/no-auth,
# balance enrichment, and GPT extraction/recheck.
HTTP_INSTRUMENTATION_VERSION = 1

# Path segments that look like opaque ids (hex shas, numeric ids, long tokens).
_HEX_RE = re.compile(r"^[0-9a-f]{7,64}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}$")

_KEEP_LABELS = frozenset(
    {
        "repos",
        "search",
        "commits",
        "git",
        "blobs",
        "rate_limit",
        "code",
        "api",
        "v1",
        "v2",
        "v3",
        "v4",
        "shodan",
        "host",
        "models",
        "chat",
        "completions",
        "messages",
        "openai",
        "paas",
        "biz",
        "finance",
        "balance",
        "users",
        "orgs",
        "contents",
    }
)


@dataclass(frozen=True, slots=True)
class LedgerContext:
    """Default attribution fields applied to every attempt from a transport."""

    stage: LedgerStage
    source: str
    query_id: str = ""
    pack_id: str = ""
    credential_fingerprint: str | None = None
    target_identity: str = ""
    artifact_identity: str = ""
    product: str = ""
    spec_id: str = ""
    provider: str = ""
    rate_resource: RateResource = "other"


def normalize_endpoint_class(url: str, explicit: str = "") -> str:
    """Return a templated path with secrets stripped.

    Rules:
    - Prefer *explicit* when provided (caller already templated).
    - Strip query string entirely.
    - Replace hex/numeric/long opaque path segments with ``{id}`` / ``{sha}``.
    """
    if explicit:
        cleaned = explicit.split("?", 1)[0]
        cleaned = re.sub(r"(?i)(token|key|authorization)=[^&/]+", r"\1={redacted}", cleaned)
        cleaned = re.sub(r"(?i)(bearer\s+)\S+", r"\1{redacted}", cleaned)
        return cleaned or "/"

    parts = urlsplit(url)
    return _template_path(parts.path or "/")


def _template_path(path: str) -> str:
    segments = path.split("/")
    result: list[str] = []
    i = 0
    while i < len(segments):
        seg = segments[i]
        if not seg:
            result.append(seg)
            i += 1
            continue
        lower = seg.lower()
        if lower == "repos" and i + 2 < len(segments):
            result.extend(["repos", "{owner}", "{repo}"])
            i += 3
            continue
        if lower == "commits" and i + 1 < len(segments) and segments[i + 1]:
            result.append("commits")
            nxt = segments[i + 1]
            if _HEX_RE.match(nxt) or _TOKENISH_RE.match(nxt):
                result.append("{sha}")
                i += 2
                continue
            i += 1
            continue
        if lower == "blobs" and i + 1 < len(segments) and segments[i + 1]:
            result.extend(["blobs", "{sha}"])
            i += 2
            continue
        if lower in _KEEP_LABELS:
            result.append(seg)
        elif _HEX_RE.match(seg) or _NUM_RE.match(seg) or _TOKENISH_RE.match(seg):
            result.append("{id}")
        else:
            result.append(seg)
        i += 1
    return ("/".join(result) or "/").split("?", 1)[0]


class InstrumentedTransport:
    """Wrap an httpx client request and emit one ledger row per attempt."""

    def __init__(
        self,
        ledger: RequestLedger | None = None,
        defaults: LedgerContext | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        sync_client: httpx.Client | None = None,
    ) -> None:
        self._ledger = ledger
        self.defaults = defaults or LedgerContext(stage="validation", source="unknown")
        self._client = client
        self._sync_client = sync_client

    def with_defaults(self, **kwargs: Any) -> InstrumentedTransport:
        return InstrumentedTransport(
            ledger=self._ledger,
            defaults=replace(self.defaults, **kwargs),
            client=self._client,
            sync_client=self._sync_client,
        )

    def _resolve_ledger(self) -> RequestLedger | None:
        return self._ledger if self._ledger is not None else get_current_ledger()

    async def request(
        self,
        method: str,
        url: str,
        *,
        stage: LedgerStage | None = None,
        endpoint_class: str = "",
        rate_resource: RateResource | None = None,
        attempt: int = 1,
        query_id: str = "",
        pack_id: str = "",
        **kwargs: Any,
    ) -> httpx.Response:
        client = self._client
        if client is None:
            raise RuntimeError("InstrumentedTransport requires an async httpx.AsyncClient")
        return await self._execute(
            client,
            method,
            url,
            stage=stage,
            endpoint_class=endpoint_class,
            rate_resource=rate_resource,
            attempt=attempt,
            query_id=query_id,
            pack_id=pack_id,
            **kwargs,
        )

    def request_sync(
        self,
        method: str,
        url: str,
        *,
        stage: LedgerStage | None = None,
        endpoint_class: str = "",
        rate_resource: RateResource | None = None,
        attempt: int = 1,
        query_id: str = "",
        pack_id: str = "",
        **kwargs: Any,
    ) -> httpx.Response:
        client = self._sync_client
        if client is None:
            raise RuntimeError("InstrumentedTransport requires a sync httpx.Client")
        return self._execute_sync(
            client,
            method,
            url,
            stage=stage,
            endpoint_class=endpoint_class,
            rate_resource=rate_resource,
            attempt=attempt,
            query_id=query_id,
            pack_id=pack_id,
            **kwargs,
        )

    async def _execute(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        stage: LedgerStage | None,
        endpoint_class: str,
        rate_resource: RateResource | None,
        attempt: int,
        query_id: str,
        pack_id: str,
        **kwargs: Any,
    ) -> httpx.Response:
        started = time.perf_counter()
        error_class = ""
        status_code: int | None = None
        response_bytes = 0
        try:
            response = await client.request(method, url, **kwargs)
            status_code = response.status_code
            response_bytes = len(response.content or b"")
            return response
        except httpx.TimeoutException:
            error_class = "timeout"
            raise
        except httpx.TransportError:
            error_class = "network"
            raise
        except Exception:
            error_class = "internal"
            raise
        finally:
            self._emit(
                method=method,
                url=url,
                stage=stage,
                endpoint_class=endpoint_class,
                rate_resource=rate_resource,
                attempt=attempt,
                query_id=query_id,
                pack_id=pack_id,
                status_code=status_code,
                error_class=error_class,
                latency_ms=int((time.perf_counter() - started) * 1000),
                response_bytes=response_bytes,
            )

    def _execute_sync(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        stage: LedgerStage | None,
        endpoint_class: str,
        rate_resource: RateResource | None,
        attempt: int,
        query_id: str,
        pack_id: str,
        **kwargs: Any,
    ) -> httpx.Response:
        started = time.perf_counter()
        error_class = ""
        status_code: int | None = None
        response_bytes = 0
        try:
            response = client.request(method, url, **kwargs)
            status_code = response.status_code
            response_bytes = len(response.content or b"")
            return response
        except httpx.TimeoutException:
            error_class = "timeout"
            raise
        except httpx.TransportError:
            error_class = "network"
            raise
        except Exception:
            error_class = "internal"
            raise
        finally:
            self._emit(
                method=method,
                url=url,
                stage=stage,
                endpoint_class=endpoint_class,
                rate_resource=rate_resource,
                attempt=attempt,
                query_id=query_id,
                pack_id=pack_id,
                status_code=status_code,
                error_class=error_class,
                latency_ms=int((time.perf_counter() - started) * 1000),
                response_bytes=response_bytes,
            )

    def _emit(
        self,
        *,
        method: str,
        url: str,
        stage: LedgerStage | None,
        endpoint_class: str,
        rate_resource: RateResource | None,
        attempt: int,
        query_id: str,
        pack_id: str,
        status_code: int | None,
        error_class: str,
        latency_ms: int,
        response_bytes: int,
    ) -> None:
        ledger = self._resolve_ledger()
        if ledger is None:
            return
        d = self.defaults
        current_attribution = get_current_query_attribution()
        ep = normalize_endpoint_class(url, endpoint_class)
        if any(s in ep.lower() for s in ("bearer ", "token=", "key=")):
            ep = re.sub(r"(?i)(bearer\s+)\S+", r"\1{redacted}", ep)
            ep = re.sub(r"(?i)((?:token|key)=)\S+", r"\1{redacted}", ep)
        entry = make_entry(
            run_id=ledger.run_id,
            stage=stage or d.stage,
            source=current_attribution.source or d.source,
            http_method=method,
            endpoint_class=ep,
            status_code=status_code,
            error_class=error_class,
            latency_ms=latency_ms,
            attempt=attempt,
            rate_resource=rate_resource or d.rate_resource,
            query_id=query_id or d.query_id or current_attribution.query_id,
            pack_id=pack_id or d.pack_id or current_attribution.pack_id,
            credential_fingerprint=d.credential_fingerprint,
            target_identity=d.target_identity,
            artifact_identity=d.artifact_identity,
            product=d.product,
            spec_id=d.spec_id,
            provider=d.provider,
            response_bytes=response_bytes,
        )
        ledger.record(entry)


class InstrumentedAsyncClient:
    """httpx-compatible request facade with ledger attribution.

    The wrapper owns no connection resources; callers still close the underlying
    ``httpx.AsyncClient``. Per-call attribution overrides are accepted under the
    private ``ledger_*`` names so they never leak into HTTP request kwargs.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        ledger: RequestLedger | None = None,
        defaults: LedgerContext | None = None,
        transport: InstrumentedTransport | None = None,
    ) -> None:
        self._client = client
        self._transport = transport or InstrumentedTransport(
            ledger=ledger,
            defaults=defaults,
            client=client,
        )

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        stage = kwargs.pop("ledger_stage", None)
        endpoint_class = kwargs.pop("ledger_endpoint_class", "")
        rate_resource = kwargs.pop("ledger_rate_resource", None)
        attempt = kwargs.pop("ledger_attempt", 1)
        query_id = kwargs.pop("ledger_query_id", "")
        pack_id = kwargs.pop("ledger_pack_id", "")
        verb = method.lower()
        sender = getattr(self._client, verb, None)
        started = time.perf_counter()
        error_class = ""
        status_code: int | None = None
        response_bytes = 0
        try:
            if callable(sender):
                response = await sender(url, **kwargs)
            else:
                response = await self._client.request(method, url, **kwargs)
            status_code = response.status_code
            response_bytes = len(response.content or b"")
            return response
        except httpx.TimeoutException:
            error_class = "timeout"
            raise
        except httpx.TransportError:
            error_class = "network"
            raise
        except Exception:
            error_class = "internal"
            raise
        finally:
            self._transport._emit(
                method=method,
                url=url,
                stage=stage,
                endpoint_class=endpoint_class,
                rate_resource=rate_resource,
                attempt=attempt,
                query_id=query_id,
                pack_id=pack_id,
                status_code=status_code,
                error_class=error_class,
                latency_ms=int((time.perf_counter() - started) * 1000),
                response_bytes=response_bytes,
            )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    def with_defaults(self, **kwargs: Any) -> InstrumentedAsyncClient:
        return InstrumentedAsyncClient(
            self._client,
            transport=self._transport.with_defaults(**kwargs),
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def record_sync_attempt(
    *,
    method: str,
    url: str,
    stage: LedgerStage,
    source: str,
    status_code: int | None = None,
    error_class: str = "",
    latency_ms: int = 0,
    attempt: int = 1,
    endpoint_class: str = "",
    rate_resource: RateResource = "other",
    query_id: str = "",
    response_bytes: int = 0,
) -> None:
    """Convenience for legacy sync clients (FOFA/Shodan)."""
    ledger = get_current_ledger()
    if ledger is None:
        return
    entry = make_entry(
        run_id=ledger.run_id,
        stage=stage,
        source=source,
        http_method=method,
        endpoint_class=normalize_endpoint_class(url, endpoint_class),
        status_code=status_code,
        error_class=error_class,
        latency_ms=latency_ms,
        attempt=attempt,
        rate_resource=rate_resource,
        query_id=query_id,
        response_bytes=response_bytes,
    )
    ledger.record(entry)
