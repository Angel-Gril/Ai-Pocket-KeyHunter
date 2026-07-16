"""Per-physical-HTTP-attempt request ledger (metrics v3 denominator).

One row per completed/failed transport attempt. Retries get separate rows with
``attempt`` 1, 2, …. Secrets never belong in ledger fields — only fingerprints
and templated ``endpoint_class`` values.
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

LedgerStage = Literal[
    "discovery", "artifact_fetch", "probe", "validation", "noauth", "balance", "gpt"
]
RateResource = Literal["core", "search", "code_search", "other"]


@dataclass(frozen=True, slots=True)
class RequestAttribution:
    source: str = ""
    query_id: str = ""
    pack_id: str = ""
    lane: str = ""


# Bound for the active scan run so deep HTTP call sites can record without
# threading a ledger through every signature (same pattern as current_run_id).
current_ledger: contextvars.ContextVar[RequestLedger | None] = contextvars.ContextVar(
    "current_ledger", default=None
)
current_query_attribution: contextvars.ContextVar[RequestAttribution | None] = (
    contextvars.ContextVar("current_query_attribution", default=None)
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class RequestLedgerEntry:
    request_id: str
    run_id: str
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
    http_method: str = "GET"
    endpoint_class: str = ""
    status_class: str = ""
    status_code: int | None = None
    error_class: str = ""
    latency_ms: int = 0
    request_bytes: int = 0
    response_bytes: int = 0
    query_credit: float = 0.0
    rate_resource: RateResource = "other"
    attempt: int = 1
    started_at: str = ""

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LedgerTotals:
    total: int
    by_stage: dict[str, int]
    by_source: dict[str, int]
    by_query: dict[tuple[str, str], int]
    by_pack: dict[str, int]


FlushCallback = Callable[[list[RequestLedgerEntry]], None]


@dataclass(slots=True)
class RequestLedger:
    """Thread-safe in-memory buffer of HTTP attempt rows for one scan run."""

    run_id: str
    flush_every: int = 100
    on_flush: FlushCallback | None = None
    _entries: list[RequestLedgerEntry] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _flush_failed: bool = field(default=False, repr=False)
    _flush_error: str = field(default="", repr=False)
    _flushed_count: int = field(default=0, repr=False)
    _recorded_count: int = field(default=0, repr=False)
    incomplete_reason: str = field(default="", repr=False)
    _by_stage: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _by_source: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _by_query: dict[tuple[str, str], int] = field(
        default_factory=lambda: defaultdict(int), repr=False
    )
    _by_pack: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)

    def record(self, entry: RequestLedgerEntry) -> None:
        if entry.run_id != self.run_id:
            # Defensive: never mix runs in one buffer.
            entry = RequestLedgerEntry(**{**entry.to_row(), "run_id": self.run_id})
        batch: list[RequestLedgerEntry] | None = None
        with self._lock:
            self._entries.append(entry)
            self._recorded_count += 1
            self._by_stage[entry.stage] += 1
            self._by_source[entry.source] += 1
            if entry.query_id:
                self._by_query[(entry.source, entry.query_id)] += 1
            if entry.pack_id:
                self._by_pack[entry.pack_id] += 1
            if self.on_flush and len(self._entries) >= self.flush_every:
                batch = list(self._entries)
                self._entries.clear()
        if batch is not None:
            self._do_flush(batch)

    def drain(self) -> list[RequestLedgerEntry]:
        with self._lock:
            out = list(self._entries)
            self._entries.clear()
        if out and self.on_flush:
            self._do_flush(out)
            return []
        return out

    def mark_incomplete(self, reason: str) -> None:
        with self._lock:
            if not self.incomplete_reason:
                self.incomplete_reason = reason

    @property
    def flush_failed(self) -> bool:
        return self._flush_failed

    @property
    def flush_error(self) -> str:
        return self._flush_error

    @property
    def is_complete(self) -> bool:
        """True when flush never failed and no incomplete reason was set."""
        return not self._flush_failed and not self.incomplete_reason

    def count(self) -> int:
        with self._lock:
            return self._recorded_count

    def totals(self) -> LedgerTotals:
        with self._lock:
            return LedgerTotals(
                total=self._recorded_count,
                by_stage=dict(self._by_stage),
                by_source=dict(self._by_source),
                by_query=dict(self._by_query),
                by_pack=dict(self._by_pack),
            )

    def _do_flush(self, batch: list[RequestLedgerEntry]) -> None:
        if not self.on_flush or not batch:
            return
        try:
            self.on_flush(batch)
            with self._lock:
                self._flushed_count += len(batch)
        except Exception as exc:  # noqa: BLE001 — ledger must not crash the scan
            with self._lock:
                self._flush_failed = True
                self._flush_error = f"{type(exc).__name__}: {exc}"
                # Put rows back so drain() can still report them if needed.
                self._entries = batch + self._entries
                self.incomplete_reason = self.incomplete_reason or "ledger_flush_failed"


def new_request_id() -> str:
    return str(uuid.uuid4())


def make_entry(
    *,
    run_id: str,
    stage: LedgerStage,
    source: str,
    http_method: str = "GET",
    endpoint_class: str = "",
    status_code: int | None = None,
    error_class: str = "",
    latency_ms: int = 0,
    attempt: int = 1,
    rate_resource: RateResource = "other",
    query_id: str = "",
    pack_id: str = "",
    credential_fingerprint: str | None = None,
    target_identity: str = "",
    artifact_identity: str = "",
    product: str = "",
    spec_id: str = "",
    provider: str = "",
    request_bytes: int = 0,
    response_bytes: int = 0,
    query_credit: float = 0.0,
    started_at: str = "",
) -> RequestLedgerEntry:
    status_class = ""
    if status_code is not None:
        if 200 <= status_code < 300:
            status_class = "2xx"
        elif 300 <= status_code < 400:
            status_class = "3xx"
        elif 400 <= status_code < 500:
            status_class = "4xx"
        elif 500 <= status_code < 600:
            status_class = "5xx"
        else:
            status_class = "error"
    elif error_class:
        status_class = "error"
    return RequestLedgerEntry(
        request_id=new_request_id(),
        run_id=run_id,
        stage=stage,
        source=source,
        query_id=query_id,
        pack_id=pack_id,
        credential_fingerprint=credential_fingerprint,
        target_identity=target_identity,
        artifact_identity=artifact_identity,
        product=product,
        spec_id=spec_id,
        provider=provider,
        http_method=http_method.upper(),
        endpoint_class=endpoint_class,
        status_class=status_class,
        status_code=status_code,
        error_class=error_class,
        latency_ms=latency_ms,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        query_credit=query_credit,
        rate_resource=rate_resource,
        attempt=attempt,
        started_at=started_at or _utc_now_iso(),
    )


def record_to_current(entry: RequestLedgerEntry) -> None:
    ledger = current_ledger.get()
    if ledger is not None:
        ledger.record(entry)


def get_current_query_attribution() -> RequestAttribution:
    return current_query_attribution.get() or RequestAttribution()


def get_current_ledger() -> RequestLedger | None:
    return current_ledger.get()
