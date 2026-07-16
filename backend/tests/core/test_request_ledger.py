"""Unit tests for RequestLedger buffer + attempt counting."""

from __future__ import annotations

from aipocket.core.request_ledger import RequestLedger, make_entry


def test_record_and_drain():
    ledger = RequestLedger(run_id="run_1")
    ledger.record(make_entry(run_id="run_1", stage="discovery", source="fofa", status_code=200))
    ledger.record(
        make_entry(run_id="run_1", stage="validation", source="validator", status_code=401)
    )
    rows = ledger.drain()
    assert len(rows) == 2
    assert ledger.drain() == []
    assert rows[0].stage == "discovery"
    assert rows[1].status_class == "4xx"


def test_retry_after_429_creates_two_ledger_rows():
    ledger = RequestLedger(run_id="run_r")
    ledger.record(
        make_entry(
            run_id="run_r",
            stage="discovery",
            source="fofa",
            status_code=429,
            attempt=1,
            endpoint_class="/api/v1/search/all",
        )
    )
    ledger.record(
        make_entry(
            run_id="run_r",
            stage="discovery",
            source="fofa",
            status_code=200,
            attempt=2,
            endpoint_class="/api/v1/search/all",
        )
    )
    rows = ledger.drain()
    assert len(rows) == 2
    assert rows[0].attempt == 1 and rows[0].status_code == 429
    assert rows[1].attempt == 2 and rows[1].status_code == 200


def test_flush_every_and_failure_marks_incomplete():
    flushed: list = []

    def on_flush(batch):
        if len(flushed) == 0:
            flushed.extend(batch)
            return
        raise RuntimeError("pg down")

    ledger = RequestLedger(run_id="run_f", flush_every=2, on_flush=on_flush)
    ledger.record(make_entry(run_id="run_f", stage="probe", source="prober", status_code=200))
    ledger.record(make_entry(run_id="run_f", stage="probe", source="prober", status_code=200))
    assert len(flushed) == 2
    assert ledger.is_complete

    ledger.record(make_entry(run_id="run_f", stage="probe", source="prober", status_code=200))
    ledger.record(make_entry(run_id="run_f", stage="probe", source="prober", status_code=200))
    assert ledger.flush_failed
    assert not ledger.is_complete
    assert "pg down" in ledger.flush_error


def test_totals_by_stage_and_source():
    ledger = RequestLedger(run_id="run_t")
    for _ in range(3):
        ledger.record(make_entry(run_id="run_t", stage="discovery", source="fofa", status_code=200))
    ledger.record(make_entry(run_id="run_t", stage="balance", source="balance", status_code=200))
    totals = ledger.totals()
    assert totals.total == 4
    assert totals.by_stage["discovery"] == 3
    assert totals.by_source["fofa"] == 3


def test_mark_incomplete():
    ledger = RequestLedger(run_id="run_i")
    ledger.mark_incomplete("missing instrumentation")
    assert not ledger.is_complete
    assert ledger.incomplete_reason == "missing instrumentation"
