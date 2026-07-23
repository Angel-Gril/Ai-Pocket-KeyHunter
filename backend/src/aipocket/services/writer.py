from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aipocket.core.config import settings
from aipocket.core.metrics import (
    ExtractionMethodAggregate,
    QueryMetric,
    ValidationOutcomeAggregate,
)
from aipocket.core.models import ScanRunResult, ValidationResult
from aipocket.services.credential_policy import filter_results_by_policy

log = logging.getLogger(__name__)

# Unicode 行/段分隔符：JSON 语法允许其以裸字节出现在字符串里，但 VSCode 的 JSON
# 语言服务会把它们当作行终止符，导致整个文件无法解析（弹窗 "unusual line terminators"）。
# 纯写入时统一替换成普通空格；中文、emoji 等正常字符不受影响。
_UNSAFE_LINE_TERMINATORS = str.maketrans({"\u2028": " ", "\u2029": " "})


def _sanitize_json_text(text: str) -> str:
    return text.translate(_UNSAFE_LINE_TERMINATORS)


def _jsonl_line(obj: Any) -> str:
    """Serialize one object to a sanitized JSONL line (with trailing newline)."""
    return _sanitize_json_text(json.dumps(obj, ensure_ascii=False, default=str)) + "\n"


def _run_dir_name(when: datetime | None = None) -> str:
    """Folder name for one scan run: run_YYYY_MM_DD_HH-MM-SS."""
    ts = (when or datetime.now(UTC)).strftime("%Y_%m_%d_%H-%M-%S")
    return f"run_{ts}"


def new_run_dir(base: Path | None = None) -> Path:
    """Create and return a fresh run directory under results/."""
    root = base or settings.results_path
    d = root / _run_dir_name()
    d.mkdir(parents=True, exist_ok=True)
    log.info("Run directory: %s", d)
    return d


# ---------------------------------------------------------------------------
# PostgreSQL persistence (source of truth when DATABASE_URL is set)
# ---------------------------------------------------------------------------


def _result_row(r: ValidationResult, kind: str, seq: int) -> tuple:
    """Build the (run_id-less) column tuple for one results row, with full record."""
    from psycopg.types.json import Jsonb

    rec = r.model_dump()
    cred = rec.get("credential") or {}
    provider_info = rec.get("provider_info") or {}
    return (
        kind,
        seq,
        cred.get("apikey", ""),
        cred.get("apiurl", ""),
        cred.get("host", ""),
        bool(rec.get("valid")),
        Jsonb(rec),
        str(provider_info.get("credential_issuer") or "unknown"),
        str(provider_info.get("validation_provider") or provider_info.get("provider") or ""),
    )


def create_run_pg(run_id: str, started_at: str, scan_mode: str) -> None:
    """Create the parent run before any request-ledger child rows can flush."""
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction():
        conn.execute(
            """
            INSERT INTO runs (
                run_id, started_at, state, sources, hits_by_source, queries_used,
                total_hosts, total_credentials, total_valid, metrics_version,
                scan_mode, ledger_complete, ledger_incomplete_reason
            ) VALUES (%s, %s, 'running', '[]'::jsonb, '{}'::jsonb, '[]'::jsonb,
                      0, 0, 0, 2, %s, FALSE, 'running')
            ON CONFLICT (run_id) DO UPDATE SET
                started_at = EXCLUDED.started_at,
                finished_at = NULL,
                state = 'running',
                ledger_complete = FALSE,
                ledger_incomplete_reason = 'running'
            """,
            (run_id, started_at, scan_mode),
        )


def mark_run_interrupted_pg(run_id: str, reason: str) -> None:
    """Leave a durable non-v3 run marker when execution aborts after creation."""
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            UPDATE runs
            SET finished_at = NOW(), state = 'interrupted', metrics_version = 2,
                ledger_complete = FALSE, ledger_incomplete_reason = %s
            WHERE run_id = %s
            """,
            (reason, run_id),
        )
        conn.commit()


def persist_ledger_batch_pg(entries: list[Any]) -> None:
    """Batch-insert request_ledger rows. Callers pass RequestLedgerEntry objects."""
    if not entries:
        return
    from aipocket.core.db import get_pool

    rows = [
        (
            e.request_id,
            e.run_id,
            e.stage,
            e.source,
            e.query_id,
            e.pack_id,
            e.credential_fingerprint,
            e.target_identity,
            e.artifact_identity,
            e.product,
            e.spec_id,
            e.provider,
            e.http_method,
            e.endpoint_class,
            e.status_class,
            e.status_code,
            e.error_class,
            e.latency_ms,
            e.request_bytes,
            e.response_bytes,
            e.query_credit,
            e.rate_resource,
            e.attempt,
            e.started_at or None,
        )
        for e in entries
    ]
    pool = get_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            """
                INSERT INTO request_ledger (
                    request_id, run_id, stage, source, query_id, pack_id,
                    credential_fingerprint, target_identity, artifact_identity,
                    product, spec_id, provider, http_method, endpoint_class,
                    status_class, status_code, error_class, latency_ms,
                    request_bytes, response_bytes, query_credit, rate_resource,
                    attempt, started_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
            rows,
        )


def persist_run_pg(
    run_id: str,
    metadata: dict,
    valid: list[ValidationResult],
    suspicious: list[ValidationResult],
    query_metrics: list[QueryMetric] | None = None,
    validation_outcomes: list[ValidationOutcomeAggregate] | None = None,
    observation_counts: list[ExtractionMethodAggregate] | None = None,
    *,
    rejected: list[ValidationResult] | None = None,
) -> None:
    """Write one run's metadata plus valid/suspicious rows transactionally.

    Idempotent per run_id: the run is UPSERTed and its result rows are replaced.
    ``seq`` is stable within each ``(run_id, kind)`` sequence.

    ``rejected`` is accepted for call-site compatibility but **never** written to
    ``results`` (auth_rejected / no_auth_endpoint noise is not product data).
    """
    from psycopg.types.json import Jsonb

    from aipocket.core.db import get_pool
    valid = filter_results_by_policy(valid, stage="persist-run-valid")
    suspicious = filter_results_by_policy(suspicious, stage="persist-run-suspicious")
    # Intentionally discarded — do not bloat results with 401/no-auth rejects.
    if rejected:
        log.info(
            "Skipping persist of %d rejected result(s) for run %s (not stored)",
            len(rejected),
            run_id,
        )
    rejected = []

    active_requests = int(metadata.get("active_requests", 0))
    if validation_outcomes is not None:
        outcome_sum = sum(row.count for row in validation_outcomes)
        if outcome_sum != active_requests:
            # Soft-fail: a metrics mismatch must not discard an otherwise complete
            # scan that already finished validate/honeypot/balance work.
            log.warning(
                "validation outcome count (%d) != active_requests (%d) for run %s; "
                "persisting anyway",
                outcome_sum,
                active_requests,
                run_id,
            )

    pool = get_pool()
    with pool.connection() as conn, conn.transaction():
        conn.execute(
            """
            INSERT INTO runs (run_id, started_at, finished_at, state, sources,
                              hits_by_source, queries_used, total_hosts,
                              total_credentials, total_valid, raw_hits,
                              unique_targets, candidates, active_requests,
                              final_verified, suspicious, high_value_final,
                              metrics_version, scan_mode,
                              total_active_http_requests, ledger_complete,
                              ledger_incomplete_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s)
            ON CONFLICT (run_id) DO UPDATE SET
                finished_at = EXCLUDED.finished_at,
                state = EXCLUDED.state,
                sources = EXCLUDED.sources,
                hits_by_source = EXCLUDED.hits_by_source,
                queries_used = EXCLUDED.queries_used,
                total_hosts = EXCLUDED.total_hosts,
                total_credentials = EXCLUDED.total_credentials,
                total_valid = EXCLUDED.total_valid,
                raw_hits = EXCLUDED.raw_hits,
                unique_targets = EXCLUDED.unique_targets,
                candidates = EXCLUDED.candidates,
                active_requests = EXCLUDED.active_requests,
                final_verified = EXCLUDED.final_verified,
                suspicious = EXCLUDED.suspicious,
                high_value_final = EXCLUDED.high_value_final,
                metrics_version = EXCLUDED.metrics_version,
                scan_mode = EXCLUDED.scan_mode,
                total_active_http_requests = EXCLUDED.total_active_http_requests,
                ledger_complete = EXCLUDED.ledger_complete,
                ledger_incomplete_reason = EXCLUDED.ledger_incomplete_reason
            """,
            (
                run_id,
                metadata.get("started_at"),
                metadata.get("finished_at"),
                metadata.get("state"),
                Jsonb(metadata.get("sources", [])),
                Jsonb(metadata.get("hits_by_source", {})),
                Jsonb(metadata.get("queries_used", [])),
                metadata.get("total_hosts"),
                metadata.get("total_credentials"),
                len(valid),
                metadata.get("raw_hits", 0),
                metadata.get("unique_targets", 0),
                metadata.get("candidates", 0),
                metadata.get("active_requests", 0),
                metadata.get("final_verified", 0),
                metadata.get("suspicious", 0),
                metadata.get("high_value_final", 0),
                metadata.get("metrics_version", 2),
                metadata.get("scan_mode", "incremental"),
                metadata.get("total_active_http_requests", 0),
                bool(metadata.get("ledger_complete", False)),
                metadata.get("ledger_incomplete_reason", ""),
            ),
        )
        # Replace this run's result rows so a re-persist is idempotent.
        conn.execute("DELETE FROM results WHERE run_id = %s", (run_id,))
        rows = [(run_id, *_result_row(r, "valid", i)) for i, r in enumerate(valid)] + [
            (run_id, *_result_row(r, "suspicious", i)) for i, r in enumerate(suspicious)
        ]
        if rows:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO results (
                        run_id, kind, seq, apikey, apiurl, host, valid, record,
                        credential_issuer, validation_provider
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    rows,
                )
        for metric in query_metrics or []:
            funnel = metric.funnel
            conn.execute(
                """
                INSERT INTO query_metrics (
                    run_id, source, query, raw_hits, unique_targets,
                    active_requests, candidates, prefilter_survivors,
                    auth_confirmed, final_verified, noauth_rejected, query_credits,
                    attribution_version, total_active_http_requests, lane, pack_id, query_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id, source, query) DO UPDATE SET
                    raw_hits = EXCLUDED.raw_hits,
                    unique_targets = EXCLUDED.unique_targets,
                    active_requests = EXCLUDED.active_requests,
                    candidates = EXCLUDED.candidates,
                    prefilter_survivors = EXCLUDED.prefilter_survivors,
                    auth_confirmed = EXCLUDED.auth_confirmed,
                    final_verified = EXCLUDED.final_verified,
                    noauth_rejected = EXCLUDED.noauth_rejected,
                    query_credits = EXCLUDED.query_credits,
                    attribution_version = EXCLUDED.attribution_version,
                    total_active_http_requests = EXCLUDED.total_active_http_requests,
                    lane = EXCLUDED.lane,
                    pack_id = EXCLUDED.pack_id,
                    query_id = EXCLUDED.query_id
                """,
                (
                    run_id,
                    metric.source,
                    metric.query,
                    funnel.raw_hits,
                    funnel.unique_targets,
                    funnel.active_requests,
                    funnel.candidates,
                    funnel.prefilter_survivors,
                    funnel.auth_confirmed,
                    funnel.final_verified,
                    funnel.noauth_rejected,
                    funnel.query_credits,
                    metric.attribution_version,
                    funnel.total_active_http_requests,
                    metric.lane,
                    metric.pack_id,
                    metric.query_id,
                ),
            )
        conn.execute("DELETE FROM extraction_method_aggregates WHERE run_id = %s", (run_id,))
        for aggregate in observation_counts or []:
            conn.execute(
                """
                INSERT INTO extraction_method_aggregates (run_id, method, count)
                VALUES (%s, %s, %s)
                """,
                (run_id, aggregate.method, aggregate.count),
            )
        conn.execute("DELETE FROM validation_outcome_aggregates WHERE run_id = %s", (run_id,))
        for aggregate in validation_outcomes or []:
            conn.execute(
                """
                INSERT INTO validation_outcome_aggregates (
                    run_id, source, query, provider, validation_state,
                    error_class, status_code, count
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    run_id,
                    aggregate.source,
                    aggregate.query,
                    aggregate.provider,
                    aggregate.validation_state,
                    aggregate.error_class,
                    aggregate.status_code,
                    aggregate.count,
                ),
            )
    log.info(
        "PG run persisted: %s (%d valid, %d suspicious)",
        run_id,
        len(valid),
        len(suspicious),
    )


def update_run_log_pg(run_id: str, log_text: str) -> None:
    """Store the final run.log text on the runs row (best-effort; run must exist)."""
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        conn.execute("UPDATE runs SET log = %s WHERE run_id = %s", (log_text, run_id))
        conn.commit()


# ---------------------------------------------------------------------------
# JSONL writers
# ---------------------------------------------------------------------------


def write_scan_metadata(metadata: dict, run_dir: Path) -> Path:
    """Write first line of scan_<ts>.jsonl — the metadata header.

    No-op (returns the intended path) when JSONL writing is disabled (PG-only
    mode); the same metadata is persisted to the ``runs`` table via persist_run_pg.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"scan_{ts}.jsonl"
    if not settings.write_jsonl:
        return path
    path.write_text(_jsonl_line(metadata), encoding="utf-8")
    log.info("Scan metadata written: %s", path)
    return path


def append_scan_result(result: ValidationResult, scan_path: Path) -> None:
    """Append one ValidationResult as a JSONL line (no-op in PG-only mode)."""
    if not settings.write_jsonl:
        return
    with scan_path.open("a", encoding="utf-8") as f:
        f.write(_jsonl_line(result.model_dump()))


def write_valid_results(results: list[ValidationResult], run_dir: Path) -> Path:
    """Write valid_<ts>.jsonl — each line is one valid result (no-op in PG-only mode)."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"valid_{ts}.jsonl"
    if not settings.write_jsonl:
        return path
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(_jsonl_line(r.model_dump()))
    log.info("Valid results written: %s (count=%d)", path, len(results))
    return path


def _mask_apikey(apikey: str) -> str:
    """Mask a credential so findings artifacts never contain plaintext keys."""
    if not apikey:
        return ""
    if len(apikey) <= 10:
        return apikey[:2] + "…"
    return f"{apikey[:6]}…{apikey[-4:]}"


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Serialize a prober Finding for the run artifact (credentials masked)."""
    return {
        "vuln_class": getattr(finding.vuln_class, "value", str(finding.vuln_class)),
        "product": finding.product,
        "target_origin": finding.target_origin,
        "spec_id": finding.spec_id,
        "cve_ids": list(finding.cve_ids),
        "confirmed": finding.confirmed,
        "severity": finding.severity,
        "summary": finding.summary,
        "evidence": finding.evidence,
        # Never persist plaintext keys — mask + count only.
        "credential_count": len(finding.credentials),
        "credentials_masked": [_mask_apikey(c.apikey) for c in finding.credentials],
    }


def _node_outcome_to_dict(node: Any) -> dict[str, Any]:
    return {
        "spec_id": node.spec_id,
        "vuln_class": getattr(node.vuln_class, "value", str(node.vuln_class)),
        "risk_level": int(node.risk_level),
        "status": getattr(node.status, "value", str(node.status)),
        "requests_used": node.requests_used,
        "reason": node.reason,
        "credentials_found": node.credentials_found,
    }


def write_probe_findings(
    findings: list[Any],
    node_outcomes: list[Any],
    run_dir: Path,
) -> Path:
    """Persist prober findings + node outcomes to ``probe_findings_<ts>.json``.

    These are the recoverable, per-target security results (SSRF/SQLi/RCE/IDOR
    proofs, CVE evidence, and *why* each node did or didn't run) that were
    previously only aggregated into a log line. Plaintext credentials are masked
    so the artifact is safe to retain. No-op when JSONL writing is disabled
    (PG-only mode); the aggregate log line still records the summary.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"probe_findings_{ts}.json"
    if not settings.write_jsonl:
        return path
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "findings_total": len(findings),
        "findings_confirmed": sum(1 for f in findings if f.confirmed),
        "findings": [_finding_to_dict(f) for f in findings],
        "node_outcomes": [_node_outcome_to_dict(n) for n in node_outcomes],
    }
    text = _sanitize_json_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    path.write_text(text, encoding="utf-8")
    log.info(
        "Probe findings written: %s (findings=%d, nodes=%d)",
        path,
        len(findings),
        len(node_outcomes),
    )
    return path


def write_suspicious_results(results: list[ValidationResult], run_dir: Path) -> Path:
    """Write suspicious_<ts>.jsonl — quarantined results for manual review.

    These passed validation but sit on a host flagged by verify_no_auth
    (forged-key 429 = open-proxy signal, or 200-non-completion = not-a-real-
    gateway). They keep valid=True but are split out of valid_*.jsonl so they
    don't consume balance-enrichment budget or pollute the high-confidence set.

    No-op in PG-only mode (results go to the ``results`` table, kind='suspicious').
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"suspicious_{ts}.jsonl"
    if not settings.write_jsonl:
        return path
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(_jsonl_line(r.model_dump()))
    log.info("Suspicious results written: %s (count=%d)", path, len(results))
    return path


def append_results_pg(
    run_id: str,
    valid: list[ValidationResult],
    suspicious: list[ValidationResult],
    rejected: list[ValidationResult] | None = None,
) -> None:
    """**Primary path**: append new rows into PostgreSQL for an existing run.

    Source of truth when ``DATABASE_URL`` is set (same as the main scan path).

    Append semantics (never replace):
    - ``INSERT`` into ``results`` with ``seq = MAX(seq)+1`` per kind
    - Does **not** ``DELETE`` existing rows (unlike :func:`persist_run_pg`)
    - Recounts ``runs.total_valid`` / ``final_verified`` / ``suspicious``

    ``rejected`` is accepted for call-site compatibility but **never** inserted.

    Raises ``LookupError`` if ``run_id`` is missing from ``runs``.
    No-op when PG is disabled or both lists are empty.
    """
    if not settings.pg_enabled:
        return
    if rejected:
        log.info(
            "Skipping append of %d rejected result(s) for run %s (not stored)",
            len(rejected),
            run_id,
        )
    valid = filter_results_by_policy(valid, stage="append-valid")
    suspicious = filter_results_by_policy(suspicious, stage="append-suspicious")
    if not valid and not suspicious:
        return

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction():
        exists = conn.execute("SELECT 1 FROM runs WHERE run_id = %s", (run_id,)).fetchone()
        if exists is None:
            raise LookupError(f"run not in PG: {run_id}")

        for kind, items in (("valid", valid), ("suspicious", suspicious)):
            if not items:
                continue
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), -1) AS m FROM results WHERE run_id = %s AND kind = %s",
                (run_id, kind),
            ).fetchone()
            start = int(row["m"]) + 1 if row else 0
            insert_rows = [(run_id, *_result_row(r, kind, start + i)) for i, r in enumerate(items)]
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO results (
                        run_id, kind, seq, apikey, apiurl, host, valid, record,
                        credential_issuer, validation_provider
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    insert_rows,
                )

        conn.execute(
            """
            UPDATE runs SET
                total_valid = (
                    SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'valid'
                ),
                final_verified = (
                    SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'valid'
                ),
                suspicious = (
                    SELECT COUNT(*) FROM results WHERE run_id = %s AND kind = 'suspicious'
                ),
                total_credentials = COALESCE(total_credentials, 0) + %s
            WHERE run_id = %s
            """,
            (
                run_id,
                run_id,
                run_id,
                len(valid) + len(suspicious),
                run_id,
            ),
        )
    log.info(
        "PG append for %s: +%d valid, +%d suspicious",
        run_id,
        len(valid),
        len(suspicious),
    )


def append_results_jsonl(
    results: list[ValidationResult],
    run_dir: Path,
    kind: str,
) -> Path | None:
    """Optional dual-write: new ``{kind}_retry_<ts>.jsonl`` (never rewrites old files).

    Only used when ``settings.write_jsonl`` is True. Production with PG-only
    (``pg_dual_write=false``) skips this entirely — results live in the DB.
    """
    if not results or not settings.write_jsonl:
        return None
    if kind not in ("valid", "suspicious"):
        raise ValueError(f"invalid kind for append: {kind}")
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"{kind}_retry_{ts}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(_jsonl_line(r.model_dump()))
    log.info(
        "Dual-write JSONL: +%d %s → %s",
        len(results),
        kind,
        path.name,
    )
    return path


def write_raw_hits(hits: list[dict[str, Any]], run_dir: Path | None = None) -> Path:
    """Write raw_hits_<ts>.jsonl — each line is one hit."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = run_dir or settings.results_path
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"raw_hits_{ts}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for hit in hits:
            f.write(_jsonl_line(hit))
    log.info("Raw hits written: %s (total=%d)", path, len(hits))
    return path


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


def load_latest() -> list[dict] | None:
    """Load the most recent run's valid results as dicts. None if none found.

    Reads PG (newest run by run_id, kind='valid', ordered by seq) when enabled;
    otherwise falls back to the newest ``valid_*.jsonl`` file. Used by the CLI
    ``balance`` command.
    """
    if settings.pg_enabled:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            row = conn.execute("SELECT run_id FROM runs ORDER BY run_id DESC LIMIT 1").fetchone()
            if row is None:
                log.warning("No runs in PG")
                return None
            recs = conn.execute(
                "SELECT record FROM results WHERE run_id = %s AND kind = 'valid' ORDER BY seq",
                (row["run_id"],),
            ).fetchall()
        return [r["record"] for r in recs]

    root = settings.results_path
    runs = sorted(
        (p for p in root.glob("run_*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    for run in runs:
        for vf in sorted(run.glob("valid_*.jsonl"), reverse=True):
            try:
                lines = vf.read_text(encoding="utf-8").splitlines()
                return [json.loads(line) for line in lines if line.strip()]
            except (ValueError, OSError) as e:
                log.warning("Failed to read %s: %s", vf, e)
    log.warning("No run_*/valid_*.jsonl found under %s", root)
    return None


# ---------------------------------------------------------------------------
# Backward-compat wrapper
# ---------------------------------------------------------------------------


def write_result(result: ScanRunResult, run_dir: Path | None = None) -> Path:
    """Write full scan as JSONL (metadata + results) and valid_*.jsonl.

    Backward-compat entry point: writes metadata as first line, then each
    ValidationResult, and also produces a valid_*.jsonl summary file.
    Returns the scan_*.jsonl path.
    """
    out_dir = run_dir or settings.results_path
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build metadata dict (everything except results and raw_hits)
    metadata = result.model_dump(exclude={"results", "raw_hits"})

    scan_path = write_scan_metadata(metadata, out_dir)

    # Append each result
    for r in result.results:
        append_scan_result(r, scan_path)

    # Write valid-only summary
    valid = [r for r in result.results if r.valid]
    write_valid_results(valid, out_dir)

    return scan_path
