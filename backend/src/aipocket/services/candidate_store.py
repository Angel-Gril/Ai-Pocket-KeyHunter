"""Spill intermediate scan candidates to PostgreSQL (memory-bounded path).

During a long FOFA/Shodan/GitHub + prober run, holding every candidate /
finding in process memory OOMs small hosts. This module batch-upserts
:class:`~aipocket.core.models.Credential` rows (including GitHub
:class:`~aipocket.core.credentials.CredentialBundle` evidence) into
``scan_candidates``, and stores lightweight prober telemetry in
``scan_probe_events``.

When ``DATABASE_URL`` is unset, all functions are no-ops / empty returns so
the in-memory path remains usable for tests and local CLI runs without PG.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from typing import Any

from aipocket.core.config import settings
from aipocket.core.credentials import (
    CredentialBundle,
    CredentialContext,
    CredentialEvidence,
)
from aipocket.core.models import Credential
from aipocket.core.observations import ExtractionMethod, credential_identity
from aipocket.services.credential_policy import (
    filter_credentials_by_policy,
    is_google_direct_result,
)

log = logging.getLogger(__name__)

# Stage labels written into scan_candidates.stage
STAGE_REGEX = "regex"
STAGE_PROBER = "prober"
STAGE_GITHUB = "github"
STAGE_GPT = "gpt"


def spill_enabled() -> bool:
    """True when intermediate candidates should go to PG instead of RAM."""
    return bool(settings.pg_enabled)


def serialize_credential(credential: Credential) -> dict[str, Any]:
    """Serialize a Credential including bundle secret (for re-validation).

    ``Credential.bundle`` is ``exclude=True`` on the model so ``model_dump()``
    alone loses GitHub evidence; we re-attach a plain dict form here.
    """
    data = credential.model_dump()
    if credential.bundle is not None:
        bundle = credential.bundle
        data["bundle"] = {
            "credential_kind": bundle.credential_kind,
            "secret": bundle.secret_value.reveal(),
            "secret_fingerprint": bundle.secret_fingerprint,
            "endpoint_candidates": list(bundle.endpoint_candidates),
            "provider_hint": bundle.provider_hint,
            "context": bundle.context.model_dump(),
            "evidence": [e.model_dump() for e in bundle.evidence],
            "confidence": bundle.confidence,
            "validation_state": bundle.validation_state,
        }
    return data


def deserialize_credential(record: dict[str, Any]) -> Credential:
    """Rebuild a Credential (and optional GitHub bundle) from a stored record."""
    data = dict(record)
    bundle_raw = data.pop("bundle", None)
    bundle: CredentialBundle | None = None
    if isinstance(bundle_raw, dict) and bundle_raw.get("secret"):
        ctx_raw = bundle_raw.get("context") or {}
        evidence_raw = bundle_raw.get("evidence") or []
        bundle = CredentialBundle.create(
            str(bundle_raw["secret"]),
            credential_kind=bundle_raw.get("credential_kind") or "api_key",
            endpoint_candidates=tuple(bundle_raw.get("endpoint_candidates") or ()),
            provider_hint=str(bundle_raw.get("provider_hint") or "unknown"),
            context=(
                CredentialContext(**ctx_raw) if isinstance(ctx_raw, dict) else CredentialContext()
            ),
            evidence=tuple(CredentialEvidence(**e) for e in evidence_raw if isinstance(e, dict)),
            confidence=bundle_raw.get("confidence") or "medium",
        )
        if not data.get("apikey"):
            data["apikey"] = bundle.secret_value.reveal()
    allowed = set(Credential.model_fields)
    slim = {k: v for k, v in data.items() if k in allowed}
    cred = Credential(**slim)
    if bundle is not None:
        cred = cred.model_copy(update={"bundle": bundle})
    return cred


def _identity_key(credential: Credential) -> str:
    ident = credential_identity(credential)
    return f"{ident.secret_fingerprint}:{ident.endpoint}"


def _candidate_row(
    run_id: str,
    stage: str,
    credential: Credential,
    *,
    source: str = "",
    query_id: str = "",
    pack_id: str = "",
    lane: str = "",
    method: str = "",
    prefilter_ok: bool = True,
) -> tuple:
    from psycopg.types.json import Jsonb

    rec = serialize_credential(credential)
    return (
        run_id,
        stage,
        _identity_key(credential),
        credential.apikey or "",
        credential.apiurl or "",
        credential.host or "",
        source or (credential.backend or credential.source or ""),
        query_id,
        pack_id,
        lane,
        method or stage,
        prefilter_ok,
        Jsonb(rec),
    )


def upsert_candidates(
    run_id: str,
    stage: str,
    credentials: Sequence[Credential],
    *,
    source: str = "",
    query_id: str = "",
    pack_id: str = "",
    lane: str = "",
    method: str = "",
    prefilter_ok: bool = True,
    provenance: Sequence[tuple[str, str, str, str]] | None = None,
) -> int:
    """Batch-upsert candidates. Returns number of rows attempted.

    ``provenance`` optional parallel list of ``(source, query_id, pack_id, lane)``
    per credential (used for GitHub). When omitted, ``source``/``query_id``/…
    apply to every row.

    First-write wins on ``(run_id, identity)`` so later stages do not thrash
    the primary payload; stage diversity is visible via the first-writer stage.
    """
    if not spill_enabled() or not run_id or not credentials:
        return 0
    credentials = filter_credentials_by_policy(credentials, stage=f"candidate:{stage}")
    if not credentials:
        return 0

    rows: list[tuple] = []
    for idx, cred in enumerate(credentials):
        src, qid, pid, ln = source, query_id, pack_id, lane
        if provenance is not None and idx < len(provenance):
            src, qid, pid, ln = provenance[idx]
        rows.append(
            _candidate_row(
                run_id,
                stage,
                cred,
                source=src,
                query_id=qid,
                pack_id=pid,
                lane=ln,
                method=method or stage,
                prefilter_ok=prefilter_ok,
            )
        )

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO scan_candidates (
                run_id, stage, identity, apikey, apiurl, host,
                source, query_id, pack_id, lane, method, prefilter_ok, record
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (run_id, identity) DO NOTHING
            """,
            rows,
        )
    log.info(
        "scan_candidates upsert: run=%s stage=%s attempted=%d",
        run_id,
        stage,
        len(rows),
    )
    return len(rows)


def upsert_github_observations(run_id: str, observations: Sequence[Any]) -> int:
    """Spill GitHub :class:`CredentialSourceObservation` rows with full evidence."""
    if not spill_enabled() or not run_id or not observations:
        return 0

    creds: list[Credential] = []
    provenance: list[tuple[str, str, str, str]] = []
    for obs in observations:
        cred = obs.credential
        creds.append(cred)
        provenance.append(
            (
                "github",
                getattr(obs, "query_id", "") or "",
                getattr(obs, "pack_id", "") or "",
                getattr(obs, "lane", "") or "",
            )
        )
    return upsert_candidates(
        run_id,
        STAGE_GITHUB,
        creds,
        method=ExtractionMethod.REGEX.value,
        provenance=provenance,
    )


def load_candidates(
    run_id: str,
    *,
    stages: Iterable[str] | None = None,
    prefilter_ok_only: bool = True,
) -> list[Credential]:
    """Load spilled candidates for validation / observation rebuild."""
    if not spill_enabled() or not run_id:
        return []

    out: list[Credential] = []
    for page in iter_candidate_pages(run_id, stages=stages, prefilter_ok_only=prefilter_ok_only):
        out.extend(page)
    return out


def iter_candidate_pages(
    run_id: str,
    *,
    stages: Iterable[str] | None = None,
    prefilter_ok_only: bool = True,
    batch_size: int | None = None,
    skip_identities: set[str] | None = None,
) -> Iterable[list[Credential]]:
    """Keyset-page load candidates (bounded working set).

    Yields pages ordered by ``id``. When ``skip_identities`` is set, those
    rows are filtered out in SQL (resume mid-validate).
    """
    if not spill_enabled() or not run_id:
        return

    from aipocket.core.config import settings as _settings

    page_size = max(1, int(batch_size or _settings.validate_batch_size))
    from aipocket.core.db import get_pool

    base_clauses = ["run_id = %s"]
    base_params: list[Any] = [run_id]
    if prefilter_ok_only:
        base_clauses.append("prefilter_ok = TRUE")
    stage_list = list(stages) if stages is not None else None
    if stage_list:
        base_clauses.append("stage = ANY(%s)")
        base_params.append(stage_list)
    if skip_identities:
        base_clauses.append("NOT (identity = ANY(%s))")
        base_params.append(list(skip_identities))

    pool = get_pool()
    last_id = 0
    while True:
        clauses = [*base_clauses, "id > %s"]
        params = [*base_params, last_id, page_size]
        sql = f"""
            SELECT id, identity, record FROM scan_candidates
            WHERE {" AND ".join(clauses)}
            ORDER BY id
            LIMIT %s
        """
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        if not rows:
            break
        page: list[Credential] = []
        for row in rows:
            rid = row["id"] if isinstance(row, dict) else row[0]
            record = row["record"] if isinstance(row, dict) else row[2]
            last_id = int(rid)
            if isinstance(record, dict):
                try:
                    page.append(deserialize_credential(record))
                except Exception as e:  # noqa: BLE001 — skip corrupt rows
                    log.warning("skip corrupt scan_candidate row: %s", e)
        if page:
            yield page
        if len(rows) < page_size:
            break


def count_candidates(run_id: str, *, stages: Iterable[str] | None = None) -> int:
    if not spill_enabled() or not run_id:
        return 0
    from aipocket.core.db import get_pool

    clauses = ["run_id = %s", "prefilter_ok = TRUE"]
    params: list[Any] = [run_id]
    stage_list = list(stages) if stages is not None else None
    if stage_list:
        clauses.append("stage = ANY(%s)")
        params.append(stage_list)
    sql = f"SELECT COUNT(*) AS n FROM scan_candidates WHERE {' AND '.join(clauses)}"
    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    if not row:
        return 0
    return int(row["n"] if isinstance(row, dict) else row[0])


def insert_probe_events(
    run_id: str,
    *,
    outcomes: Sequence[Any] = (),
    findings: Sequence[Any] = (),
    node_outcomes: Sequence[Any] = (),
) -> int:
    """Append prober telemetry rows (masked findings). Returns rows written."""
    if not spill_enabled() or not run_id:
        return 0

    from psycopg.types.json import Jsonb

    from aipocket.services.writer import _finding_to_dict, _node_outcome_to_dict

    rows: list[tuple] = []
    for outcome in outcomes:
        rows.append(
            (
                run_id,
                "outcome",
                Jsonb(
                    {
                        "identity_hash": getattr(outcome, "identity_hash", ""),
                        "status": getattr(
                            getattr(outcome, "status", None),
                            "value",
                            str(getattr(outcome, "status", "")),
                        ),
                        "request_count": int(getattr(outcome, "request_count", 0) or 0),
                        "prober": getattr(outcome, "prober", "") or "",
                        "reason": getattr(outcome, "reason", "") or "",
                    }
                ),
            )
        )
    for finding in findings:
        rows.append((run_id, "finding", Jsonb(_finding_to_dict(finding))))
    for node in node_outcomes:
        rows.append((run_id, "node_outcome", Jsonb(_node_outcome_to_dict(node))))

    if not rows:
        return 0

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO scan_probe_events (run_id, event_type, record)
            VALUES (%s, %s, %s)
            """,
            rows,
        )
    return len(rows)


def load_probe_outcomes(run_id: str) -> list[dict[str, Any]]:
    """Load spilled probe outcomes (dicts) for dedup mark_target."""
    if not spill_enabled() or not run_id:
        return []
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT record FROM scan_probe_events
            WHERE run_id = %s AND event_type = 'outcome'
            ORDER BY id
            """,
            (run_id,),
        )
        rows = cur.fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        record = row["record"] if isinstance(row, dict) else row[0]
        if isinstance(record, dict):
            out.append(record)
    return out


def serialize_validation_result(result: Any) -> dict[str, Any]:
    """Serialize ValidationResult including credential bundle secret."""
    data = result.model_dump()
    cred = getattr(result, "credential", None)
    if cred is not None:
        data["credential"] = serialize_credential(cred)
    return data


def deserialize_validation_result(record: dict[str, Any]) -> Any:
    """Rebuild ValidationResult from a stored record."""
    from aipocket.core.models import ValidationResult

    data = dict(record)
    cred_raw = data.pop("credential", None)
    if isinstance(cred_raw, dict):
        data["credential"] = deserialize_credential(cred_raw)
    return ValidationResult(**{k: v for k, v in data.items() if k in ValidationResult.model_fields})


def upsert_validation_results(run_id: str, results: Sequence[Any]) -> int:
    """Spill validation outcomes for resume. Returns rows attempted."""
    if not spill_enabled() or not run_id or not results:
        return 0

    from psycopg.types.json import Jsonb

    rows: list[tuple] = []
    for result in results:
        cred = getattr(result, "credential", None)
        if cred is None or is_google_direct_result(result):
            continue
        identity = _identity_key(cred)
        rows.append(
            (
                run_id,
                identity,
                bool(getattr(result, "valid", False)),
                str(getattr(result, "validation_state", "") or ""),
                str(getattr(result, "error", "") or "")[:500],
                Jsonb(serialize_validation_result(result)),
            )
        )
    if not rows:
        return 0

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO scan_validation_results (
                run_id, identity, valid, validation_state, error, record
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (run_id, identity) DO UPDATE SET
                valid = EXCLUDED.valid,
                validation_state = EXCLUDED.validation_state,
                error = EXCLUDED.error,
                record = EXCLUDED.record
            """,
            rows,
        )
    log.info(
        "scan_validation_results upsert: run=%s attempted=%d",
        run_id,
        len(rows),
    )
    return len(rows)


def load_validated_identities(run_id: str) -> set[str]:
    """Return identity keys already present in scan_validation_results."""
    if not spill_enabled() or not run_id:
        return set()
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT identity FROM scan_validation_results WHERE run_id = %s",
            (run_id,),
        )
        rows = cur.fetchall()
    out: set[str] = set()
    for row in rows:
        ident = row["identity"] if isinstance(row, dict) else row[0]
        if ident:
            out.add(str(ident))
    return out


def load_validation_results(
    run_id: str,
    *,
    valid_only: bool = False,
) -> list[Any]:
    """Load spilled ValidationResult rows (for finalize / resume merge)."""
    if not spill_enabled() or not run_id:
        return []
    from aipocket.core.db import get_pool

    clauses = ["run_id = %s"]
    params: list[Any] = [run_id]
    if valid_only:
        clauses.append("valid = TRUE")
    sql = f"""
        SELECT record FROM scan_validation_results
        WHERE {" AND ".join(clauses)}
        ORDER BY id
    """
    pool = get_pool()
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    out: list[Any] = []
    for row in rows:
        record = row["record"] if isinstance(row, dict) else row[0]
        if isinstance(record, dict):
            try:
                out.append(deserialize_validation_result(record))
            except Exception as e:  # noqa: BLE001
                log.warning("skip corrupt scan_validation_results row: %s", e)
    return out


def mark_orphan_runs_interrupted(reason: str = "process_restart") -> int:
    """Mark any ``state=running`` runs as interrupted after a hard restart.

    Returns number of rows updated. Best-effort: does not raise on PG errors.
    """
    if not settings.pg_enabled:
        return 0
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            cur = conn.execute(
                """
                UPDATE runs
                SET finished_at = COALESCE(finished_at, NOW()),
                    state = 'interrupted',
                    metrics_version = 2,
                    ledger_complete = FALSE,
                    ledger_incomplete_reason = %s
                WHERE state = 'running'
                RETURNING run_id
                """,
                (reason[:200],),
            )
            rows = cur.fetchall() if cur is not None else []
            conn.commit()
        n = len(rows or [])
        if n:
            ids = [r["run_id"] if isinstance(r, dict) else r[0] for r in rows]
            log.warning(
                "Marked %d orphan run(s) interrupted (%s): %s",
                n,
                reason,
                ", ".join(ids[:10]),
            )
        return n
    except Exception as e:  # noqa: BLE001 — startup must not fail
        log.warning("mark_orphan_runs_interrupted failed: %s", e)
        return 0
