"""Read scan results off disk for the web API.

The CLI's :func:`aipocket.writer.load_latest` only reads the newest run; the web
API needs to browse ALL runs by id, so this module reads the ``results/run_*``
tree directly. It reuses the same on-disk layout the writer produces:

    results/
      run_YYYY_MM_DD_HH-MM-SS/
        valid_*.jsonl        # one ValidationResult.model_dump() per line
        suspicious_*.jsonl   # same shape + suspicious_reason
        run.log              # full execution log

Records are returned as plain dicts (the JSONL shape). Callers mask apikeys via
:mod:`aipocket.api.masking` before returning them to clients.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from aipocket.core.config import settings
from .errors import ApiError
from .masking import mask_apikey

log = logging.getLogger(__name__)

# run_YYYY_MM_DD_HH-MM-SS — anchored so nothing but a real run id validates.
_RUN_ID_RE = re.compile(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")


def _validate_run_id(run_id: str) -> str:
    """Reject anything that isn't a well-formed run id (blocks path traversal)."""
    if not _RUN_ID_RE.match(run_id):
        raise ApiError(f"invalid run id: {run_id}", status_code=400, code="bad_request")
    return run_id


def _run_dir(run_id: str) -> Path:
    _validate_run_id(run_id)
    d = settings.results_path / run_id
    if not d.is_dir():
        raise ApiError(f"run not found: {run_id}", status_code=404, code="not_found")
    return d


# ---------------------------------------------------------------------------
# PostgreSQL read helpers (source of truth when DATABASE_URL is set). Each falls
# back to the JSONL files when PG is disabled OR the run isn't in PG yet (so a
# dual-write cutover and historical-before-backfill runs both keep working).
# ---------------------------------------------------------------------------


def _pg_has_run(run_id: str) -> bool:
    """True when PG is enabled AND this run_id exists in the runs table."""
    if not settings.pg_enabled:
        return False
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        row = conn.execute("SELECT 1 FROM runs WHERE run_id = %s", (run_id,)).fetchone()
    return row is not None


def _pg_load_kind(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Raw records for a run's valid/suspicious list from PG, ordered by seq."""
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT record FROM results WHERE run_id = %s AND kind = %s ORDER BY seq",
            (run_id, kind),
        ).fetchall()
    return [r["record"] for r in rows]


def _day_from_run_id(run_id: str) -> str:
    """`run_2026_07_06_14-35-22` → `2026-07-06`."""
    m = re.match(r"^run_(\d{4})_(\d{2})_(\d{2})_", run_id)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else "unknown"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("skip malformed jsonl line in %s: %s", path.name, line[:80])
    except OSError as e:
        log.warning("failed reading %s: %s", path, e)
    return out


def _scan_metadata(run: Path) -> dict[str, Any]:
    """Read the structured metadata header from the newest scan JSONL file."""
    files = sorted(run.glob("scan_*.jsonl"), reverse=True)
    if not files:
        return {}
    records = _read_jsonl(files[0])
    return records[0] if records else {}


def _sources_of(valid_files: list[Path]) -> list[str]:
    """Distinct discovery backends (``fofa``/``shodan``) seen in a run's valid file."""
    found: set[str] = set()
    for f in valid_files:
        for rec in _read_jsonl(f):
            cred = rec.get("credential")
            backend = cred.get("backend", "") if isinstance(cred, dict) else ""
            for part in str(backend).split(","):
                part = part.strip()
                if part:
                    found.add(part)
    return sorted(found)


def _high_value_by_window(started: list[str]) -> dict[str, int]:
    """Best-effort per-run high-value counts.

    The high-value log (``high_value_keys/keys.jsonl``) is global and keyed by
    ``saved_at``, not by run. We attribute each entry to the most recent run that
    started at or before its ``saved_at`` — i.e. the run that was in flight when
    it was written. ``started`` is the list of run ``started_at`` ISO strings,
    newest first. Returns ``{started_at: count}``.
    """
    counts: dict[str, int] = {s: 0 for s in started if s}
    hv_path = settings.results_path / "high_value_keys" / "keys.jsonl"
    if not hv_path.exists():
        return counts
    # started is newest-first; walk it to find the first run whose start <= saved_at.
    ordered = [s for s in started if s]
    for rec in _read_jsonl(hv_path):
        saved = str(rec.get("saved_at", ""))
        if not saved:
            continue
        for s in ordered:  # newest-first → first match is the enclosing run
            if s <= saved:
                counts[s] = counts.get(s, 0) + 1
                break
    return counts


# Cache of the last computed run list, keyed by a cheap directory signature.
# Building the list parses every run's JSONL files, so we skip the rebuild while
# nothing on disk has changed (run dirs added/removed, or a run dir's mtime bumps
# when new result files land inside it, or the high-value log changes).
_runs_cache: tuple[tuple, list[dict[str, Any]]] | None = None


def _runs_signature(root: Path, runs: list[Path]) -> tuple:
    sig: list[tuple[str, int]] = []
    for r in runs:
        try:
            sig.append((r.name, r.stat().st_mtime_ns))
        except OSError:
            sig.append((r.name, 0))
    try:
        hv_mtime = (root / "high_value_keys" / "keys.jsonl").stat().st_mtime_ns
    except OSError:
        hv_mtime = 0
    return (tuple(sig), hv_mtime)


def list_runs() -> list[dict[str, Any]]:
    """All runs, grouped by day (newest first).

    Returns ``[{"day": "2026-07-06", "runs": [{"run_id", "started_at",
    "valid_count", "suspicious_count", "has_log", "raw_hits",
    "unique_targets", "final_verified", "sources", "high_value_final"}, ...]}, ...]``.

    Reads PG (SQL aggregation) when enabled; otherwise walks the results/ tree.
    """
    if settings.pg_enabled:
        return _list_runs_pg()
    return _list_runs_files()


def _list_runs_pg() -> list[dict[str, Any]]:
    """List runs from PG. Counts come from GROUP BY; high-value from the FK."""
    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        runs = conn.execute(
            """
            SELECT run_id, started_at, total_hosts, total_credentials,
                   (log IS NOT NULL AND log <> '') AS has_log
            FROM runs ORDER BY run_id DESC
            """
        ).fetchall()
        # Per-run valid/suspicious counts in one pass.
        kind_counts = conn.execute(
            "SELECT run_id, kind, COUNT(*) AS n FROM results GROUP BY run_id, kind"
        ).fetchall()
        hv_counts = conn.execute(
            "SELECT run_id, COUNT(*) AS n FROM high_value_keys WHERE run_id IS NOT NULL GROUP BY run_id"
        ).fetchall()
        # Distinct discovery backends per run, matching the file version's
        # _sources_of (a credential's `backend` may be "fofa,shodan", so split).
        src_rows = conn.execute(
            """
            SELECT DISTINCT run_id,
                   TRIM(part) AS backend
            FROM results,
                 LATERAL regexp_split_to_table(record->'credential'->>'backend', ',') AS part
            WHERE kind = 'valid' AND TRIM(part) <> ''
            """
        ).fetchall()

    valid_by: dict[str, int] = {}
    susp_by: dict[str, int] = {}
    for r in kind_counts:
        if r["kind"] == "valid":
            valid_by[r["run_id"]] = r["n"]
        elif r["kind"] == "suspicious":
            susp_by[r["run_id"]] = r["n"]
    hv_by = {r["run_id"]: r["n"] for r in hv_counts}
    src_by: dict[str, set[str]] = {}
    for r in src_rows:
        src_by.setdefault(r["run_id"], set()).add(r["backend"])

    by_day: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        rid = run["run_id"]
        started = run["started_at"]
        entry = {
            "run_id": rid,
            "started_at": started.isoformat() if started else _run_id_to_iso(rid),
            "valid_count": valid_by.get(rid, 0),
            "suspicious_count": susp_by.get(rid, 0),
            "has_log": bool(run["has_log"]),
            "raw_hits": run["total_hosts"] or 0,
            "unique_targets": run["total_hosts"] or 0,
            "candidates": run.get("total_credentials", 0) or 0,
            "active_requests": run.get("total_credentials", 0) or 0,
            "final_verified": valid_by.get(rid, 0),
            "suspicious": susp_by.get(rid, 0),
            "sources": sorted(src_by.get(rid, set())),
            "high_value_final": hv_by.get(rid, 0),
        }
        by_day.setdefault(_day_from_run_id(rid), []).append(entry)
    return [{"day": day, "runs": entries} for day, entries in by_day.items()]


def _list_runs_files() -> list[dict[str, Any]]:
    """Original file-based run listing (used when PG is disabled)."""
    global _runs_cache

    root = settings.results_path
    if not root.is_dir():
        return []

    runs = sorted(
        (p for p in root.glob("run_*") if p.is_dir() and _RUN_ID_RE.match(p.name)),
        key=lambda p: p.name,
        reverse=True,
    )

    signature = _runs_signature(root, runs)
    cache = _runs_cache  # snapshot for a consistent read under thread offload
    if cache is not None and cache[0] == signature:
        return cache[1]

    started = [_run_id_to_iso(r.name) for r in runs]
    hv_counts = _high_value_by_window(started)

    by_day: dict[str, list[dict[str, Any]]] = {}
    for run, run_started in zip(runs, started, strict=True):
        valid_files = list(run.glob("valid_*.jsonl"))
        susp_files = list(run.glob("suspicious_*.jsonl"))
        metadata = _scan_metadata(run)
        candidates = int(metadata.get("total_credentials", 0))
        entry = {
            "run_id": run.name,
            "started_at": run_started,
            "valid_count": sum(_count_lines(f) for f in valid_files),
            "suspicious_count": sum(_count_lines(f) for f in susp_files),
            "has_log": (run / "run.log").exists(),
            "raw_hits": int(metadata.get("raw_hits", 0)),
            "unique_targets": int(metadata.get("unique_targets", metadata.get("total_hosts", 0))),
            "candidates": candidates,
            "active_requests": int(metadata.get("active_requests", candidates)),
            "final_verified": sum(_count_lines(f) for f in valid_files),
            "suspicious": sum(_count_lines(f) for f in susp_files),
            "sources": _sources_of(valid_files),
            "high_value_final": hv_counts.get(run_started, 0),
        }
        by_day.setdefault(_day_from_run_id(run.name), []).append(entry)

    result = [{"day": day, "runs": entries} for day, entries in by_day.items()]
    _runs_cache = (signature, result)
    return result


def _run_id_to_iso(run_id: str) -> str:
    m = re.match(r"^run_(\d{4})_(\d{2})_(\d{2})_(\d{2})-(\d{2})-(\d{2})$", run_id)
    if not m:
        return ""
    try:
        dt = datetime(*(int(g) for g in m.groups()))  # type: ignore[arg-type]
        return dt.isoformat()
    except ValueError:
        return ""


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def _load_kind(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Load raw (unmasked) records for a run's ``valid`` or ``suspicious`` list.

    Reads PG (ordered by seq) when the run exists there; otherwise falls back to
    the ``valid_*.jsonl`` / ``suspicious_*.jsonl`` files. Both preserve the same
    ordering, so the ``index``/``indices`` (== seq) reveal/export contract holds.
    """
    _validate_run_id(run_id)
    if _pg_has_run(run_id):
        return _pg_load_kind(run_id, kind)
    d = _run_dir(run_id)
    glob = "valid_*.jsonl" if kind == "valid" else "suspicious_*.jsonl"
    records: list[dict[str, Any]] = []
    for f in sorted(d.glob(glob)):
        records.extend(_read_jsonl(f))
    return records


def _mask_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with the credential apikey masked."""
    out = dict(rec)
    cred = rec.get("credential")
    if isinstance(cred, dict) and cred.get("apikey"):
        masked_cred = dict(cred)
        masked_cred["apikey"] = mask_apikey(cred["apikey"])
        out["credential"] = masked_cred
    return out


def load_run_records(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Masked records for a run's valid/suspicious list (safe to return to client)."""
    return [_mask_record(r) for r in _load_kind(run_id, kind)]


def load_run_records_plain(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Unmasked records — used only by export/reveal, never by list endpoints."""
    return _load_kind(run_id, kind)


def read_run_log(run_id: str) -> str:
    """Return a run's full log text.

    Prefers PG (``runs.log``), but a run still in flight — or one interrupted
    before persist — has no log column yet, so we fall back to the live
    ``<run_dir>/run.log`` file the FileHandler is writing. That fallback is also
    what serves the SSE-adjacent "view current log" while a scan is running.
    """
    _validate_run_id(run_id)

    if _pg_has_run(run_id):
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT log FROM runs WHERE run_id = %s", (run_id,)
            ).fetchone()
        if row is not None and row["log"]:
            return row["log"]
        # Run row exists but log not persisted yet (still running / interrupted):
        # fall through to the on-disk file.

    log_path = settings.results_path / run_id / "run.log"
    if not log_path.exists():
        raise ApiError(f"no log for run {run_id}", status_code=404, code="not_found")
    try:
        return log_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ApiError(f"failed reading log: {e}", status_code=500, code="internal_error") from e


def reveal_apikey(
    run_id: str,
    kind: str = "valid",
    *,
    masked: str | None = None,
    apiurl: str | None = None,
    index: int | None = None,
) -> dict[str, str]:
    """Re-read the run file to recover ONE plaintext apikey.

    Matching precedence:
    1. ``index`` (0-based line index into the file), if provided;
    2. else ``masked`` (+ optional ``apiurl`` to disambiguate) matched against the
       server-side re-masking of each key.

    Returns ``{"apikey": <plaintext>, "apiurl": ...}``.
    """
    records = _load_kind(run_id, kind)

    if index is not None:
        if index < 0 or index >= len(records):
            raise ApiError("index out of range", status_code=404, code="not_found")
        cred = records[index].get("credential") or {}
        return {"apikey": str(cred.get("apikey", "")), "apiurl": str(cred.get("apiurl", ""))}

    if not masked:
        raise ApiError("provide index or masked", status_code=400, code="bad_request")

    for rec in records:
        cred = rec.get("credential") or {}
        apikey = str(cred.get("apikey", ""))
        if not apikey:
            continue
        if mask_apikey(apikey) != masked:
            continue
        if apiurl is not None and str(cred.get("apiurl", "")) != apiurl:
            continue
        return {"apikey": apikey, "apiurl": str(cred.get("apiurl", ""))}

    raise ApiError("key not found in run", status_code=404, code="not_found")
