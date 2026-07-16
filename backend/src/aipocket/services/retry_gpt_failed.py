"""Retry GPT-failed batches for an existing run and **append** recovered results.

Input (disk only):
  Failed GPT batches are dumped by :mod:`aipocket.services.analyzer` as
  ``gpt_failed_batch_*.jsonl`` inside the run directory — these are *retry
  inputs*, not the results store.

Output (PostgreSQL is source of truth):
  Recovered valid/suspicious credentials are **appended** into the ``results``
  table via :func:`append_results_pg` (INSERT with next ``seq``; never DELETE
  existing rows). JSONL dual-write is optional and only runs when
  ``settings.write_jsonl`` is True.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult
from aipocket.services.analyzer import extract_with_gpt, set_run_dir
from aipocket.services.extractor import extract_credentials
from aipocket.services.validator import validate_all
from aipocket.services.writer import append_results_jsonl, append_results_pg

log = logging.getLogger(__name__)

_RUN_ID_RE = re.compile(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")
_FAILED_GLOB = "gpt_failed_batch_*.jsonl"


@dataclass(frozen=True, slots=True)
class FailedBatchFile:
    name: str
    hits: int
    batch_idx: int | None = None


@dataclass(frozen=True, slots=True)
class GptFailedSummary:
    run_id: str
    failed_files: list[FailedBatchFile]
    failed_hits: int

    @property
    def has_failures(self) -> bool:
        return self.failed_hits > 0


@dataclass(slots=True)
class RetryGptFailedReport:
    run_id: str
    failed_files: int = 0
    failed_hits: int = 0
    credentials_found: int = 0
    valid_appended: int = 0
    suspicious_appended: int = 0
    high_value_final: int = 0
    archived_files: list[str] = field(default_factory=list)
    jsonl_paths: list[str] = field(default_factory=list)
    message: str = ""


def _run_dir(run_id: str) -> Path:
    if not _RUN_ID_RE.match(run_id):
        raise ValueError(f"invalid run id: {run_id}")
    d = settings.results_path / run_id
    if not d.is_dir():
        raise FileNotFoundError(f"run directory not found: {run_id}")
    return d


def _failed_batch_paths(run_dir: Path) -> list[Path]:
    """Active failed-batch files only (exclude ``*.done`` / backups)."""
    return sorted(
        p
        for p in run_dir.glob(_FAILED_GLOB)
        if p.is_file() and not p.name.endswith(".done") and ".bak" not in p.name
    )


def _parse_failed_file(path: Path) -> tuple[list[dict[str, Any]], int | None]:
    """Return (hits, batch_idx). First line is metadata; remaining lines are hits."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return [], None
    batch_idx: int | None = None
    try:
        meta = json.loads(lines[0])
        if isinstance(meta, dict) and "batch_idx" in meta:
            batch_idx = int(meta["batch_idx"]) if meta["batch_idx"] is not None else None
            hits = [json.loads(line) for line in lines[1:] if line.strip()]
            return hits, batch_idx
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    # No meta line — treat every non-empty line as a hit.
    hits = []
    for line in lines:
        if not line.strip():
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return hits, batch_idx


def inspect_gpt_failed(run_id: str) -> GptFailedSummary:
    """Scan a run directory for pending ``gpt_failed_batch_*.jsonl`` files."""
    run_dir = _run_dir(run_id)
    files: list[FailedBatchFile] = []
    total = 0
    for path in _failed_batch_paths(run_dir):
        hits, batch_idx = _parse_failed_file(path)
        files.append(FailedBatchFile(name=path.name, hits=len(hits), batch_idx=batch_idx))
        total += len(hits)
    return GptFailedSummary(run_id=run_id, failed_files=files, failed_hits=total)


def _credential_identity(c: Credential) -> tuple[str, str]:
    if c.bundle is not None:
        return c.bundle.secret_fingerprint, c.apiurl
    return c.apikey, c.apiurl


def _result_identity(r: ValidationResult) -> tuple[str, str]:
    return _credential_identity(r.credential)


def _load_existing_identities(run_id: str) -> set[tuple[str, str]]:
    """Existing (apikey, apiurl) pairs already stored for this run (valid+suspicious)."""
    from aipocket.api.results_reader import load_run_records_plain

    seen: set[tuple[str, str]] = set()
    for kind in ("valid", "suspicious"):
        try:
            records = load_run_records_plain(run_id, kind)
        except Exception:  # noqa: BLE001 — run may lack one kind
            continue
        for rec in records:
            cred = rec.get("credential") if isinstance(rec.get("credential"), dict) else {}
            apikey = str(cred.get("apikey") or "")
            apiurl = str(cred.get("apiurl") or "")
            if apikey:
                seen.add((apikey, apiurl))
    return seen


def _archive_failed_files(paths: list[Path]) -> list[str]:
    archived: list[str] = []
    for path in paths:
        dest = path.with_name(path.name + ".done")
        # Avoid clobbering a previous archive with the same name.
        if dest.exists():
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            dest = path.with_name(f"{path.name}.{ts}.done")
        path.rename(dest)
        archived.append(dest.name)
        log.info("Archived failed batch %s → %s", path.name, dest.name)
    return archived


async def retry_gpt_failed(run_id: str) -> RetryGptFailedReport:
    """Re-process GPT failed batches for *run_id* and append recovered results.

    Guarantees:
    - Existing ``valid_*`` / ``suspicious_*`` / PG result rows are never replaced
    - New results are deduped against already-stored keys for this run
    - Source failed-batch files are renamed to ``*.done`` after processing
    """
    run_dir = _run_dir(run_id)
    failed_paths = _failed_batch_paths(run_dir)
    if not failed_paths:
        return RetryGptFailedReport(
            run_id=run_id,
            message="No gpt_failed_batch_*.jsonl files found — nothing to retry.",
        )

    all_failed_hits: list[dict[str, Any]] = []
    for path in failed_paths:
        hits, batch_idx = _parse_failed_file(path)
        all_failed_hits.extend(hits)
        log.info(
            "Retry load %s: %d hits (batch_idx=%s)",
            path.name,
            len(hits),
            batch_idx,
        )

    report = RetryGptFailedReport(
        run_id=run_id,
        failed_files=len(failed_paths),
        failed_hits=len(all_failed_hits),
    )
    if not all_failed_hits:
        report.archived_files = _archive_failed_files(failed_paths)
        report.message = "Failed batch files were empty; archived."
        return report

    set_run_dir(run_dir)
    try:
        # 1. Regex extraction
        regex_creds = extract_credentials(all_failed_hits)
        log.info("Retry regex extraction: %d credentials", len(regex_creds))

        # 2. GPT extraction (may dump new failed batches into the same run dir)
        for index, hit in enumerate(all_failed_hits):
            hit.setdefault("_entry_id", f"retry-{index}")
        log.info("Retry GPT extraction on %d hits...", len(all_failed_hits))
        gpt_report = await extract_with_gpt(all_failed_hits)
        log.info("Retry GPT extraction: %d credentials", len(gpt_report.credentials))

        # 3. Merge + dedupe credentials
        all_creds: list[Credential] = list(regex_creds)
        seen = {_credential_identity(c) for c in all_creds}
        for c in gpt_report.credentials:
            identity = _credential_identity(c)
            if identity not in seen:
                all_creds.append(c)
                seen.add(identity)
        report.credentials_found = len(all_creds)

        if not all_creds:
            report.archived_files = _archive_failed_files(failed_paths)
            report.message = "No credentials recovered from failed batches."
            return report

        # 4. Validate
        log.info(
            "Retry validating %d credentials (concurrency=%d)...",
            len(all_creds),
            settings.validate_concurrency,
        )
        results = await validate_all(all_creds)

        # 5. Honeypot filter (mutates in place; splits suspicious later)
        from aipocket.services.honeypot import filter_honeypots

        filter_honeypots(results)

        valid = [r for r in results if r.valid and not r.suspicious]
        suspicious = [r for r in results if r.valid and r.suspicious]

        # 6. Drop keys already stored for this run BEFORE balance enrich
        #    (append-only; avoid re-querying balance for duplicates).
        existing = _load_existing_identities(run_id)
        new_valid = [r for r in valid if _result_identity(r) not in existing]
        new_suspicious = [r for r in suspicious if _result_identity(r) not in existing]
        valid_ids = {_result_identity(r) for r in new_valid}
        new_suspicious = [r for r in new_suspicious if _result_identity(r) not in valid_ids]

        report.valid_appended = len(new_valid)
        report.suspicious_appended = len(new_suspicious)

        if not new_valid and not new_suspicious:
            report.archived_files = _archive_failed_files(failed_paths)
            report.message = (
                f"Recovered {report.credentials_found} credential(s) but all were "
                "already stored or invalid after validation."
            )
            return report

        # 7. Balance enrich + high-value commit only for *new* valid keys
        if new_valid:
            from aipocket.services.balance import enrich_results
            from aipocket.services.dedup import get_dedup_store
            from aipocket.services.finalizer import commit_final_results

            dedup = get_dedup_store()
            await enrich_results(new_valid, dedup=dedup, use_cache=False)
            commit_report = await commit_final_results(new_valid, dedup=dedup)
            report.high_value_final = commit_report.high_value_final

        # 8. Persist recovered results — PostgreSQL is the source of truth.
        #    APPEND only: INSERT new rows with next seq; never DELETE/replace.
        #    JSONL is dual-write only (write_jsonl=true); production PG-only
        #    skips files entirely.
        if settings.pg_enabled:
            try:
                append_results_pg(run_id, new_valid, new_suspicious)
            except LookupError as e:
                # Run missing from PG while PG is configured — refuse silent
                # file-only write so the UI doesn't show stale DB state.
                raise RuntimeError(
                    f"run {run_id} not found in PostgreSQL; cannot append results"
                ) from e
            dest = "PostgreSQL results table"
        else:
            dest = "JSONL (PG disabled)"

        jsonl_paths: list[str] = []
        if settings.write_jsonl:
            path_v = append_results_jsonl(new_valid, run_dir, "valid")
            if path_v is not None:
                jsonl_paths.append(path_v.name)
            path_s = append_results_jsonl(new_suspicious, run_dir, "suspicious")
            if path_s is not None:
                jsonl_paths.append(path_s.name)
        report.jsonl_paths = jsonl_paths

        report.archived_files = _archive_failed_files(failed_paths)
        report.message = (
            f"Appended {report.valid_appended} valid + {report.suspicious_appended} "
            f"suspicious credential(s) to {dest}."
        )
        log.info(
            "Retry GPT failed done for %s: files=%d hits=%d creds=%d "
            "appended_valid=%d appended_suspicious=%d dest=%s dual_write_jsonl=%s",
            run_id,
            report.failed_files,
            report.failed_hits,
            report.credentials_found,
            report.valid_appended,
            report.suspicious_appended,
            dest,
            bool(jsonl_paths),
        )
        return report
    finally:
        set_run_dir(None)
