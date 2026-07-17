"""GitHub artifact fetch layer — message → patch → paginate → blob fallback.

Fetch priority:
1. Search item commit message
2. Commit detail ``files[].patch``
3. Paginate large commits (≤ ``GITHUB_MAX_COMMIT_FILES``)
4. Missing/binary/truncated patch → blob only if path/extension matches pack hints
5. Oversized blob / budget exhaust → explicit status (not silent skip)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Protocol

from aipocket.clients.github import (
    CommitDetail,
    CommitFile,
    GitHubClient,
    GitHubSourceGone,
)
from aipocket.core.config import Settings
from aipocket.core.config import settings as default_settings
from aipocket.core.credentials import CredentialBundle, CredentialEvidence
from aipocket.core.key_patterns import KEY_PATTERNS, is_noise
from aipocket.services.config_extractor import extract_config_bundles
from aipocket.services.github_patch import join_side, line_span, parse_unified_patch
from aipocket.services.github_work_queue import ArtifactWorkItem

log = logging.getLogger(__name__)


class PackHints(Protocol):
    path_hints: tuple[str, ...]
    extensions: tuple[str, ...]
    default_endpoint: str
    pack_id: str


@dataclass(frozen=True, slots=True)
class ExtractedArtifactSecret:
    bundle: CredentialBundle
    source_kind: str  # commit_message|patch|blob
    change_side: str  # added|removed|context|message
    file_path: str = ""
    object_sha: str = ""
    line_start: int | None = None
    line_end: int | None = None


@dataclass(slots=True)
class ArtifactFetchResult:
    work: ArtifactWorkItem
    message: str = ""
    files: list[CommitFile] = field(default_factory=list)
    secrets: list[ExtractedArtifactSecret] = field(default_factory=list)
    status: str = "ok"  # ok|source_gone|transient|artifact_too_large|budget_exhausted
    error_class: str = ""
    files_truncated: bool = False
    blobs_fetched: int = 0


@dataclass(slots=True)
class BlobBudget:
    remaining: int

    def consume(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


async def fetch_and_extract(
    client: GitHubClient,
    work: ArtifactWorkItem,
    *,
    message_hint: str = "",
    pack: PackHints | None = None,
    blob_budget: BlobBudget | None = None,
    settings: Settings | None = None,
) -> ArtifactFetchResult:
    """Fetch artifact content for *work* and extract credential candidates.

    Never persists raw patch/blob; returns in-memory secrets only.
    """
    cfg = settings or default_settings
    owner, repo = _split_full_name(work.repository_full_name)
    if not owner or not repo:
        return ArtifactFetchResult(
            work=work,
            status="source_gone",
            error_class="bad_repository_name",
        )

    result = ArtifactFetchResult(work=work, message=message_hint or "")

    # 1. Commit message from search item (when present).
    if message_hint:
        result.secrets.extend(
            _extract_from_text(
                message_hint,
                source_kind="commit_message",
                change_side="message",
                work=work,
                pack=pack,
            )
        )

    # 2–3. Commit detail + file patches (paginate up to max files).
    try:
        detail, all_files = await _fetch_commit_files(
            client, owner, repo, work.commit_sha, max_files=cfg.github_max_commit_files
        )
    except GitHubSourceGone:
        result.status = "source_gone"
        result.error_class = "source_gone"
        return result
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "commit fetch failed %s@%s: %s",
            work.repository_full_name,
            work.commit_sha[:8],
            type(exc).__name__,
        )
        result.status = "transient"
        result.error_class = type(exc).__name__
        return result

    if detail.not_modified:
        result.status = "ok"
        return result

    if not result.message and detail.message:
        result.message = detail.message
        result.secrets.extend(
            _extract_from_text(
                detail.message,
                source_kind="commit_message",
                change_side="message",
                work=work,
                pack=pack,
            )
        )

    result.files = all_files
    result.files_truncated = detail.files_truncated or len(all_files) >= cfg.github_max_commit_files

    # Filter to a specific path when the work row is path-scoped.
    files_to_scan = all_files
    if work.file_path:
        files_to_scan = [f for f in all_files if f.filename == work.file_path] or all_files

    budget = blob_budget or BlobBudget(remaining=cfg.github_blob_fallback_budget)

    for cf in files_to_scan:
        if cf.patch:
            result.secrets.extend(_extract_from_patch(cf, work=work, pack=pack))
            continue

        # 4. Patch missing/binary → blob fallback if path matches hints.
        if not _path_matches_hints(cf.filename, pack):
            continue
        if not budget.consume():
            result.status = "budget_exhausted"
            result.error_class = "blob_fallback_budget"
            break
        try:
            blob = await client.get_blob(
                owner, repo, cf.sha or work.object_sha, max_bytes=cfg.github_max_blob_bytes
            )
        except GitHubSourceGone:
            continue
        except Exception:  # noqa: BLE001
            result.error_class = result.error_class or "blob_fetch_error"
            continue

        result.blobs_fetched += 1
        if blob.not_modified:
            continue
        if blob.truncated or blob.size > cfg.github_max_blob_bytes:
            result.status = "artifact_too_large"
            result.error_class = "artifact_too_large"
            continue
        if not blob.content:
            continue
        result.secrets.extend(
            _extract_from_text(
                blob.content,
                source_kind="blob",
                change_side="context",
                work=work,
                pack=pack,
                file_path=cf.filename,
                object_sha=blob.sha or cf.sha,
                format_hint=_ext_of(cf.filename),
            )
        )

    return result


async def _fetch_commit_files(
    client: GitHubClient,
    owner: str,
    repo: str,
    sha: str,
    *,
    max_files: int,
) -> tuple[CommitDetail, list[CommitFile]]:
    page = 1
    per_page = 100
    all_files: list[CommitFile] = []
    first: CommitDetail | None = None
    while len(all_files) < max_files:
        detail = await client.get_commit(owner, repo, sha, page=page, per_page=per_page)
        if first is None:
            first = detail
        if detail.not_modified:
            return detail, all_files
        batch = list(detail.files)
        all_files.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
        if page > (max_files // per_page) + 1:
            break
    assert first is not None
    truncated = len(all_files) >= max_files
    # Rebuild detail with combined files list metadata.
    combined = CommitDetail(
        sha=first.sha,
        message=first.message,
        html_url=first.html_url,
        files=tuple(all_files[:max_files]),
        owner=first.owner,
        repo=first.repo,
        repository_id=first.repository_id,
        repository_full_name=first.repository_full_name,
        etag=first.etag,
        files_truncated=truncated or first.files_truncated,
    )
    return combined, list(combined.files)


def _extract_from_patch(
    cf: CommitFile,
    *,
    work: ArtifactWorkItem,
    pack: PackHints | None,
) -> list[ExtractedArtifactSecret]:
    assert cf.patch is not None
    lines = parse_unified_patch(cf.patch)
    out: list[ExtractedArtifactSecret] = []

    # Prefer added lines; keep removed as lower-risk candidates.
    for side in ("added", "removed", "context"):
        text = join_side(lines, side)  # type: ignore[arg-type]
        if not text.strip():
            continue
        start, end = line_span(lines, side)  # type: ignore[arg-type]
        out.extend(
            _extract_from_text(
                text,
                source_kind="patch",
                change_side=side,
                work=work,
                pack=pack,
                file_path=cf.filename,
                object_sha=cf.sha,
                line_start=start,
                line_end=end,
                format_hint=_ext_of(cf.filename),
            )
        )
    return out


def _extract_from_text(
    text: str,
    *,
    source_kind: str,
    change_side: str,
    work: ArtifactWorkItem,
    pack: PackHints | None,
    file_path: str = "",
    object_sha: str = "",
    line_start: int | None = None,
    line_end: int | None = None,
    format_hint: str = "",
) -> list[ExtractedArtifactSecret]:
    results: list[ExtractedArtifactSecret] = []
    seen_fp: set[str] = set()

    evidence_base = dict(
        source="github",
        path=file_path or work.file_path,
        query_id=work.query_id,
        pack_id=work.pack_id or (pack.pack_id if pack else ""),
        repository_id=work.repo_id,
        repository_full_name=work.repository_full_name,
        commit_sha=work.commit_sha,
        object_sha=object_sha or work.object_sha,
        source_kind=source_kind,
        change_side=change_side,
        line_start=line_start,
        line_end=line_end,
    )

    # Structured config first when format looks like config.
    if format_hint or _looks_like_config(text, file_path or work.file_path):
        try:
            bundles = extract_config_bundles(text, format_hint=format_hint)
        except Exception:  # noqa: BLE001
            bundles = []
        for b in bundles:
            if b.secret_fingerprint in seen_fp:
                continue
            seen_fp.add(b.secret_fingerprint)
            ev = CredentialEvidence(**evidence_base)
            enriched = CredentialBundle.create(
                b.secret_value.reveal(),
                credential_kind=b.credential_kind,
                endpoint_candidates=b.endpoint_candidates
                or ((pack.default_endpoint,) if pack and pack.default_endpoint else ()),
                provider_hint=b.provider_hint,
                context=b.context,
                evidence=(ev,),
                confidence=b.confidence,
            )
            results.append(
                ExtractedArtifactSecret(
                    bundle=enriched,
                    source_kind=source_kind,
                    change_side=change_side,
                    file_path=file_path or work.file_path,
                    object_sha=object_sha or work.object_sha,
                    line_start=line_start,
                    line_end=line_end,
                )
            )

    # Regex patterns for free-form message / patch lines.
    for _label, pattern in KEY_PATTERNS:
        for m in pattern.finditer(text):
            secret = m.group(1) if m.lastindex else m.group(0)
            if not secret or is_noise(secret):
                continue
            # Build temp fingerprint via create.
            default_ep = (pack.default_endpoint,) if pack and pack.default_endpoint else ()
            tmp = CredentialBundle.create(
                secret,
                endpoint_candidates=default_ep,
                provider_hint=_label if _label not in ("sk_key", "generic") else "unknown",
                evidence=(CredentialEvidence(**evidence_base),),
            )
            if tmp.secret_fingerprint in seen_fp:
                continue
            seen_fp.add(tmp.secret_fingerprint)
            results.append(
                ExtractedArtifactSecret(
                    bundle=tmp,
                    source_kind=source_kind,
                    change_side=change_side,
                    file_path=file_path or work.file_path,
                    object_sha=object_sha or work.object_sha,
                    line_start=line_start,
                    line_end=line_end,
                )
            )
    return results


def _path_matches_hints(path: str, pack: PackHints | None) -> bool:
    if pack is None:
        # Without pack hints, still allow common config filenames.
        base = os.path.basename(path).lower()
        return base.startswith(".env") or base.endswith(
            (".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf")
        )
    lower = path.lower()
    for hint in pack.path_hints:
        if hint and hint.lower() in lower:
            return True
    ext = _ext_of(path)
    for e in pack.extensions:
        if e and ext == e.lower().lstrip("."):
            return True
    base = os.path.basename(path).lower()
    return bool(base.startswith(".env") or base == "env")


def _looks_like_config(text: str, path: str) -> bool:
    if path and _ext_of(path) in {"env", "yml", "yaml", "json", "toml", "ini"}:
        return True
    return bool("=" in text and any(k in text.upper() for k in ("KEY", "TOKEN", "SECRET", "API")))


def _ext_of(path: str) -> str:
    base = os.path.basename(path)
    if base.startswith(".env"):
        return "env"
    _, ext = os.path.splitext(base)
    return ext.lstrip(".").lower()


def _split_full_name(full_name: str) -> tuple[str, str]:
    parts = (full_name or "").strip().split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", ""
