"""Discovery source contracts — host hits and credential observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from aipocket.core.credentials import CredentialBundle
from aipocket.core.metrics import QueryUsage
from aipocket.core.models import Credential, ScanMode
from aipocket.core.scan_policy import ScanPolicy


@dataclass(frozen=True, slots=True)
class ArtifactProvenance:
    """GitHub-specific structured evidence without plaintext secrets."""

    repository_id: str = ""
    repository_full_name: str = ""
    commit_sha: str = ""
    object_sha: str = ""
    file_path: str = ""
    source_kind: str = ""  # commit_message|patch|blob
    change_side: str = ""  # added|removed|context|message
    line_start: int | None = None
    line_end: int | None = None
    query_id: str = ""
    pack_id: str = ""
    lane: str = ""


@dataclass(frozen=True, slots=True)
class CredentialSourceObservation:
    bundle: CredentialBundle
    credential: Credential
    provenance: ArtifactProvenance
    query_id: str
    pack_id: str
    lane: str
    coverage_mode: str  # complete|truncated|seeded_only
    coverage_gap: str = ""


@dataclass(frozen=True, slots=True)
class CheckpointUpdate:
    source: str
    lane: str
    pack_id: str
    shard_id: str
    watermark: str
    cursor_state: dict[str, Any]
    etag: str = ""
    status: str = "ok"  # ok|truncated|error


@dataclass(frozen=True, slots=True)
class SourceFetchResult:
    source: str
    host_hits: tuple[dict[str, Any], ...] = ()
    credential_observations: tuple[CredentialSourceObservation, ...] = ()
    query_usage: tuple[QueryUsage, ...] = ()
    checkpoint_updates: tuple[CheckpointUpdate, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceBudgets:
    fofa: int | None = None
    shodan: int | None = None
    github_commit: int | None = None
    github_code: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class DiscoverySource(Protocol):
    name: str

    def is_configured(self) -> bool: ...

    async def fetch(
        self,
        *,
        budgets: SourceBudgets,
        mode: ScanMode,
        policy: ScanPolicy | None = None,
        skip_direct: bool = False,
        **kwargs: Any,
    ) -> SourceFetchResult: ...
