"""GitHub query shard model and lane builders.

Three lanes (do not mix qualifiers across them):

* ``commit_message`` — ``/search/commits``; never uses path/filename/extension/language
* ``code_snapshot`` — ``/search/code``; qualifier groups from the pack only
* ``seeded_file_history`` — ``/repos/.../commits?path=`` (core resource)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

from aipocket.core.request_ledger import RateResource

LaneName = Literal["commit_message", "code_snapshot", "seeded_file_history"]

# Forbidden on commit_message lane (GitHub does not filter patch content with these).
_COMMIT_FORBIDDEN_QUALIFIERS = re.compile(
    r"\b(path|filename|extension|language)\s*:",
    re.I,
)


class PackLike(Protocol):
    """Minimal pack surface required by query builders (full packs land in WS-D)."""

    pack_id: str
    commit_message_anchors: tuple[str, ...]
    code_content_anchors: tuple[str, ...]
    code_qualifier_groups: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class GitHubPackView:
    """Concrete pack view used by WS-C until discovery.packs ships."""

    pack_id: str
    commit_message_anchors: tuple[str, ...] = ()
    code_content_anchors: tuple[str, ...] = ()
    code_qualifier_groups: tuple[tuple[str, ...], ...] = ()
    path_hints: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    variable_names: tuple[str, ...] = ()
    official_domains: tuple[str, ...] = ()
    default_endpoint: str = ""
    seeded_history_policy: str = "enabled"


@dataclass(frozen=True, slots=True)
class GitHubQueryShard:
    lane: LaneName
    pack_id: str
    query_id: str
    anchor: str
    qualifiers: tuple[str, ...]
    window_start: datetime | None
    window_end: datetime | None
    rate_resource: RateResource
    page_budget: int
    shard_id: str
    coverage_mode: str  # complete|truncated|seeded_only
    # Extra locator fields for seeded history.
    owner: str = ""
    repo: str = ""
    file_path: str = ""
    repo_id: str = ""
    seed_origin: str = ""

    def build_q(self) -> str:
        """Render the GitHub search ``q`` parameter (or empty for history lane)."""
        if self.lane == "seeded_file_history":
            return ""
        parts: list[str] = []
        if self.anchor:
            # Quote multi-word anchors for phrase search.
            if " " in self.anchor and not (
                self.anchor.startswith('"') and self.anchor.endswith('"')
            ):
                parts.append(f'"{self.anchor}"')
            else:
                parts.append(self.anchor)
        parts.extend(self.qualifiers)
        if self.lane == "commit_message" and not any(
            qualifier.strip().lower() in {"is:public", "is:private"}
            for qualifier in self.qualifiers
        ):
            parts.append("is:public")
        if self.lane == "commit_message" and self.window_start and self.window_end:
            start = _fmt_date(self.window_start)
            end = _fmt_date(self.window_end)
            parts.append(f"committer-date:{start}..{end}")
        return " ".join(p for p in parts if p)

    def assert_lane_invariants(self) -> None:
        if self.lane == "commit_message":
            q = self.build_q()
            if _COMMIT_FORBIDDEN_QUALIFIERS.search(q):
                raise ValueError(
                    f"commit_message shard must not contain path/filename/extension/language: {self.query_id}"
                )
            for qual in self.qualifiers:
                if _COMMIT_FORBIDDEN_QUALIFIERS.search(qual):
                    raise ValueError(
                        f"forbidden qualifier on commit_message: {qual!r} (query_id={self.query_id})"
                    )
            if "is:private" in q.lower():
                raise ValueError(f"commit_message shard must be public-only: {self.query_id}")


def build_commit_message_shards(
    pack: PackLike,
    *,
    window_start: datetime,
    window_end: datetime,
    page_budget: int = 5,
    extra_qualifiers: tuple[str, ...] = (),
) -> list[GitHubQueryShard]:
    """Build commit-message search shards from pack anchors.

    Case-insensitive search → collapse case-only duplicates.
    Never attaches path/filename/extension/language qualifiers.
    """
    seen_norm: set[str] = set()
    shards: list[GitHubQueryShard] = []
    for raw in pack.commit_message_anchors:
        anchor = (raw or "").strip()
        if not anchor:
            continue
        norm = anchor.casefold()
        if norm in seen_norm:
            continue
        seen_norm.add(norm)
        # Strip any forbidden qualifiers that slipped into anchors.
        if _COMMIT_FORBIDDEN_QUALIFIERS.search(anchor):
            continue
        safe_quals = tuple(
            q for q in extra_qualifiers if not _COMMIT_FORBIDDEN_QUALIFIERS.search(q)
        )
        query_id = _stable_id("cm", pack.pack_id, anchor, safe_quals)
        shard_id = _stable_id(
            "cmshard",
            pack.pack_id,
            anchor,
            _fmt_date(window_start),
            _fmt_date(window_end),
        )
        shard = GitHubQueryShard(
            lane="commit_message",
            pack_id=pack.pack_id,
            query_id=query_id,
            anchor=anchor,
            qualifiers=safe_quals,
            window_start=window_start,
            window_end=window_end,
            rate_resource="search",
            page_budget=page_budget,
            shard_id=shard_id,
            coverage_mode="complete",
        )
        shard.assert_lane_invariants()
        shards.append(shard)
    return shards


def build_code_snapshot_shards(
    pack: PackLike,
    *,
    page_budget: int = 5,
) -> list[GitHubQueryShard]:
    """Build code-search shards: each (anchor × qualifier group)."""
    groups = pack.code_qualifier_groups or ((),)
    shards: list[GitHubQueryShard] = []
    seen: set[str] = set()
    for raw in pack.code_content_anchors:
        anchor = (raw or "").strip()
        if not anchor:
            continue
        for group in groups:
            quals = tuple(q for q in group if q)
            key = f"{anchor.casefold()}|{'|'.join(quals)}"
            if key in seen:
                continue
            seen.add(key)
            query_id = _stable_id("cs", pack.pack_id, anchor, quals)
            shard_id = _stable_id("csshard", pack.pack_id, anchor, quals)
            shards.append(
                GitHubQueryShard(
                    lane="code_snapshot",
                    pack_id=pack.pack_id,
                    query_id=query_id,
                    anchor=anchor,
                    qualifiers=quals,
                    window_start=None,
                    window_end=None,
                    rate_resource="code_search",
                    page_budget=page_budget,
                    shard_id=shard_id,
                    coverage_mode="complete",
                )
            )
    return shards


def build_seeded_file_history_shards(
    pack: PackLike,
    seeds: list[dict[str, Any]],
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    page_budget: int = 5,
) -> list[GitHubQueryShard]:
    """Build core-resource history shards from (repo, path) seeds.

    Each seed dict expects: owner, repo, path, optional repo_id, seed_origin.
    """
    shards: list[GitHubQueryShard] = []
    seen: set[str] = set()
    for seed in seeds:
        owner = str(seed.get("owner") or "")
        repo = str(seed.get("repo") or "")
        if seed.get("public") is not True:
            continue
        path = str(seed.get("path") or seed.get("file_path") or "")
        if not owner or not repo or not path:
            continue
        key = f"{owner}/{repo}:{path}".casefold()
        if key in seen:
            continue
        seen.add(key)
        repo_id = str(seed.get("repo_id") or "")
        origin = str(seed.get("seed_origin") or "code_snapshot")
        query_id = _stable_id("sfh", pack.pack_id, owner, repo, path)
        shard_id = _stable_id("sfhshard", pack.pack_id, owner, repo, path)
        shards.append(
            GitHubQueryShard(
                lane="seeded_file_history",
                pack_id=pack.pack_id,
                query_id=query_id,
                anchor=path,
                qualifiers=(),
                window_start=window_start,
                window_end=window_end,
                rate_resource="core",
                page_budget=page_budget,
                shard_id=shard_id,
                coverage_mode="seeded_only",
                owner=owner,
                repo=repo,
                file_path=path,
                repo_id=repo_id,
                seed_origin=origin,
            )
        )
    return shards


def bisect_date_window(shard: GitHubQueryShard) -> list[GitHubQueryShard]:
    """Split a commit_message shard's date window in half for 1000-cap recovery.

    Returns two child shards, or a single truncated shard when the window is
    already a single calendar day (cannot bisect further without watchlist).
    """
    if shard.lane != "commit_message" or not shard.window_start or not shard.window_end:
        return [shard]
    start = shard.window_start
    end = shard.window_end
    if end <= start:
        return [
            GitHubQueryShard(
                lane=shard.lane,
                pack_id=shard.pack_id,
                query_id=shard.query_id,
                anchor=shard.anchor,
                qualifiers=shard.qualifiers,
                window_start=start,
                window_end=end,
                rate_resource=shard.rate_resource,
                page_budget=shard.page_budget,
                shard_id=shard.shard_id + ":trunc",
                coverage_mode="truncated",
                owner=shard.owner,
                repo=shard.repo,
                file_path=shard.file_path,
                repo_id=shard.repo_id,
                seed_origin=shard.seed_origin,
            )
        ]
    # Single calendar day → mark truncated (no further bisect without watchlist).
    if start.date() == end.date() or (end - start) <= timedelta(hours=24):
        return [
            GitHubQueryShard(
                lane=shard.lane,
                pack_id=shard.pack_id,
                query_id=shard.query_id,
                anchor=shard.anchor,
                qualifiers=shard.qualifiers,
                window_start=start,
                window_end=end,
                rate_resource=shard.rate_resource,
                page_budget=shard.page_budget,
                shard_id=shard.shard_id + ":daycap",
                coverage_mode="truncated",
                owner=shard.owner,
                repo=shard.repo,
                file_path=shard.file_path,
                repo_id=shard.repo_id,
                seed_origin=shard.seed_origin,
            )
        ]
    mid = start + (end - start) / 2
    children: list[GitHubQueryShard] = []
    for idx, (ws, we) in enumerate(((start, mid), (mid, end))):
        children.append(
            GitHubQueryShard(
                lane=shard.lane,
                pack_id=shard.pack_id,
                query_id=shard.query_id,
                anchor=shard.anchor,
                qualifiers=shard.qualifiers,
                window_start=ws,
                window_end=we,
                rate_resource=shard.rate_resource,
                page_budget=shard.page_budget,
                shard_id=f"{shard.shard_id}:b{idx}",
                coverage_mode=shard.coverage_mode,
                owner=shard.owner,
                repo=shard.repo,
                file_path=shard.file_path,
                repo_id=shard.repo_id,
                seed_origin=shard.seed_origin,
            )
        )
    return children


def default_window(
    *,
    lookback_hours: int = 24,
    overlap_minutes: int = 15,
    watermark: str = "",
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Compute [start, end) window from watermark + overlap or lookback."""
    end = now or datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    if watermark:
        try:
            start = datetime.fromisoformat(watermark.replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            start = start - timedelta(minutes=max(0, overlap_minutes))
        except ValueError:
            start = end - timedelta(hours=max(1, lookback_hours))
    else:
        start = end - timedelta(hours=max(1, lookback_hours))
    return start, end


def _fmt_date(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%d")


def _stable_id(*parts: Any) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
