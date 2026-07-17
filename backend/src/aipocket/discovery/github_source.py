"""GitHub artifact discovery source — credential observations only.

Never constructs fake host hits / DiscoveryTargets. Requires
``GITHUB_HUNTER_ENABLED`` + tokens + PostgreSQL; fail-closed when
``source=github``, skip when ``source=all`` and not configured.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from aipocket.core.config import Settings
from aipocket.core.config import settings as default_settings
from aipocket.core.credentials import CredentialBundle
from aipocket.core.metrics import QueryUsage
from aipocket.core.models import Credential, ScanMode
from aipocket.core.request_ledger import (
    RequestAttribution,
    current_query_attribution,
    get_current_ledger,
)
from aipocket.core.scan_phase import report_phase
from aipocket.core.scan_policy import ScanPolicy
from aipocket.discovery.base import (
    ArtifactProvenance,
    CheckpointUpdate,
    CredentialSourceObservation,
    SourceBudgets,
    SourceFetchResult,
)
from aipocket.services.github_artifacts import BlobBudget, fetch_and_extract
from aipocket.services.github_checkpoint import (
    CheckpointRow,
    advance_checkpoint_with_work,
    load_checkpoint,
    watermark_now,
)
from aipocket.services.github_queries import (
    GitHubPackView,
    GitHubQueryShard,
    PackLike,
    bisect_date_window,
    build_code_snapshot_shards,
    build_commit_message_shards,
    build_seeded_file_history_shards,
    default_window,
)
from aipocket.services.github_work_queue import (
    ArtifactWorkItem,
    claim_pending,
    mark_extract_done,
    mark_source_gone,
    mark_terminal,
    mark_transient,
    reset_memory_store,  # noqa: F401 — re-export for tests
    transition,
    upsert_work_rows,
    work_from_search_item,
)

log = logging.getLogger(__name__)


class GitHubNotConfiguredError(RuntimeError):
    """Raised when source=github was requested but tokens/PG are missing."""


def _default_glm_pack() -> GitHubPackView:
    """Starter pack view until WS-D packs land (glm vertical slice anchors)."""
    return GitHubPackView(
        pack_id="glm",
        commit_message_anchors=(
            "glm api key",
            "zhipu",
            "bigmodel",
            "rotate glm",
            "remove leaked key",
        ),
        code_content_anchors=(
            "GLM_API_KEY",
            "ZHIPUAI_API_KEY",
            "BIGMODEL_API_KEY",
            "ZHIPU_API_KEY",
            "open.bigmodel.cn",
            "api.zhipuai.cn",
        ),
        code_qualifier_groups=(
            ("extension:env", "path:.env"),
            ("extension:yml", "path:config"),
            ("extension:json",),
            ("extension:toml",),
        ),
        path_hints=(".env", "config", "compose", "k8s", "kubernetes"),
        extensions=("env", "yml", "yaml", "json", "toml"),
        variable_names=("GLM_API_KEY", "ZHIPUAI_API_KEY", "BIGMODEL_API_KEY", "ZHIPU_API_KEY"),
        official_domains=("open.bigmodel.cn", "api.zhipuai.cn"),
        default_endpoint="https://open.bigmodel.cn/api/paas/v4",
        seeded_history_policy="enabled",
    )


def resolve_packs(pack_ids: Sequence[str] | None = None) -> list[PackLike]:
    """Load packs by id. Prefers discovery.packs registry when present."""
    try:
        from aipocket.discovery.packs import list_packs
        from aipocket.discovery.packs.registry import get_pack

        if pack_ids:
            if "all" in pack_ids:
                return list(list_packs())
            out: list[PackLike] = []
            for pid in pack_ids:
                try:
                    out.append(get_pack(pid))
                except KeyError:
                    continue
            return out
        registered = list(list_packs())
        if registered:
            # Preserve the existing default while allowing explicit access to every pack.
            glm = [p for p in registered if p.pack_id == "glm"]
            return glm or registered
    except Exception:  # noqa: BLE001 — packs package optional at import time
        pass
    default = _default_glm_pack()
    if not pack_ids or default.pack_id in pack_ids or "all" in (pack_ids or []):
        return [default]
    return []


class GitHubSource:
    name = "github"

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        packs: list[PackLike] | None = None,
        client: Any | None = None,
        strict: bool = False,
    ) -> None:
        self._settings = settings or default_settings
        self._packs = packs
        self._client = client
        # strict=True when the scan explicitly requested source=github.
        self.strict = strict

    def is_configured(self) -> bool:
        cfg = self._settings
        return bool(cfg.github_hunter_enabled and cfg.github_token_list and cfg.pg_enabled)

    def configuration_error(self) -> str:
        cfg = self._settings
        missing: list[str] = []
        if not cfg.github_hunter_enabled:
            missing.append("GITHUB_HUNTER_ENABLED=false")
        if not cfg.github_token_list:
            missing.append("GITHUB_TOKENS empty")
        if not cfg.pg_enabled:
            missing.append("DATABASE_URL empty (PostgreSQL required for GitHub durable queue)")
        return (
            "GitHub source not configured: "
            + "; ".join(missing)
            + ". Set GITHUB_TOKENS and DATABASE_URL, enable GITHUB_HUNTER_ENABLED."
        )

    async def fetch(
        self,
        *,
        budgets: SourceBudgets,
        mode: ScanMode,
        policy: ScanPolicy | None = None,
        skip_direct: bool = False,
        **kwargs: Any,
    ) -> SourceFetchResult:
        if not self.is_configured():
            # Fail closed when explicitly selected; skip when part of "all".
            if self.strict or kwargs.get("strict"):
                return SourceFetchResult(
                    source=self.name,
                    errors=(self.configuration_error(),),
                )
            log.info("GitHub not configured — skipping")
            return SourceFetchResult(source=self.name)

        packs = self._packs if self._packs is not None else resolve_packs(kwargs.get("pack_ids"))
        if not packs:
            return SourceFetchResult(
                source=self.name,
                errors=("no GitHub packs available",),
            )

        from aipocket.clients.github import GitHubClient

        ledger = get_current_ledger()
        own_client = self._client is None
        client = self._client or GitHubClient(
            tokens=list(self._settings.github_token_list),
            ledger=ledger,
            settings=self._settings,
        )

        observations: list[CredentialSourceObservation] = []
        usage: list[QueryUsage] = []
        checkpoints: list[CheckpointUpdate] = []
        errors: list[str] = []
        seeds: list[dict[str, Any]] = []

        pack_ids = [p.pack_id for p in packs]
        report_phase(f"GitHub 狩猎 · packs={','.join(pack_ids)}")
        try:
            # Claim pending work before new search shards.
            pending = claim_pending(limit=200)
            if pending:
                report_phase(f"GitHub · 处理队列中积压 work · {len(pending)} 项")
                log.info("GitHub: processing %d pending work items", len(pending))
                obs, err = await self._process_work_items(
                    client, pending, packs=packs, message_hints={}
                )
                observations.extend(obs)
                errors.extend(err)
                log.info(
                    "GitHub: pending work done · obs=+%d errors=%d",
                    len(obs),
                    len(err),
                )

            run_id = (ledger.run_id if ledger else "") or kwargs.get("run_id") or ""
            commit_budget = budgets.github_commit
            if commit_budget is None:
                commit_budget = self._settings.github_commit_query_budget
            code_budget = budgets.github_code
            if code_budget is None:
                code_budget = self._settings.github_code_query_budget

            for pack in packs:
                # Lane A — commit_message
                try:
                    report_phase(f"GitHub · {pack.pack_id} · commit_message 搜索")
                    log.info(
                        "GitHub lane=commit_message pack=%s budget=%s",
                        pack.pack_id,
                        commit_budget,
                    )
                    a_obs, a_usage, a_cp, a_err, a_seeds = await self._run_commit_message_lane(
                        client,
                        pack,
                        commit_budget=commit_budget,
                        run_id=run_id,
                        mode=mode,
                    )
                    observations.extend(a_obs)
                    usage.extend(a_usage)
                    checkpoints.extend(a_cp)
                    errors.extend(a_err)
                    seeds.extend(a_seeds)
                    log.info(
                        "GitHub lane=commit_message pack=%s done · obs=+%d seeds=+%d errors=%d",
                        pack.pack_id,
                        len(a_obs),
                        len(a_seeds),
                        len(a_err),
                    )
                except Exception as exc:  # noqa: BLE001
                    log.exception("commit_message lane failed for pack=%s", pack.pack_id)
                    errors.append(f"commit_message:{pack.pack_id}:{type(exc).__name__}")

                # Lane B — code_snapshot
                try:
                    report_phase(f"GitHub · {pack.pack_id} · code_snapshot 搜索")
                    log.info(
                        "GitHub lane=code_snapshot pack=%s budget=%s",
                        pack.pack_id,
                        code_budget,
                    )
                    b_obs, b_usage, b_cp, b_err, b_seeds = await self._run_code_snapshot_lane(
                        client,
                        pack,
                        code_budget=code_budget,
                        run_id=run_id,
                    )
                    observations.extend(b_obs)
                    usage.extend(b_usage)
                    checkpoints.extend(b_cp)
                    errors.extend(b_err)
                    seeds.extend(b_seeds)
                    log.info(
                        "GitHub lane=code_snapshot pack=%s done · obs=+%d seeds=+%d errors=%d",
                        pack.pack_id,
                        len(b_obs),
                        len(b_seeds),
                        len(b_err),
                    )
                except Exception as exc:  # noqa: BLE001
                    log.exception("code_snapshot lane failed for pack=%s", pack.pack_id)
                    errors.append(f"code_snapshot:{pack.pack_id}:{type(exc).__name__}")

                # Lane C — seeded_file_history
                if self._settings.github_file_history_enabled and seeds:
                    try:
                        report_phase(
                            f"GitHub · {pack.pack_id} · file history · {len(seeds)} 个 seed 文件"
                        )
                        log.info(
                            "GitHub lane=seeded_file_history pack=%s seeds=%d",
                            pack.pack_id,
                            len(seeds),
                        )
                        c_obs, c_usage, c_cp, c_err = await self._run_seeded_history_lane(
                            client,
                            pack,
                            seeds=seeds,
                            run_id=run_id,
                            mode=mode,
                        )
                        observations.extend(c_obs)
                        usage.extend(c_usage)
                        checkpoints.extend(c_cp)
                        errors.extend(c_err)
                        log.info(
                            "GitHub lane=seeded_file_history pack=%s done · obs=+%d errors=%d",
                            pack.pack_id,
                            len(c_obs),
                            len(c_err),
                        )
                    except Exception as exc:  # noqa: BLE001
                        log.exception("seeded_file_history lane failed for pack=%s", pack.pack_id)
                        errors.append(f"seeded_file_history:{pack.pack_id}:{type(exc).__name__}")
        finally:
            if own_client and client is not None:
                close = getattr(client, "aclose", None)
                if close is not None:
                    await close()

        report_phase(f"GitHub 狩猎完成 · observations={len(observations)}")
        log.info(
            "GitHub fetch complete · observations=%d usage=%d errors=%d",
            len(observations),
            len(usage),
            len(errors),
        )
        return SourceFetchResult(
            source=self.name,
            host_hits=(),  # NEVER fake hosts
            credential_observations=tuple(observations),
            query_usage=tuple(usage),
            checkpoint_updates=tuple(checkpoints),
            errors=tuple(errors),
        )

    # ---------------------------------------------------------------- lanes
    async def _run_commit_message_lane(
        self,
        client: Any,
        pack: PackLike,
        *,
        commit_budget: int,
        run_id: str,
        mode: ScanMode,
    ) -> tuple[
        list[CredentialSourceObservation],
        list[QueryUsage],
        list[CheckpointUpdate],
        list[str],
        list[dict[str, Any]],
    ]:
        cfg = self._settings
        observations: list[CredentialSourceObservation] = []
        usage: list[QueryUsage] = []
        checkpoints: list[CheckpointUpdate] = []
        errors: list[str] = []
        seeds: list[dict[str, Any]] = []

        # One watermark per pack for the lookback window (shared across anchors).
        root_shard_id = f"cm:{pack.pack_id}:window"
        existing = load_checkpoint(
            lane="commit_message", pack_id=pack.pack_id, shard_id=root_shard_id
        )
        watermark = existing.watermark if existing else ""
        if mode == "full" and cfg.github_backfill_from:
            watermark = ""
            window_start, window_end = default_window(
                lookback_hours=max(cfg.github_lookback_hours, 24),
                overlap_minutes=cfg.github_overlap_minutes,
                watermark=cfg.github_backfill_from,
            )
        else:
            window_start, window_end = default_window(
                lookback_hours=cfg.github_lookback_hours,
                overlap_minutes=cfg.github_overlap_minutes,
                watermark=watermark,
            )

        shards = build_commit_message_shards(
            pack,
            window_start=window_start,
            window_end=window_end,
            page_budget=cfg.github_max_pages_per_shard,
        )[: max(0, commit_budget)]
        total_shards = len(shards)
        log.info(
            "GitHub commit_message pack=%s shards=%d window=%s..%s",
            pack.pack_id,
            total_shards,
            window_start.isoformat(),
            window_end.isoformat(),
        )

        message_hints: dict[str, str] = {}
        for idx, shard in enumerate(shards, start=1):
            if idx == 1 or idx == total_shards or idx % 5 == 0:
                report_phase(f"GitHub · {pack.pack_id} · commit_message {idx}/{total_shards}")
                log.info(
                    "GitHub commit_message [%d/%d] pack=%s q=%s",
                    idx,
                    total_shards,
                    pack.pack_id,
                    (shard.build_q() or shard.query_id or "")[:80],
                )
            try:
                o, u, cp, e, sh, mh = await self._search_shard(client, shard, run_id=run_id)
                observations.extend(o)
                usage.extend(u)
                checkpoints.extend(cp)
                errors.extend(e)
                seeds.extend(sh)
                message_hints.update(mh)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{shard.query_id}:{type(exc).__name__}")

        # Advance root window watermark only after shards processed.
        if shards and not errors:
            cp = CheckpointRow(
                source="github",
                lane="commit_message",
                pack_id=pack.pack_id,
                shard_id=root_shard_id,
                watermark=window_end.isoformat(),
                cursor_state={"window_start": window_start.isoformat()},
                status="ok",
            )
            advance_checkpoint_with_work(
                checkpoint=cp,
                work_rows=[],
                upsert_work_fn=lambda rows, conn=None: None,
            )
            checkpoints.append(cp.to_update())

        return observations, usage, checkpoints, errors, seeds

    async def _run_code_snapshot_lane(
        self,
        client: Any,
        pack: PackLike,
        *,
        code_budget: int,
        run_id: str,
    ) -> tuple[
        list[CredentialSourceObservation],
        list[QueryUsage],
        list[CheckpointUpdate],
        list[str],
        list[dict[str, Any]],
    ]:
        cfg = self._settings
        observations: list[CredentialSourceObservation] = []
        usage: list[QueryUsage] = []
        checkpoints: list[CheckpointUpdate] = []
        errors: list[str] = []
        seeds: list[dict[str, Any]] = []

        shards = build_code_snapshot_shards(pack, page_budget=cfg.github_max_pages_per_shard)[
            : max(0, code_budget)
        ]
        total_shards = len(shards)
        log.info(
            "GitHub code_snapshot pack=%s shards=%d",
            pack.pack_id,
            total_shards,
        )

        for idx, shard in enumerate(shards, start=1):
            if idx == 1 or idx == total_shards or idx % 5 == 0:
                report_phase(f"GitHub · {pack.pack_id} · code_snapshot {idx}/{total_shards}")
                log.info(
                    "GitHub code_snapshot [%d/%d] pack=%s q=%s",
                    idx,
                    total_shards,
                    pack.pack_id,
                    (shard.build_q() or shard.query_id or "")[:80],
                )
            try:
                o, u, cp, e, sh, _mh = await self._search_shard(client, shard, run_id=run_id)
                observations.extend(o)
                usage.extend(u)
                checkpoints.extend(cp)
                errors.extend(e)
                seeds.extend(sh)
                if o or sh:
                    log.info(
                        "GitHub code_snapshot [%d/%d] hits → obs=+%d seeds=+%d",
                        idx,
                        total_shards,
                        len(o),
                        len(sh),
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{shard.query_id}:{type(exc).__name__}")
                log.warning(
                    "GitHub code_snapshot [%d/%d] failed: %s",
                    idx,
                    total_shards,
                    type(exc).__name__,
                )

        return observations, usage, checkpoints, errors, seeds

    async def _run_seeded_history_lane(
        self,
        client: Any,
        pack: PackLike,
        *,
        seeds: list[dict[str, Any]],
        run_id: str,
        mode: ScanMode,
    ) -> tuple[
        list[CredentialSourceObservation],
        list[QueryUsage],
        list[CheckpointUpdate],
        list[str],
    ]:
        cfg = self._settings
        observations: list[CredentialSourceObservation] = []
        usage: list[QueryUsage] = []
        checkpoints: list[CheckpointUpdate] = []
        errors: list[str] = []

        window_start, window_end = default_window(
            lookback_hours=cfg.github_lookback_hours,
            overlap_minutes=cfg.github_overlap_minutes,
        )
        shards = build_seeded_file_history_shards(
            pack,
            seeds,
            window_start=window_start,
            window_end=window_end,
            page_budget=1,
        )
        limit = cfg.github_file_history_commit_limit
        pack_hints = pack if hasattr(pack, "path_hints") else _default_glm_pack()
        total_shards = len(shards)
        log.info(
            "GitHub file_history pack=%s unique_seeds=%d",
            pack.pack_id,
            total_shards,
        )

        for idx, shard in enumerate(shards, start=1):
            if idx == 1 or idx == total_shards or idx % 10 == 0:
                report_phase(
                    f"GitHub · {pack.pack_id} · file history {idx}/{total_shards} · "
                    f"{shard.owner}/{shard.repo}"
                )
                log.info(
                    "GitHub file_history [%d/%d] %s/%s path=%s",
                    idx,
                    total_shards,
                    shard.owner,
                    shard.repo,
                    (shard.file_path or "")[:120],
                )
            since = window_start.isoformat()
            until = window_end.isoformat()
            attribution_token = current_query_attribution.set(
                RequestAttribution(
                    source="github",
                    query_id=shard.query_id,
                    pack_id=shard.pack_id,
                    lane=shard.lane,
                )
            )
            try:
                try:
                    commits = await client.list_commits(
                        shard.owner,
                        shard.repo,
                        path=shard.file_path,
                        since=since,
                        until=until,
                        page=1,
                        per_page=min(100, limit),
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{shard.query_id}:{type(exc).__name__}")
                    continue
            finally:
                current_query_attribution.reset(attribution_token)

            work_items: list[ArtifactWorkItem] = []
            for c in commits[:limit]:
                if not isinstance(c, dict):
                    continue
                item = work_from_search_item(
                    {
                        **c,
                        "repository": {
                            "id": shard.repo_id,
                            "full_name": f"{shard.owner}/{shard.repo}",
                        },
                    },
                    source_kind="patch",
                    run_id=run_id,
                    query_id=shard.query_id,
                    pack_id=shard.pack_id,
                    lane=shard.lane,
                    coverage_mode="seeded_only",
                    file_path=shard.file_path,
                )
                if item:
                    work_items.append(item)

            if work_items:
                cp = CheckpointRow(
                    source="github",
                    lane=shard.lane,
                    pack_id=shard.pack_id,
                    shard_id=shard.shard_id,
                    watermark=until,
                    cursor_state={"seed_origin": shard.seed_origin, "path": shard.file_path},
                    status="ok",
                )
                advance_checkpoint_with_work(
                    checkpoint=cp,
                    work_rows=work_items,
                    upsert_work_fn=upsert_work_rows,
                )
                checkpoints.append(cp.to_update())
                obs, err = await self._process_work_items(
                    client, work_items, packs=[pack_hints], message_hints={}
                )
                observations.extend(obs)
                errors.extend(err)
                log.info(
                    "GitHub file_history [%d/%d] commits=%d obs=+%d",
                    idx,
                    total_shards,
                    len(work_items),
                    len(obs),
                )

            usage.append(
                QueryUsage(
                    query=f"history:{shard.owner}/{shard.repo}:{shard.file_path}",
                    query_id=shard.query_id,
                    lane=shard.lane,
                    pack_id=shard.pack_id,
                )
            )

        return observations, usage, checkpoints, errors

    @staticmethod
    def _is_public_search_item(item: dict[str, Any]) -> bool:
        repository = item.get("repository")
        if not isinstance(repository, dict):
            return False
        return repository.get("private") is False

    async def _search_shard(
        self,
        client: Any,
        shard: GitHubQueryShard,
        *,
        run_id: str,
    ) -> tuple[
        list[CredentialSourceObservation],
        list[QueryUsage],
        list[CheckpointUpdate],
        list[str],
        list[dict[str, Any]],
        dict[str, str],
    ]:
        """Paginate a search shard, durable-upsert work, extract secrets."""
        cfg = self._settings
        observations: list[CredentialSourceObservation] = []
        usage: list[QueryUsage] = []
        checkpoints: list[CheckpointUpdate] = []
        errors: list[str] = []
        seeds: list[dict[str, Any]] = []
        message_hints: dict[str, str] = {}

        q = shard.build_q()
        if not q and shard.lane != "seeded_file_history":
            return observations, usage, checkpoints, errors, seeds, message_hints

        existing = load_checkpoint(lane=shard.lane, pack_id=shard.pack_id, shard_id=shard.shard_id)
        start_page = 1
        etag = ""
        if existing and isinstance(existing.cursor_state, dict):
            if shard.lane != "code_snapshot":
                start_page = int(existing.cursor_state.get("page") or 1)
            etag = existing.etag or ""

        total_hits = 0
        coverage = shard.coverage_mode
        page = start_page
        pages_done = 0

        while pages_done < shard.page_budget:
            if shard.lane == "commit_message":
                page_result = await client.search_commits(
                    q,
                    page=page,
                    etag=etag if page == start_page else "",
                    query_id=shard.query_id,
                    pack_id=shard.pack_id,
                )
            else:
                page_result = await client.search_code(
                    q,
                    page=page,
                    etag=etag if page == start_page else "",
                    query_id=shard.query_id,
                    pack_id=shard.pack_id,
                )

            if getattr(page_result, "not_modified", False):
                break

            items = list(page_result.items or ())
            total_hits += len(items)

            if page_result.incomplete_results or page_result.total_count >= 1000:
                if shard.lane == "commit_message":
                    children = bisect_date_window(shard)
                    if len(children) == 1 and children[0].coverage_mode == "truncated":
                        coverage = "truncated"
                    elif len(children) > 1 and page == 1 and pages_done == 0:
                        # Recurse into bisected windows instead of this saturated shard.
                        for child in children:
                            o, u, cp, e, sh, mh = await self._search_shard(
                                client, child, run_id=run_id
                            )
                            observations.extend(o)
                            usage.extend(u)
                            checkpoints.extend(cp)
                            errors.extend(e)
                            seeds.extend(sh)
                            message_hints.update(mh)
                        return observations, usage, checkpoints, errors, seeds, message_hints
                else:
                    coverage = "truncated"

            work_items: list[ArtifactWorkItem] = []
            for it in items:
                if not self._is_public_search_item(it):
                    continue
                source_kind = "commit_message" if shard.lane == "commit_message" else "blob"
                file_path = ""
                object_sha = ""
                if shard.lane == "code_snapshot":
                    file_path = str(it.get("path") or "")
                    object_sha = str(it.get("sha") or "")
                    # code search item sha is blob sha; commit is in url sometimes.
                wi = work_from_search_item(
                    it,
                    source_kind=source_kind,
                    run_id=run_id,
                    query_id=shard.query_id,
                    pack_id=shard.pack_id,
                    lane=shard.lane,
                    coverage_mode=coverage,
                    file_path=file_path,
                    object_sha=object_sha,
                )
                if wi is None:
                    continue
                # For code search, commit_sha may be missing — use blob sha as locator.
                if shard.lane == "code_snapshot" and not wi.commit_sha:
                    wi.commit_sha = object_sha or "HEAD"
                work_items.append(wi)

                # Capture message for commit search items.
                if shard.lane == "commit_message":
                    commit_obj = it.get("commit") if isinstance(it.get("commit"), dict) else {}
                    msg = str(commit_obj.get("message") or "")
                    if msg:
                        message_hints[wi.commit_sha] = msg
                    # Seed for history: not from commit message lane primarily;
                    # history seeds come from code_snapshot.

                if shard.lane == "code_snapshot":
                    repo = it.get("repository") if isinstance(it.get("repository"), dict) else {}
                    full = str(repo.get("full_name") or "")
                    if "/" in full and file_path:
                        owner, repo_name = full.split("/", 1)
                        seeds.append(
                            {
                                "owner": owner,
                                "repo": repo_name,
                                "path": file_path,
                                "repo_id": str(repo.get("id") or full),
                                "seed_origin": "code_snapshot",
                                "public": True,
                            }
                        )

            checkpoint_etag = page_result.etag or ""
            if shard.lane == "code_snapshot" and page != 1:
                checkpoint_etag = existing.etag if existing else ""
            next_page = 1 if shard.lane == "code_snapshot" else page + 1
            cp = CheckpointRow(
                source="github",
                lane=shard.lane,
                pack_id=shard.pack_id,
                shard_id=shard.shard_id,
                watermark=watermark_now(),
                cursor_state={"page": next_page, "q_hash": shard.query_id},
                etag=checkpoint_etag,
                status="truncated" if coverage == "truncated" else "ok",
            )
            # Atomic: work rows + checkpoint.
            advance_checkpoint_with_work(
                checkpoint=cp,
                work_rows=work_items,
                upsert_work_fn=upsert_work_rows,
            )
            checkpoints.append(cp.to_update())

            if work_items:
                pack_list = [
                    p
                    for p in (self._packs or resolve_packs([shard.pack_id]))
                    if p.pack_id == shard.pack_id
                ]
                if not pack_list:
                    pack_list = resolve_packs([shard.pack_id]) or [_default_glm_pack()]
                obs, err = await self._process_work_items(
                    client,
                    work_items,
                    packs=pack_list,
                    message_hints=message_hints,
                )
                observations.extend(obs)
                errors.extend(err)

            pages_done += 1
            page += 1
            etag = ""
            if not items:
                break
            # Cap: GitHub search max 1000 results.
            if page > 10 or (page - 1) * cfg.github_search_page_size >= min(
                1000, page_result.total_count or 1000
            ):
                break
        usage.append(
            QueryUsage(
                query=q,
                credits=0,
                query_id=shard.query_id,
                lane=shard.lane,
                pack_id=shard.pack_id,
            )
        )
        return observations, usage, checkpoints, errors, seeds, message_hints

    async def _process_work_items(
        self,
        client: Any,
        items: list[ArtifactWorkItem],
        *,
        packs: list[Any],
        message_hints: dict[str, str],
    ) -> tuple[list[CredentialSourceObservation], list[str]]:
        cfg = self._settings
        observations: list[CredentialSourceObservation] = []
        errors: list[str] = []
        pack_by_id = {p.pack_id: p for p in packs}
        default_pack = packs[0] if packs else _default_glm_pack()
        blob_budget = BlobBudget(remaining=cfg.github_blob_fallback_budget)
        sem = asyncio.Semaphore(max(1, cfg.github_artifact_concurrency))

        async def one(item: ArtifactWorkItem) -> None:
            attribution_token = current_query_attribution.set(
                RequestAttribution(
                    source="github",
                    query_id=item.query_id,
                    pack_id=item.pack_id,
                    lane=item.lane,
                )
            )
            try:
                async with sem:
                    pack = pack_by_id.get(item.pack_id, default_pack)
                    # Code snapshot items with blob sha: try blob path directly when
                    # source_kind is blob and we have object_sha without commit context.
                    if item.source_kind == "blob" and item.object_sha and item.file_path:
                        try:
                            from aipocket.services.github_artifacts import (
                                _extract_from_text,
                                _split_full_name,
                            )

                            owner, repo = _split_full_name(item.repository_full_name)
                            if owner and repo:
                                if not blob_budget.consume():
                                    transition(
                                        item,
                                        "budget_exhausted",
                                        error_class="blob_fallback_budget",
                                    )
                                    return
                                blob = await client.get_blob(owner, repo, item.object_sha)
                                if blob.truncated:
                                    transition(
                                        item,
                                        "artifact_too_large",
                                        error_class="artifact_too_large",
                                    )
                                    return
                                secrets = _extract_from_text(
                                    blob.content,
                                    source_kind="blob",
                                    change_side="context",
                                    work=item,
                                    pack=pack,
                                    file_path=item.file_path,
                                    object_sha=blob.sha,
                                    format_hint=(
                                        item.file_path.rsplit(".", 1)[-1]
                                        if "." in item.file_path
                                        else "env"
                                    ),
                                )
                                for secret in secrets:
                                    observations.append(
                                        _to_observation(secret.bundle, item, secret)
                                    )
                                mark_extract_done(item)
                                mark_terminal(item)
                                return
                        except Exception as exc:  # noqa: BLE001
                            # Fall through to commit fetch path.
                            log.debug("blob direct fetch failed: %s", type(exc).__name__)

                    message = message_hints.get(item.commit_sha, "")
                    result = await fetch_and_extract(
                        client,
                        item,
                        message_hint=message,
                        pack=pack,
                        blob_budget=blob_budget,
                        settings=cfg,
                    )
                    if result.status == "source_gone":
                        mark_source_gone(item, error_class=result.error_class or "source_gone")
                        return
                    if result.status == "transient":
                        mark_transient(item, error_class=result.error_class or "transient")
                        return
                    if result.status in ("artifact_too_large", "budget_exhausted"):
                        for secret in result.secrets:
                            observations.append(_to_observation(secret.bundle, item, secret))
                        transition(item, result.status, error_class=result.error_class)  # type: ignore[arg-type]
                        return
                    for secret in result.secrets:
                        observations.append(_to_observation(secret.bundle, item, secret))
                    mark_extract_done(item)
                    mark_terminal(item)
            finally:
                current_query_attribution.reset(attribution_token)

        await asyncio.gather(*(one(it) for it in items))
        return observations, errors


def _to_observation(
    bundle: CredentialBundle,
    work: ArtifactWorkItem,
    sec: Any,
) -> CredentialSourceObservation:
    endpoint = bundle.endpoint_candidates[0] if bundle.endpoint_candidates else ""
    cred = Credential(
        apikey=bundle.secret_value.reveal(),
        apiurl=endpoint,
        backend="github",
        source="github",
        host="",
        product=work.pack_id or "",
        raw_context="",  # never put secret-bearing patch text here long-term
        bundle=bundle,
    )
    provenance = ArtifactProvenance(
        repository_id=work.repo_id,
        repository_full_name=work.repository_full_name,
        commit_sha=work.commit_sha,
        object_sha=getattr(sec, "object_sha", "") or work.object_sha,
        file_path=getattr(sec, "file_path", "") or work.file_path,
        source_kind=getattr(sec, "source_kind", work.source_kind),
        change_side=getattr(sec, "change_side", ""),
        line_start=getattr(sec, "line_start", None),
        line_end=getattr(sec, "line_end", None),
        query_id=work.query_id,
        pack_id=work.pack_id,
        lane=work.lane,
    )
    return CredentialSourceObservation(
        bundle=bundle,
        credential=cred,
        provenance=provenance,
        query_id=work.query_id,
        pack_id=work.pack_id,
        lane=work.lane,
        coverage_mode=work.coverage_mode,
    )
