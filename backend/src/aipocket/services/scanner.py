from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aipocket.clients.fofa import FofaClient
from aipocket.core.config import settings
from aipocket.core.metrics import (
    ErrorClass,
    ExtractionMethodAggregate,
    QueryUsage,
    ValidationOutcomeAggregate,
    classify_error,
)
from aipocket.core.models import Credential, ScanMode, ScanRunResult, ValidationResult
from aipocket.core.observations import ExtractionMethod, ObservationRegistry
from aipocket.core.request_ledger import RequestAttribution, RequestLedger, current_ledger
from aipocket.core.scan_phase import report_phase
from aipocket.core.scan_policy import ScanPolicy, policy_from_mode
from aipocket.core.targets import DiscoveryTarget, canonicalize_hits
from aipocket.discovery import SourceBudgets, SourceRegistry, merge_fetch_results

from .credential_policy import filter_credentials_by_policy
from .dedup import DedupStore, get_dedup_store
from .extractor import extract_credentials
from .queries import build_queries
from .query_metrics import QueryMetricsCollector
from .query_planner import (
    PlannerConfig,
    QueryCandidate,
    candidate_lane,
    load_query_history,
    plan_queries,
)
from .validator import validate_all
from .writer import (
    append_scan_result,
    write_scan_metadata,
    write_suspicious_results,
    write_valid_results,
)

log = logging.getLogger(__name__)

# Quick regex to detect potential credentials in hit blobs — used for sampling priority.
_SK_PATTERN = re.compile(
    r"sk-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{20,}"
)


def _merge_credentials(
    existing: list[Credential],
    new: list[Credential],
    seen: set[tuple[str, str]] | None = None,
) -> set[tuple[str, str]]:
    """Merge *new* credentials into *existing* in-place, deduplicating by (apikey, apiurl).
    Returns the updated seen-set."""
    if seen is None:
        seen = {_credential_identity(c) for c in existing}
    for c in new:
        identity = _credential_identity(c)
        if identity not in seen:
            existing.append(c)
            seen.add(identity)
    return seen


def _credential_identity(credential: Credential) -> tuple[str, str]:
    if credential.bundle is not None:
        return credential.bundle.secret_fingerprint, credential.apiurl
    return credential.apikey, credential.apiurl


def _discovery_funnel_counts(
    host_hits: list[dict],
    targets: list[DiscoveryTarget],
    cred_observations: list,
) -> tuple[int, int]:
    """Run-level raw_hits / unique_targets across host + credential lanes.

    Host sources (FOFA/Shodan): raw search hits and canonicalized targets.
    Credential sources (GitHub): each observation is a raw hit; unique targets
    are distinct credential identities (secret fingerprint + endpoint).
    """
    raw_hits = len(host_hits) + len(cred_observations)
    unique_github = len({_credential_identity(obs.credential) for obs in cred_observations})
    unique_targets = len(targets) + unique_github
    return raw_hits, unique_targets


@dataclass(frozen=True, slots=True)
class QueryBudgets:
    fofa: int | None
    shodan: int | None


_REQUIRED_LEDGER_STAGES = frozenset(
    {"discovery", "artifact_fetch", "probe", "validation", "noauth", "balance", "gpt"}
)
_REQUIRED_HTTP_INSTRUMENTATION_VERSION = 1


def _complete_ledger(ledger: RequestLedger | None) -> tuple[int, bool, str]:
    if ledger is None:
        return 0, False, "ledger_unavailable"
    if not settings.pg_enabled:
        ledger.mark_incomplete("pg_disabled")
    from .http_transport import HTTP_INSTRUMENTATION_VERSION

    if HTTP_INSTRUMENTATION_VERSION < _REQUIRED_HTTP_INSTRUMENTATION_VERSION:
        ledger.mark_incomplete("http_instrumentation_incomplete")
    if settings.pg_enabled and ledger.on_flush is None:
        ledger.mark_incomplete("ledger_flush_unavailable")
    ledger.drain()
    totals = ledger.totals()
    unknown_stages = set(totals.by_stage) - _REQUIRED_LEDGER_STAGES
    if unknown_stages:
        ledger.mark_incomplete("unknown_instrumentation_stage")
    complete = ledger.is_complete and settings.pg_enabled
    reason = ledger.incomplete_reason or ("" if complete else "ledger_incomplete")
    if ledger.flush_failed:
        complete = False
        reason = ledger.flush_error or "ledger_flush_failed"
    return totals.total, complete, reason


def _snapshot_query_metrics(
    collector: QueryMetricsCollector,
    ledger: RequestLedger | None,
    *,
    ledger_complete: bool,
):
    if ledger is not None:
        collector.apply_ledger(ledger.totals().by_query)
    return collector.snapshot(attribution_version=3 if ledger_complete else 2)


def _credential_attribution(
    observations: ObservationRegistry,
    credentials: list[Credential],
    query_metadata: dict[tuple[str, str], tuple[str, str, str]],
) -> dict[int, RequestAttribution]:
    attribution: dict[int, RequestAttribution] = {}
    for credential in credentials:
        observation = observations.get(credential)
        if observation is None:
            continue
        source, query = observation.primary_provenance
        query_id, lane, pack_id = query_metadata.get((source, query), (query, "", ""))
        attribution[id(credential)] = RequestAttribution(
            source=source,
            query_id=query_id,
            pack_id=pack_id,
            lane=lane,
        )
    return attribution


async def run_scan(
    query_budgets: QueryBudgets | None = None,
    run_dir: Path | None = None,
    *,
    mode: ScanMode = "incremental",
    skip_direct: bool = False,
    sources: set[str] | None = None,
    github_pack_ids: tuple[str, ...] = (),
    policy: ScanPolicy | None = None,
    resume_run_id: str | None = None,
    manual_enrich: frozenset[str] | set[str] | tuple[str, ...] | list[str] | None = None,
) -> ScanRunResult:
    started = datetime.now(UTC).isoformat()
    scan_policy = policy or policy_from_mode(mode)

    # Stamp the run dir so GPT debug/failed-batch dumps land inside it.
    from . import analyzer as _analyzer

    _analyzer.set_run_dir(run_dir)

    from aipocket.core.db import current_run_id

    from .scan_checkpoint import (
        PHASE_FINISHED,
        load_run_state,
        mark_phase,
    )

    # Resume is opt-in and explicit (C8). Reuse the prior run_id / run_dir.
    resume_phase = ""
    resume_detail: dict = {}
    if resume_run_id:
        if not settings.pg_enabled:
            raise RuntimeError("resume requires DATABASE_URL / PostgreSQL")
        state_row = await asyncio.to_thread(load_run_state, resume_run_id)
        if state_row is None:
            raise RuntimeError(f"resume run not found: {resume_run_id}")
        if (
            str(state_row.get("state") or "") == "finished"
            or str(state_row.get("phase") or "") == PHASE_FINISHED
        ):
            raise RuntimeError(f"run already finished: {resume_run_id}")
        resume_phase = str(state_row.get("phase") or "")
        detail = state_row.get("phase_detail") or {}
        resume_detail = detail if isinstance(detail, dict) else {}
        run_id = resume_run_id
        if run_dir is None:
            run_dir = settings.results_path / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
        started = str(state_row.get("started_at") or started)
        if state_row.get("scan_mode") in {"full", "incremental"}:
            mode = state_row["scan_mode"]  # type: ignore[assignment]
            scan_policy = policy or policy_from_mode(mode)
        log.info(
            "Resuming run %s from phase=%s detail_keys=%s",
            run_id,
            resume_phase or "(empty)",
            list(resume_detail),
        )
    else:
        run_id = run_dir.name if run_dir else f"ephemeral_{started}"

    run_token = current_run_id.set(run_id if run_dir or settings.pg_enabled else None)
    parent_run_created = False
    ledger_token = None
    dedup: DedupStore | None = None

    try:
        # The request_ledger table has a foreign key to runs. Create the parent
        # before constructing a ledger with an active flush callback.
        if settings.pg_enabled:
            from .writer import create_run_pg

            if not resume_run_id:
                await asyncio.to_thread(create_run_pg, run_id, started, mode)
            else:
                # Re-open interrupted run without wiping durable intermediate tables.
                await asyncio.to_thread(create_run_pg, run_id, started, mode)
            parent_run_created = True
            await asyncio.to_thread(mark_phase, run_id, "started", resume=bool(resume_run_id))

        def _flush_ledger(batch: list) -> None:
            from .writer import persist_ledger_batch_pg

            persist_ledger_batch_pg(batch)

        ledger = RequestLedger(
            run_id=run_id,
            on_flush=_flush_ledger if parent_run_created else None,
        )
        ledger_token = current_ledger.set(ledger)

        # Cross-run dedup store (Redis-backed; degrades to no-op if unavailable).
        dedup = await get_dedup_store()
        budgets = (
            QueryBudgets(fofa=None, shodan=None)
            if scan_policy.discovery_scope == "full"
            else query_budgets
            or QueryBudgets(
                fofa=settings.fofa_query_budget,
                shodan=settings.shodan_query_budget,
            )
        )
        from .scan_lock import acquire_scan_lease

        lease = await acquire_scan_lease()
        async with lease:
            return await lease.run(
                _run_scan_inner(
                    budgets,
                    run_dir,
                    skip_direct=skip_direct,
                    started=started,
                    dedup=dedup,
                    mode=mode,
                    sources=sources,
                    github_pack_ids=github_pack_ids,
                    policy=scan_policy,
                    ledger=ledger,
                    resume_phase=resume_phase,
                    resume_detail=resume_detail,
                    manual_enrich=manual_enrich,
                )
            )
    except BaseException as exc:
        if parent_run_created:
            from .writer import mark_run_interrupted_pg

            try:
                await asyncio.to_thread(
                    mark_run_interrupted_pg,
                    run_id,
                    f"{type(exc).__name__}: scan aborted",
                )
            except Exception:  # noqa: BLE001 - preserve the original scan failure
                log.exception("Failed to mark interrupted run %s", run_id)
        raise
    finally:
        if dedup is not None:
            await dedup.close()
        if ledger_token is not None:
            current_ledger.reset(ledger_token)
        current_run_id.reset(run_token)


async def _run_scan_inner(
    query_budgets: QueryBudgets,
    run_dir: Path | None,
    *,
    skip_direct: bool,
    started: str,
    dedup: DedupStore,
    mode: ScanMode,
    sources: set[str] | None = None,
    github_pack_ids: tuple[str, ...] = (),
    policy: ScanPolicy | None = None,
    ledger: RequestLedger | None = None,
    resume_phase: str = "",
    resume_detail: dict | None = None,
    manual_enrich: frozenset[str] | set[str] | tuple[str, ...] | list[str] | None = None,
) -> ScanRunResult:
    from aipocket.core.db import current_run_id as _current_run_id

    from .scan_checkpoint import (
        PHASE_DISCOVERY,
        PHASE_EXTRACT,
        PHASE_FINALIZE,
        PHASE_FINISHED,
        PHASE_GPT,
        PHASE_PROBE,
        PHASE_VALIDATE,
        mark_phase,
        phase_at_least,
    )

    scan_policy = policy or policy_from_mode(mode)
    query_metrics = QueryMetricsCollector()
    run_id = _current_run_id.get() or (run_dir.name if run_dir else "")
    resume_detail = resume_detail or {}

    # Resume after discovery: skip FOFA/Shodan/GitHub fetch when durable hits exist.
    skip_discovery = bool(resume_phase) and phase_at_least(resume_phase, PHASE_EXTRACT)
    skip_to_validate = bool(resume_phase) and phase_at_least(resume_phase, PHASE_VALIDATE)

    # ------------------------------------------------------------------
    # Source Registry — FOFA/Shodan host hits + GitHub credential observations.
    query_metadata: dict[tuple[str, str], tuple[str, str, str]] = {}
    # Host hits go through canonicalize_hits; credential observations do not.
    # ------------------------------------------------------------------
    all_hits: list[dict] = []
    cred_observations: list = []
    sources_used: list[str] = []
    hits_by_source: dict[str, int] = {}
    queries_used: list[str] = []
    all_usage: list = []
    fetch_results: list = []
    discovery_spilled = False

    if skip_to_validate:
        log.info("Resume: skipping discovery/extract/probe/gpt → validate (phase=%s)", resume_phase)
        report_phase(f"恢复验证 · run={run_id}")
        sources_used = list(sources) if sources else ["resume"]
        hits_by_source = {}
        raw_hits_count = 0
        unique_targets_count = 0
        targets: list[DiscoveryTarget] = []
    elif skip_discovery:
        log.info("Resume: reloading discovery hits from PG (phase=%s)", resume_phase)
        report_phase("恢复发现 · 从 PostgreSQL 加载 hits")
        from aipocket.services.discovery_store import count_hits, iter_hits, slim_hit_for_target

        await asyncio.to_thread(mark_phase, run_id, PHASE_DISCOVERY, resume=True)
        slim_pages: list[dict] = []
        for page in iter_hits(run_id, batch_size=500):
            slim_pages.extend(slim_hit_for_target(h) for h in page)
        all_hits = slim_pages
        discovery_spilled = True
        from aipocket.services.candidate_store import STAGE_GITHUB, count_candidates

        fofa_n = await asyncio.to_thread(count_hits, run_id, source="fofa")
        shodan_n = await asyncio.to_thread(count_hits, run_id, source="shodan")
        gh_n = await asyncio.to_thread(count_candidates, run_id, stages=[STAGE_GITHUB])
        if fofa_n:
            hits_by_source["fofa"] = fofa_n
            sources_used.append("fofa")
        if shodan_n:
            hits_by_source["shodan"] = shodan_n
            sources_used.append("shodan")
        if gh_n:
            hits_by_source["github"] = gh_n
            sources_used.append("github")
        targets = canonicalize_hits(all_hits)
        raw_hits_count = sum(hits_by_source.values())
        unique_targets_count = len(targets) + gh_n
        log.info(
            "Resume discovery reload: hits=%d targets=%d github_cands=%d",
            raw_hits_count,
            len(targets),
            gh_n,
        )
    else:
        registry = SourceRegistry.default()
        resolved = registry.resolve(requested=sources, settings=settings)
        source_budgets = SourceBudgets(
            fofa=query_budgets.fofa,
            shodan=query_budgets.shodan,
            github_commit=settings.github_commit_query_budget,
            github_code=settings.github_code_query_budget,
        )
        source_names = ", ".join(s.name for s in resolved) or "none"
        report_phase(f"发现中 · 数据源 {source_names}")
        await asyncio.to_thread(mark_phase, run_id, PHASE_DISCOVERY)
        # Manual-only: optional FOFA/Shodan hostname reverse-lookup for banners.
        from aipocket.services.manual_enrich import normalize_enrich_engines

        enrich_engines = normalize_enrich_engines(manual_enrich)
        if enrich_engines and sources is not None and "manual" not in sources:
            log.info(
                "Ignoring manual_enrich=%s (manual source not selected)",
                ",".join(sorted(enrich_engines)),
            )
            enrich_engines = frozenset()
        fetch_results = await registry.fetch_all(
            resolved,
            budgets=source_budgets,
            mode=mode,
            policy=scan_policy,
            skip_direct=skip_direct,
            strict_sources=frozenset(sources or ()),
            pack_ids=github_pack_ids,
            manual_enrich=enrich_engines,
        )
        (
            all_hits,
            cred_observations,
            sources_used,
            hits_by_source,
            queries_used,
            all_usage,
        ) = merge_fetch_results(fetch_results)
        discovery_spilled = any(getattr(fr, "spilled", False) for fr in fetch_results)

        for fr in fetch_results:
            for usage in fr.query_usage:
                query_metadata[(fr.source, usage.query)] = (
                    usage.query_id or usage.query,
                    usage.lane,
                    usage.pack_id,
                )
                query_metrics.increment(
                    fr.source,
                    usage.query,
                    query_id=usage.query_id or usage.query,
                    lane=usage.lane,
                    pack_id=usage.pack_id,
                    query_credits=usage.credits,
                )

        # ONLY host hits enter canonicalize_hits — never GitHub credential payloads.
        targets = canonicalize_hits(all_hits)
        for hit in all_hits:
            source = str(hit.get("_source", ""))
            query = str(hit.get("_query_id", ""))
            if source and query:
                query_metrics.increment(source, query, raw_hits=1)
        for target in targets:
            for source, query in target.provenance_pairs:
                query_metrics.increment(source, query, unique_targets=1)
        # GitHub credential lane: count observations into the same funnel metrics.
        _seen_github_ids: set[tuple[str, str]] = set()
        for obs in cred_observations:
            query_key = obs.query_id or obs.pack_id or "github"
            query_metrics.increment("github", query_key, raw_hits=1)
            identity = _credential_identity(obs.credential)
            if identity not in _seen_github_ids:
                _seen_github_ids.add(identity)
                query_metrics.increment("github", query_key, unique_targets=1)
        # Prefer per-source counters when sources spilled (list lens may under-count).
        if hits_by_source:
            raw_hits_count = sum(hits_by_source.values())
            gh_obs = hits_by_source.get("github", 0)
            unique_targets_count = len(targets) + (
                gh_obs if not cred_observations else len(_seen_github_ids)
            )
        else:
            raw_hits_count, unique_targets_count = _discovery_funnel_counts(
                all_hits, targets, cred_observations
            )
        if not sources_used:
            source_errors = [error for result in fetch_results for error in result.errors]
            if sources == {"github"}:
                detail = (
                    source_errors[0]
                    if source_errors
                    else (
                        "GitHub source requested but not configured. "
                        "Set GITHUB_TOKENS and DATABASE_URL in .env"
                    )
                )
                raise RuntimeError(detail)
            if sources == {"manual"}:
                detail = (
                    source_errors[0]
                    if source_errors
                    else (
                        "Manual source requested but no enabled targets are stored. "
                        "Add relay/gateway URLs on the「自定义狩猎」page "
                        "(requires DATABASE_URL)."
                    )
                )
                raise RuntimeError(detail)
            # Keys may be set but every source threw (e.g. PG reject of NUL in
            # Shodan banners). Prefer the real failure over a "not configured"
            # message that sends operators hunting for missing env vars.
            if source_errors:
                joined = "; ".join(source_errors[:5])
                more = f" (+{len(source_errors) - 5} more)" if len(source_errors) > 5 else ""
                raise RuntimeError(
                    f"Discovery source(s) failed with no usable results: {joined}{more}"
                )
            raise RuntimeError(
                "No discovery source configured. Set FOFA_KEYS and/or SHODAN_KEYS "
                "(and optionally GITHUB_TOKENS + DATABASE_URL) in .env, "
                "or add manual targets for source=manual"
            )

        github_obs_metric = hits_by_source.get("github", len(cred_observations))
        log.info(
            "Discovery: raw_hits=%d unique_targets=%d credential_obs=%d (sources: %s spill=%s)",
            raw_hits_count,
            unique_targets_count,
            github_obs_metric,
            ", ".join(sources_used),
            discovery_spilled,
        )
        report_phase(
            f"发现完成 · hits={raw_hits_count} targets={unique_targets_count} "
            f"github_obs={github_obs_metric}"
        )
        await asyncio.to_thread(
            mark_phase,
            run_id,
            PHASE_EXTRACT,
            discovery_sources_done=list(sources_used),
            raw_hits=raw_hits_count,
        )

    # ------------------------------------------------------------------
    # Honeypot site cache — skip known bad hosts before any outbound HTTP
    # (probe / GPT / validate). Populated incrementally by prior scans.
    # ------------------------------------------------------------------
    from .candidate_store import (
        STAGE_GPT,
        STAGE_PROBER,
        STAGE_REGEX,
        load_candidates,
        spill_enabled,
        upsert_candidates,
        upsert_github_observations,
    )
    from .honeypot_store import (
        filter_credentials as filter_honeypot_credentials,
    )
    from .honeypot_store import (
        filter_targets as filter_honeypot_targets,
    )
    from .honeypot_store import (
        load_known_host_keys,
    )
    from .honeypot_store import (
        record_from_results as record_honeypot_sites,
    )

    use_spill = spill_enabled() and bool(run_id)
    # Only reload from PG when something was actually written this run.
    spilled_any = discovery_spilled or (skip_discovery and use_spill)

    known_honeypots: set[str] = set()
    if not skip_to_validate:
        known_honeypots = await asyncio.to_thread(load_known_host_keys)
        if known_honeypots:
            before_hp = len(targets)
            targets, hp_skipped = filter_honeypot_targets(targets, known_honeypots)
            if hp_skipped:
                log.info(
                    "Honeypot cache: skipped %d/%d target(s) (%d known sites)",
                    hp_skipped,
                    before_hp,
                    len(known_honeypots),
                )
                report_phase(
                    f"蜜罐缓存 · 跳过 {hp_skipped} 个已知站点 (库内 {len(known_honeypots)})"
                )

    # ------------------------------------------------------------------
    # Shared downstream pipeline (source-agnostic): extract -> validate
    # -> GPT recheck -> balance
    # ------------------------------------------------------------------
    if skip_to_validate:
        report_phase("恢复 · 跳过提取/探测/GPT")
        creds = await asyncio.to_thread(load_candidates, run_id) if use_spill else []
        observations = ObservationRegistry()
        for cred in creds:
            backend = (cred.backend or cred.source or "").lower()
            if "github" in backend:
                observations.observe(cred, ExtractionMethod.REGEX, (("github", "github"),))
            else:
                observations.observe(cred, ExtractionMethod.REGEX, (("unknown", "resume"),))
        target_by_alias: dict[str, DiscoveryTarget] = {}
        # Jump to validation below (probe/gpt blocks gated by skip_to_validate).
    else:
        report_phase("提取候选密钥")
        await asyncio.to_thread(mark_phase, run_id, PHASE_EXTRACT)

    # When spill holds full discovery hits, regex-extract page-by-page from PG
    # so body keys are not lost (slim hits in RAM may omit body).
    if not skip_to_validate and use_spill and discovery_spilled:
        from aipocket.services.discovery_store import iter_hits

        creds = []
        for page in iter_hits(run_id, batch_size=500):
            page_creds = extract_credentials(page)
            if page_creds:
                creds.extend(page_creds)
            del page
        log.info("Extract from spill pages: %d regex candidates", len(creds))
    elif not skip_to_validate:
        creds = extract_credentials(all_hits)
    if not skip_to_validate:
        observations = ObservationRegistry()
        # Map a credential back to its discovery target for per-query funnel metrics.
        # regex-extracted creds carry the RAW hit host (e.g. "1.2.3.4:8080"), while
        # probed/GPT creds carry the canonical identity url ("https://1.2.3.4:8080").
        # Index BOTH the canonical url and every raw alias (host/ip/link) so no
        # credential silently misses its target and drops out of the funnel counts.
        target_by_alias = {}
        for target in targets:
            for alias in (target.identity.url, *target.aliases):
                target_by_alias.setdefault(alias, target)

    def observe_credentials(method: ExtractionMethod, credentials: list[Credential]) -> None:
        for credential in credentials:
            target = (
                target_by_alias.get(credential.host)
                or target_by_alias.get(credential.apiurl)
                or target_by_alias.get(credential.leak_host)
            )
            # Always register an observation so post-validation metrics can look
            # the credential up. Missing discovery linkage is attributed to a
            # synthetic provenance bucket rather than silently dropping the row
            # (which later broke the active_requests == outcomes invariant).
            provenance = (
                target.provenance_pairs
                if target is not None and target.provenance_pairs
                else (("unknown", "unattributed"),)
            )
            observations.observe(credential, method, provenance)

    def record_credentials(metric: str, credentials: list[Credential]) -> None:
        for credential in credentials:
            observation = observations.get(credential)
            if observation is not None:
                query_metrics.observe(metric, observation)

    if not skip_to_validate:
        observe_credentials(ExtractionMethod.REGEX, creds)
        record_credentials("candidates", creds)
        seen = {_credential_identity(c) for c in creds}
        log.info("Extracted %d candidate credentials (regex)", len(creds))
    else:
        seen = {_credential_identity(c) for c in creds}

    # GitHub credential lane: observations already carry CredentialBundle.
    # Never route these through host prober / GPT page extract.
    if not skip_to_validate and cred_observations:
        github_creds = [obs.credential for obs in cred_observations]
        for obs in cred_observations:
            provenance = (("github", obs.query_id or obs.pack_id or "github"),)
            observations.observe(obs.credential, ExtractionMethod.REGEX, provenance)
        seen = _merge_credentials(creds, github_creds, seen)
        record_credentials("candidates", github_creds)
        log.info(
            "GitHub credential observations: +%d (total candidates=%d)",
            len(github_creds),
            len(creds),
        )

    # ------------------------------------------------------------------
    # Early credential filtering — reject known bad formats BEFORE
    # wasting HTTP calls on validation. This catches:
    # - Non-LLM key formats (Google OAuth, AWS, hex32 tokens)
    # - Too-short keys
    # - Obvious noise patterns
    # ------------------------------------------------------------------
    from .honeypot import pre_filter_credentials

    if not skip_to_validate:
        pre_filtered_count = len(creds)
        creds = pre_filter_credentials(creds)
        creds = filter_credentials_by_policy(creds, stage="scanner-prefilter")
        format_rejected = pre_filtered_count - len(creds)
        hp_cred_skipped = 0
        if known_honeypots:
            before_hp_creds = len(creds)
            creds, hp_cred_skipped = filter_honeypot_credentials(creds, known_honeypots)
            if hp_cred_skipped:
                log.info(
                    "Honeypot cache: dropped %d credential(s) on known sites (%d → %d)",
                    hp_cred_skipped,
                    before_hp_creds,
                    len(creds),
                )
        record_credentials("prefilter_survivors", creds)
        log.info(
            "Pre-filter: %d → %d credentials (rejected format=%d honeypot-host=%d)",
            pre_filtered_count,
            len(creds),
            format_rejected,
            hp_cred_skipped,
        )

        # Spill only prefilter survivors so DB never holds noise keys.
        # GitHub keeps full CredentialBundle + evidence via upsert_github_observations.
        # (Streaming GitHub spill may have already written survivors.)
        if use_spill and creds:
            survivor_ids = {_credential_identity(c) for c in creds}
            if cred_observations:
                gh_survivors = [
                    obs
                    for obs in cred_observations
                    if _credential_identity(obs.credential) in survivor_ids
                ]
                if gh_survivors:
                    await asyncio.to_thread(upsert_github_observations, run_id, gh_survivors)
                    spilled_any = True
            non_github = [
                c
                for c in creds
                if _credential_identity(c) in survivor_ids
                and (c.backend or c.source or "").lower() != "github"
            ]
            if non_github:
                await asyncio.to_thread(
                    upsert_candidates,
                    run_id,
                    STAGE_REGEX,
                    non_github,
                    method=ExtractionMethod.REGEX.value,
                )
                spilled_any = True

    # Active probing — order high-signal targets first; the runner then applies
    # evidence gates and a per-target request budget before issuing requests.
    from aipocket.prober import probe_hosts

    probed_creds: list[Credential] = []
    if not skip_to_validate and settings.scan_prober:
        report_phase(f"主机探测 · {len(targets)} 个目标")
        # Sort: high-signal hosts first (have sk- / api_key / OPENAI / ANTHROPIC in banner/header)
        _SIGNAL_RE = re.compile(
            r"sk-[A-Za-z0-9_\-]{6,}|api[_-]?key|OPENAI|ANTHROPIC|authorization", re.I
        )

        def _has_signal(h: dict) -> bool:
            blob = (h.get("header", "") or "") + " " + (h.get("banner", "") or "")
            return bool(_SIGNAL_RE.search(blob))

        # Stable sort: high-signal first, rest after
        ordered_targets = sorted(
            targets, key=lambda target: 0 if _has_signal(target.to_hit()) else 1
        )

        # Cross-run dedup: skip hosts already probed in a previous run.
        # Full discovery still uses TTL probe cache (verification_policy=ttl).
        before_probe = len(ordered_targets)
        if not scan_policy.force_revalidate:
            ordered_targets = await dedup.filter_unseen_targets("probe", ordered_targets)
        if before_probe != len(ordered_targets):
            log.info(
                "Dedup: host probe %d → %d (skipped %d seen)",
                before_probe,
                len(ordered_targets),
                before_probe - len(ordered_targets),
            )
        high_count = sum(1 for target in ordered_targets if _has_signal(target.to_hit()))

        log.info(
            "Probing %d hosts (high-signal=%d, low-signal=%d)",
            len(ordered_targets),
            high_count,
            len(ordered_targets) - high_count,
        )

        # Reviewed safe products are an execution allowlist only. Product routing
        # remains based on each target's own hints/fingerprint evidence.
        from .hunt_recipes import products_with_active_coverage_from_cves
        from .queries import load_cves

        try:
            safe_products = products_with_active_coverage_from_cves(load_cves())
        except Exception as e:  # noqa: BLE001 — advisory gating must never block a scan
            log.warning("advisory hunt-recipe gating skipped (%s)", type(e).__name__)
            safe_products = frozenset()
        log.info(
            "Advisory safe-recipe allowlist: %d product(s) enabled",
            len(safe_products),
        )

        await asyncio.to_thread(mark_phase, run_id, PHASE_PROBE, targets=len(ordered_targets))
        probe_report = await probe_hosts(ordered_targets, safe_products)
        if probe_report.spilled:
            spilled_any = True
            # Reload prober candidates from PG (not held across batches in RAM).
            probed_creds = await asyncio.to_thread(load_candidates, run_id, stages=[STAGE_PROBER])
            log.info(
                "Prober spilled path: reloaded %d candidates from scan_candidates (reported=%d)",
                len(probed_creds),
                probe_report.credential_count,
            )
        else:
            probed_creds = list(probe_report.credentials)
        target_by_identity = {target.identity.identity_hash: target for target in ordered_targets}
        outcome_counts: dict[str, int] = {}
        for outcome in probe_report.outcomes:
            label = outcome.status.value
            outcome_counts[label] = outcome_counts.get(label, 0) + 1
            target = target_by_identity.get(outcome.identity_hash)
            if target is None:
                continue
            if outcome.request_count > 0:
                await dedup.mark_target("probe", target)
            elif scan_policy.force_revalidate:
                await dedup.clear_target("probe", target)
        log.info(
            "Prober outcomes: attempted=%d rejected_by_evidence=%d skipped=%d failed=%d",
            outcome_counts.get("attempted", 0),
            outcome_counts.get("rejected_by_evidence", 0),
            outcome_counts.get("skipped", 0),
            outcome_counts.get("failed", 0),
        )
        # Vuln-class observability: why IDOR/weak_password didn't run, confirmed POCs, etc.
        if probe_report.findings or probe_report.node_outcomes:
            node_status: dict[str, int] = {}
            for node in probe_report.node_outcomes:
                node_status[node.status.value] = node_status.get(node.status.value, 0) + 1
            by_class: dict[str, int] = {}
            for finding in probe_report.findings:
                if finding.confirmed:
                    key = finding.vuln_class.value
                    by_class[key] = by_class.get(key, 0) + 1
            log.info(
                "Prober capability: findings=%d confirmed_by_class=%s node_status=%s",
                len(probe_report.findings),
                by_class or "{}",
                node_status or "{}",
            )
            # Persist the full findings + node outcomes so non-credential proofs
            # (SSRF/SQLi/RCE/IDOR, CVE evidence, skip reasons) survive the scan.
            if run_dir:
                from .writer import write_probe_findings

                write_probe_findings(
                    list(probe_report.findings),
                    list(probe_report.node_outcomes),
                    run_dir,
                )

        observe_credentials(ExtractionMethod.PROBER, probed_creds)
        seen = _merge_credentials(creds, probed_creds, seen)
        record_credentials("candidates", probed_creds)
        record_credentials("prefilter_survivors", probed_creds)
        log.info("After active probing: %d candidate credentials", len(creds))
        # When spill is on, drop the large probed list after merge+metrics so
        # peak RSS can fall before GPT/validate; validate reloads from PG.
        if use_spill and probe_report.spilled:
            probed_creds = []

    from .analyzer import GPTExtractionReport, extract_with_gpt

    if not skip_to_validate:
        await asyncio.to_thread(mark_phase, run_id, PHASE_GPT)
        before_gpt = len(_prioritize_targets_for_gpt(targets))
        # Full discovery still respects GPT host TTL cache unless verification is fresh.
        sampled_targets = (
            await _select_gpt_targets(targets, dedup)
            if not scan_policy.force_revalidate
            else _prioritize_targets_for_gpt(targets)[:5000]
        )
        sampled = []
        target_by_entry_id: dict[str, DiscoveryTarget] = {}
        for target in sampled_targets:
            entry_id = target.identity.identity_hash
            hit = target.to_hit()
            hit["_entry_id"] = entry_id
            sampled.append(hit)
            target_by_entry_id[entry_id] = target
        # GPT path must reload full body/banner/header from PG when discovery spilled (C3).
        if sampled and use_spill and discovery_spilled:
            from aipocket.services.discovery_store import load_hits_by_entry_ids

            full_by_id = await asyncio.to_thread(
                load_hits_by_entry_ids,
                run_id,
                [str(h.get("_entry_id") or "") for h in sampled],
            )
            reloaded: list[dict] = []
            for hit in sampled:
                eid = str(hit.get("_entry_id") or "")
                full = full_by_id.get(eid)
                if full is not None:
                    full = dict(full)
                    full["_entry_id"] = eid
                    reloaded.append(full)
                else:
                    reloaded.append(hit)
            sampled = reloaded
            log.info("GPT loaded %d full hits from scan_discovery_hits", len(full_by_id))
        if before_gpt != len(sampled):
            log.info(
                "Dedup: GPT candidates %d → %d selected unseen hosts",
                before_gpt,
                len(sampled),
            )
        fofa_sampled = sum(1 for h in sampled if "fofa" in str(h.get("_source", "")).split(","))
        shodan_sampled = sum(1 for h in sampled if "shodan" in str(h.get("_source", "")).split(","))
        log.info(
            "GPT sampling: %d hits (fofa=%d, shodan=%d)",
            len(sampled),
            fofa_sampled,
            shodan_sampled,
        )
        if sampled:
            report_phase(f"GPT 提取 · 采样 {len(sampled)} 个目标")
        gpt_report = await extract_with_gpt(sampled)
    else:
        sampled = []
        target_by_entry_id = {}
        gpt_report = GPTExtractionReport((), frozenset(), frozenset())
    for entry_id in gpt_report.successful_entry_ids:
        target = target_by_entry_id.get(entry_id)
        if target is not None:
            await dedup.mark_target("gpt", target)
    for entry_id in gpt_report.failed_entry_ids:
        if (
            scan_policy.force_revalidate
            and (target := target_by_entry_id.get(entry_id)) is not None
        ):
            await dedup.clear_target("gpt", target)
    gpt_creds = list(gpt_report.credentials)
    gpt_creds = filter_credentials_by_policy(gpt_creds, stage="gpt-prefilter")
    if gpt_creds:
        observe_credentials(ExtractionMethod.GPT, gpt_creds)
        seen = _merge_credentials(creds, gpt_creds, seen)
        record_credentials("candidates", gpt_creds)
        record_credentials("prefilter_survivors", gpt_creds)
        log.info("After GPT enrichment: %d candidate credentials", len(creds))
        if use_spill:
            await asyncio.to_thread(
                upsert_candidates,
                run_id,
                STAGE_GPT,
                gpt_creds,
                method=ExtractionMethod.GPT.value,
            )
            spilled_any = True

    # When PG spill wrote rows this run (or resume), rebuild from the store so
    # we do not depend on the in-memory merge after multi-batch prober.
    if use_spill and (spilled_any or skip_to_validate or skip_discovery):
        reloaded = await asyncio.to_thread(load_candidates, run_id)
        if reloaded:
            # Re-register observations for any rows that were not observed above
            # (e.g. prober spilled-only path after we cleared probed_creds).
            for cred in reloaded:
                if observations.get(cred) is None:
                    backend = (cred.backend or cred.source or "").lower()
                    if "github" in backend:
                        observations.observe(
                            cred,
                            ExtractionMethod.REGEX,
                            (("github", "github"),),
                        )
                    else:
                        observe_credentials(ExtractionMethod.PROBER, [cred])
            creds = reloaded
            seen = {_credential_identity(c) for c in creds}
            log.info("Candidate store reload for validate: %d credentials", len(creds))

    if not creds and not (use_spill and skip_to_validate):
        log.info("No credentials found — writing empty scan results")
        finished = datetime.now(UTC).isoformat()
        total_http, ledger_complete, ledger_reason = _complete_ledger(ledger)
        metrics_version = 3 if ledger_complete else 2
        empty_meta = {
            "started_at": started,
            "finished_at": finished,
            "state": "finished",
            "sources": sources_used,
            "hits_by_source": hits_by_source,
            "raw_hits": raw_hits_count,
            "unique_targets": unique_targets_count,
            "total_hosts": len(targets),
            "total_credentials": 0,
            "candidates": 0,
            "active_requests": 0,
            "total_active_http_requests": total_http,
            "ledger_complete": ledger_complete,
            "ledger_incomplete_reason": ledger_reason,
            "final_verified": 0,
            "suspicious": 0,
            "high_value_final": 0,
            "metrics_version": metrics_version,
            "scan_mode": mode,
            "queries_used": queries_used,
        }
        if run_dir:
            write_scan_metadata(empty_meta, run_dir)
            write_valid_results([], run_dir)
        if settings.pg_enabled:
            from .writer import persist_run_pg

            await asyncio.to_thread(
                persist_run_pg,
                ledger.run_id if ledger is not None else run_dir.name if run_dir else "",
                empty_meta,
                [],
                [],
                _snapshot_query_metrics(query_metrics, ledger, ledger_complete=ledger_complete),
            )
        return ScanRunResult(
            started_at=started,
            finished_at=finished,
            sources=sources_used,
            hits_by_source=hits_by_source,
            total_hosts=len(targets),
            raw_hits_count=raw_hits_count,
            unique_targets=unique_targets_count,
            total_credentials=0,
            total_valid=0,
            total_active_http_requests=total_http,
            ledger_complete=ledger_complete,
            ledger_incomplete_reason=ledger_reason,
            queries_used=queries_used,
            results=[],
            scan_mode=mode,
            raw_hits=_trim_hits(all_hits),
        )

    # Cross-run dedup: reuse valid results, skip cached failure outcomes, and
    # validate remaining credentials. Full discovery uses TTL verification by
    # default (not force-fresh); only verification_policy=fresh bypasses cache.
    await asyncio.to_thread(mark_phase, run_id, PHASE_VALIDATE, candidates=len(creds))
    cached_results: list[ValidationResult] = []
    to_validate: list[Credential] = []
    failure_counts = {"rejected": 0, "transient": 0}
    # Prefer paged validate_from_store when spill is on (bounded workers + resume).
    use_store_validate = use_spill and (spilled_any or skip_to_validate or skip_discovery)

    creds_meta_count = len(creds)

    if use_store_validate:
        from aipocket.core.observations import credential_identity
        from aipocket.services.candidate_store import (
            count_candidates,
            iter_candidate_pages,
            load_validation_results,
        )

        from .validator import validate_from_store

        def _ident(credential: Credential) -> str:
            i = credential_identity(credential)
            return f"{i.secret_fingerprint}:{i.endpoint}"

        # Page candidates for Redis dedup classification. Cache hits stay in RAM
        # (small); failures are skipped via skip_ids so store path does not re-probe.
        skip_ids: set[str] = set()
        n_to_validate = 0
        for page in iter_candidate_pages(run_id, prefilter_ok_only=True):
            for credential in page:
                ident = _ident(credential)
                if scan_policy.force_revalidate:
                    n_to_validate += 1
                    continue
                hit = await dedup.get_cached_valid(credential)
                if hit is not None:
                    cached_results.append(hit)
                    skip_ids.add(ident)
                    continue
                failure = await dedup.get_failure_outcome(credential)
                if failure is not None:
                    failure_counts[failure] += 1
                    skip_ids.add(ident)
                    continue
                n_to_validate += 1
            del page

        log.info(
            "Dedup: store path → %d cached / ~%d to validate / rejected=%d / transient=%d",
            len(cached_results),
            n_to_validate,
            failure_counts["rejected"],
            failure_counts["transient"],
        )
        # active_requests metric: approximate with n_to_validate (paged, no full list).
        log.info(
            "Validating via store (concurrency=%d batch_size=%d)...",
            settings.validate_concurrency,
            settings.validate_batch_size,
        )
        report_phase(f"验证 credentials · ~{n_to_validate} 待验 (缓存命中 {len(cached_results)})")
        to_validate = []  # store path does not keep the full work list in RAM
        # record active_requests on query metrics with count only via a synthetic observe
        # when we lack the list; funnel still gets total_active_http from ledger.

        fresh_results = await validate_from_store(
            run_id,
            skip_identities=None if scan_policy.force_revalidate else skip_ids,
            attribution=None,
            valid_only_return=False,
            resume=not scan_policy.force_revalidate,
        )
        # On resume, include rows already written before the kill.
        if skip_to_validate:
            prior = await asyncio.to_thread(load_validation_results, run_id)
            seen_ids = {_ident(r.credential) for r in fresh_results}
            for r in prior:
                kid = _ident(r.credential)
                if kid not in seen_ids:
                    fresh_results.append(r)
                    seen_ids.add(kid)
        results = cached_results + fresh_results
        store_n = await asyncio.to_thread(count_candidates, run_id)
        if store_n:
            creds_meta_count = store_n
        # For outcome aggregation / active_requests metadata.
        to_validate = [r.credential for r in fresh_results]
        record_credentials("active_requests", to_validate)
    else:
        for credential in creds:
            if scan_policy.force_revalidate:
                to_validate.append(credential)
                continue
            hit = await dedup.get_cached_valid(credential)
            if hit is not None:
                cached_results.append(hit)
                continue
            failure = await dedup.get_failure_outcome(credential)
            if failure is not None:
                failure_counts[failure] += 1
                continue
            to_validate.append(credential)
        log.info(
            "Dedup: %d creds → %d cached / %d to validate / rejected=%d / transient=%d",
            len(creds),
            len(cached_results),
            len(to_validate),
            failure_counts["rejected"],
            failure_counts["transient"],
        )
        record_credentials("active_requests", to_validate)

        log.info(
            "Validating %d credentials (concurrency=%d)...",
            len(to_validate),
            settings.validate_concurrency,
        )
        report_phase(f"验证 credentials · {len(to_validate)} 待验 (缓存命中 {len(cached_results)})")
        fresh_results = (
            await validate_all(
                to_validate,
                attribution=_credential_attribution(observations, to_validate, query_metadata),
            )
            if to_validate
            else []
        )
        if use_spill and fresh_results:
            from aipocket.services.candidate_store import upsert_validation_results

            await asyncio.to_thread(upsert_validation_results, run_id, fresh_results)
        results = cached_results + fresh_results
        creds_meta_count = len(creds)

    record_credentials("auth_confirmed", [result.credential for result in results if result.valid])
    await asyncio.to_thread(mark_phase, run_id, PHASE_FINALIZE, validated=len(results))

    # No-auth honeypot probe: for each host that has a valid result, send a
    # FORGED key. If it also validates, the endpoint ignores Authorization and
    # every key on it is fake. Runs once per host (not per key) to bound volume.
    from .validator import verify_no_auth

    no_auth_urls: set[str] = set()
    suspicious_urls: set[str] = set()
    valid_after_probe = [r for r in results if r.valid]
    if valid_after_probe:
        distinct_hosts = len({r.credential.host or r.credential.apiurl for r in valid_after_probe})
        log.info(
            "Probing %d host(s) with a forged key to detect no-auth honeypots...",
            distinct_hosts,
        )
        no_auth_urls, suspicious_urls = await verify_no_auth(
            results,
            attribution=_credential_attribution(
                observations,
                [result.credential for result in results],
                query_metadata,
            ),
        )

    # GPT recheck — disabled by default since honeypot filter catches the same
    # cases faster. Enable with GPT_RECHECK=true for extra verification.
    if settings.gpt_recheck:
        from .analyzer import recheck_all_with_gpt

        results = list(
            await recheck_all_with_gpt(
                results,
                attribution=_credential_attribution(
                    observations,
                    [result.credential for result in results],
                    query_metadata,
                ),
            )
        )

    from .finalizer import commit_final_results, finalize_results

    finalized = await finalize_results(
        results,
        dedup=dedup,
        no_auth_hosts=no_auth_urls,
        suspicious_hosts=suspicious_urls,
    )
    valid = finalized.final_verified

    # Persist newly confirmed honeypot hosts so the next scan skips them.
    try:
        await asyncio.to_thread(
            record_honeypot_sites,
            results,
            run_id=run_id,
            no_auth_hosts=no_auth_urls,
        )
    except Exception as e:  # noqa: BLE001 — cache write must never fail the scan
        log.warning("honeypot cache record skipped: %s", e)

    outcome_groups: dict[tuple[str, str, str, str, ErrorClass, int | None], int] = {}
    missing_observations = 0
    for result in fresh_results:
        observation = observations.get(result.credential)
        if observation is None:
            # Metrics-only fallback. Must still count every fresh result so
            # persist_run_pg's active_requests == sum(outcomes) invariant holds.
            # Common after official-endpoint routing when leak_host is empty.
            missing_observations += 1
            source, query = "unknown", "missing-observation"
        else:
            source, query = observation.primary_provenance
        provider = result.provider_info.provider
        error_class = classify_error(result.error, result.validation_state, result.status_code)
        key = (
            source,
            query,
            provider,
            result.validation_state,
            error_class,
            result.status_code,
        )
        outcome_groups[key] = outcome_groups.get(key, 0) + 1
    if missing_observations:
        log.warning(
            "%d fresh validation result(s) had no canonical observation; "
            "attributed to unknown/missing-observation (scan continues)",
            missing_observations,
        )
    validation_outcomes = [
        ValidationOutcomeAggregate(*key, count=count)
        for key, count in sorted(outcome_groups.items(), key=lambda item: repr(item[0]))
    ]
    method_counts: dict[str, int] = {}
    for observation in observations.observations:
        method_counts[observation.method.value] = method_counts.get(observation.method.value, 0) + 1
    observation_counts = [
        ExtractionMethodAggregate(method=method, count=count)  # type: ignore[arg-type]
        for method, count in sorted(method_counts.items())
    ]

    record_credentials("final_verified", [result.credential for result in valid])
    rejected_hosts = no_auth_urls - suspicious_urls
    record_credentials(
        "noauth_rejected",
        [
            result.credential
            for result in results
            if (result.credential.host or result.credential.apiurl) in rejected_hosts
        ],
    )
    suspicious = finalized.rate_limited_unconfirmed
    log.info(
        "Validation done: %d valid / %d total (%d suspicious quarantined)",
        len(valid),
        len(results),
        len(suspicious),
    )

    enrichable = [*valid, *suspicious]
    if enrichable:
        from .balance import enrich_results

        log.info(
            "Querying provider evidence for %d valid/suspicious credentials...", len(enrichable)
        )
        report_phase(f"查询余额与凭据证据 · {len(enrichable)} 个结果")
        await enrich_results(
            enrichable,
            dedup=dedup,
            use_cache=not scan_policy.force_balance,
            attribution=_credential_attribution(
                observations,
                [r.credential for r in enrichable],
                query_metadata,
            ),
        )
        log.info("Provider evidence enrichment done.")

    # Cache + persist high-value AFTER balance enrichment so saved records carry balance evidence.
    commit_report = await commit_final_results(valid, dedup=dedup)

    if run_dir:
        write_valid_results(valid, run_dir)
        if suspicious:
            write_suspicious_results(suspicious, run_dir)

    total_http, ledger_complete, ledger_incomplete_reason = _complete_ledger(ledger)
    metrics_version = 3 if ledger_complete else 2

    finished = datetime.now(UTC).isoformat()
    run_meta = {
        "started_at": started,
        "finished_at": finished,
        "state": "finished",
        "sources": sources_used,
        "hits_by_source": hits_by_source,
        "raw_hits": raw_hits_count,
        "unique_targets": unique_targets_count,
        "candidates": creds_meta_count,
        "active_requests": len(to_validate) if to_validate else len(fresh_results),
        "total_active_http_requests": total_http,
        "ledger_complete": ledger_complete,
        "ledger_incomplete_reason": ledger_incomplete_reason,
        "final_verified": len(valid),
        "suspicious": len(suspicious),
        "high_value_final": commit_report.high_value_final,
        "metrics_version": metrics_version,
        "scan_mode": mode,
        "total_hosts": len(targets),
        "total_credentials": creds_meta_count,
        "queries_used": queries_used,
    }
    await asyncio.to_thread(mark_phase, run_id, PHASE_FINISHED)

    if run_dir:
        scan_path = write_scan_metadata(run_meta, run_dir)
        for result in results:
            append_scan_result(result, scan_path)

    # Persist the whole run (metadata + valid + suspicious) to PG in one
    # transaction — the source of truth when DATABASE_URL is set.
    # Offloaded to a worker thread: it's a synchronous write of (potentially)
    # hundreds of rows, and running it on the event loop blocks every other
    # async endpoint for the whole transaction.
    if settings.pg_enabled:
        from .writer import persist_run_pg

        await asyncio.to_thread(
            persist_run_pg,
            ledger.run_id if ledger is not None else run_dir.name if run_dir else "",
            run_meta,
            valid,
            suspicious,
            _snapshot_query_metrics(query_metrics, ledger, ledger_complete=ledger_complete),
            validation_outcomes,
            observation_counts,
            rejected=finalized.rejected,
        )

    return ScanRunResult(
        started_at=started,
        finished_at=finished,
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(targets),
        raw_hits_count=raw_hits_count,
        unique_targets=unique_targets_count,
        candidates=creds_meta_count,
        active_requests=len(to_validate) if to_validate else len(fresh_results),
        total_active_http_requests=total_http,
        ledger_complete=ledger_complete,
        ledger_incomplete_reason=ledger_incomplete_reason,
        final_verified=len(valid),
        suspicious=len(suspicious),
        high_value_final=commit_report.high_value_final,
        total_credentials=creds_meta_count,
        total_valid=len(valid),
        queries_used=queries_used,
        results=results,
        scan_mode=mode,
        raw_hits=_trim_hits(all_hits),
    )


def _fetch_fofa(
    max_queries: int | None,
    *,
    skip_direct: bool = False,
    run_id: str = "",
) -> tuple[list[dict], list[QueryUsage], int]:
    """Run the FOFA backend: build queries, paginate each, tag hits with _cve/_product.

    When PG spill is enabled and ``run_id`` is set, each page is upserted to
    ``scan_discovery_hits`` and only a slim signal payload is retained in RAM.
    Returns ``(hits_or_slim, queries_used, total_hit_count)``.
    """
    from aipocket.services.candidate_store import spill_enabled
    from aipocket.services.discovery_store import (
        entry_id_for_hit,
        slim_hit_for_target,
        upsert_hits,
    )

    queries = build_queries(skip_direct=skip_direct)
    planned = plan_queries(
        tuple(
            QueryCandidate(
                query=query["query"],
                lane=candidate_lane(query),
                stable_order=index,
            )
            for index, query in enumerate(queries)
        ),
        load_query_history("fofa"),
        PlannerConfig(
            max_queries=max_queries,
            exploration_ratio=settings.query_exploration_ratio,
            metrics_version=settings.planner_metrics_version,
        ),
    )
    selected = {candidate.query for candidate in planned}
    queries = [query for query in queries if query["query"] in selected]
    log.info("Built %d FOFA queries from CVE map", len(queries))

    use_spill = spill_enabled() and bool(run_id)
    all_hits: list[dict] = []
    total_count = 0
    queries_used: list[QueryUsage] = []

    def _tag_hits(hits: list[dict], q: dict) -> list[dict]:
        for h in hits:
            if isinstance(h, dict):
                h.setdefault("_source", "fofa")
                h.setdefault("_cve", q["cve_id"])
                h.setdefault("_product", q["product"])
                h.setdefault("_cves", q.get("advisory_ids", []))
                h.setdefault("_product_hints", q.get("product_hints", []))
                h.setdefault("_query_id", q["query"])
                h.setdefault("_entry_id", entry_id_for_hit(h))
                if "body=" in q["query"].lower():
                    h["_requires_content_refetch"] = True
        return hits

    with FofaClient() as fofa:
        try:
            info = fofa.info()
            if info:
                log.info(
                    "  FOFA keys=%d dead=%d remain_api_query=%s remain_api_data=%s",
                    info.get("n_keys"),
                    info.get("n_dead"),
                    info.get("total_remain_api_query"),
                    info.get("total_remain_api_data"),
                )
                for k in info.get("keys", [])[:5]:
                    log.info(
                        "    key %s vip=%s remain_api_query=%s fofa_point=%s",
                        k.get("_key_masked"),
                        k.get("vip_level"),
                        k.get("remain_api_query"),
                        k.get("fofa_point"),
                    )
                if len(info.get("keys", [])) > 5:
                    log.info("    … %d more keys", len(info["keys"]) - 5)
        except Exception:  # noqa: BLE001 - info is best-effort
            pass

        for i, q in enumerate(queries, 1):
            log.info("[FOFA %d/%d] %s | %s", i, len(queries), q["cve_id"], q["query"][:80])
            queries_used.append(QueryUsage(q["query"]))

            def _on_page(page_hits: list[dict], _q: dict = q) -> None:
                nonlocal total_count
                tagged = _tag_hits(page_hits, _q)
                if use_spill:
                    upsert_hits(run_id, "fofa", tagged)
                    all_hits.extend(slim_hit_for_target(h) for h in tagged)
                else:
                    all_hits.extend(tagged)
                total_count += len(tagged)

            hits = fofa.search(
                q["query"],
                pages=settings.fofa_max_pages,
                on_page=_on_page if use_spill else None,
                retain_results=not use_spill,
            )
            if not use_spill and hits:
                _tag_hits(hits, q)
                all_hits.extend(hits)
                total_count += len(hits)
            log.info(
                "  FOFA accumulated %d hits (retained_in_ram=%d spill=%s)",
                total_count,
                len(all_hits) if not use_spill else len(all_hits),
                use_spill,
            )
    log.info("FOFA total hits: %d (spill=%s)", total_count, use_spill)
    return all_hits, queries_used, total_count


def _fetch_shodan(
    max_queries: int | None,
    *,
    skip_direct: bool = False,
    run_id: str = "",
) -> tuple[list[dict], list[QueryUsage], int]:
    """Run the Shodan backend: build Shodan-syntax queries, paginate each.

    When PG spill is enabled, each page is upserted and only slim signal fields
    are retained in RAM. Returns ``(hits_or_slim, queries_used, total_hit_count)``.
    """
    from aipocket.clients.shodan import ShodanClient
    from aipocket.services.candidate_store import spill_enabled
    from aipocket.services.discovery_store import (
        entry_id_for_hit,
        slim_hit_for_target,
        upsert_hits,
    )

    from .shodan_queries import build_shodan_queries

    use_spill = spill_enabled() and bool(run_id)
    all_hits: list[dict] = []
    total_count = 0
    queries_used: list[QueryUsage] = []

    def _tag_hits(hits: list[dict], q: dict) -> list[dict]:
        for h in hits:
            if isinstance(h, dict):
                h.setdefault("_source", "shodan")
                h.setdefault("_cve", q["cve_id"])
                h.setdefault("_product", q["product"])
                h.setdefault("_cves", q.get("advisory_ids", []))
                h.setdefault("_product_hints", q.get("product_hints", []))
                h.setdefault("_query_id", q["query"])
                h.setdefault("_entry_id", entry_id_for_hit(h))
        return hits

    with ShodanClient() as shodan:
        queries = build_shodan_queries(
            skip_direct=skip_direct,
            count=shodan.count,
            max_pages=settings.shodan_max_pages,
            request_budget=settings.shodan_shard_host_budget,
            credit_budget=settings.shodan_credit_budget,
        )
        planned = plan_queries(
            tuple(
                QueryCandidate(
                    query=query["query"],
                    lane=candidate_lane(query),
                    stable_order=index,
                )
                for index, query in enumerate(queries)
            ),
            load_query_history("shodan"),
            PlannerConfig(
                max_queries=max_queries,
                exploration_ratio=settings.query_exploration_ratio,
                metrics_version=settings.planner_metrics_version,
            ),
        )
        selected = {candidate.query for candidate in planned}
        queries = [query for query in queries if query["query"] in selected]
        log.info("Built %d Shodan queries from CVE map", len(queries))

        try:
            info = shodan.info()
            if info:
                log.info(
                    "  Shodan keys=%d dead=%d total_query_credits=%s",
                    info.get("n_keys"),
                    info.get("n_dead"),
                    info.get("total_query_credits"),
                )
                for k in info.get("keys", []):
                    log.info(
                        "    key %s plan=%s query_credits=%s",
                        k.get("_key_masked"),
                        k.get("plan"),
                        k.get("query_credits"),
                    )
        except Exception:  # noqa: BLE001 - info is best-effort
            pass

        for i, q in enumerate(queries, 1):
            log.info("[SHODAN %d/%d] %s | %s", i, len(queries), q["cve_id"], q["query"][:80])

            # Credit-saving pre-filter: count() is FREE (no query credits). Only
            # skip when Shodan explicitly reports zero — a None (count endpoint
            # failed) MUST fall through to search so a transient error doesn't
            # silently drop a live query. Each skipped 0-hit query saves 1 credit
            # (page 1 of any filtered query is billed).
            total = shodan.count(q["query"])
            if total == 0:
                queries_used.append(QueryUsage(q["query"]))
                log.info("  shodan count=0, skipping (credit saved)")
                continue
            if total is None:
                log.info("  shodan count unknown, proceeding")
            else:
                log.info("  shodan count=%s", total)

            queries_used.append(QueryUsage(q["query"], credits=1))

            def _on_page(page_hits: list[dict], _q: dict = q) -> None:
                nonlocal total_count
                tagged = _tag_hits(page_hits, _q)
                if use_spill:
                    upsert_hits(run_id, "shodan", tagged)
                    all_hits.extend(slim_hit_for_target(h) for h in tagged)
                else:
                    all_hits.extend(tagged)
                total_count += len(tagged)

            hits = shodan.search(
                q["query"],
                pages=settings.shodan_max_pages,
                on_page=_on_page if use_spill else None,
                retain_results=not use_spill,
            )
            if not use_spill and hits:
                _tag_hits(hits, q)
                all_hits.extend(hits)
                total_count += len(hits)
            log.info(
                "  Shodan accumulated %d hits (retained_in_ram=%d spill=%s)",
                total_count,
                len(all_hits),
                use_spill,
            )
    log.info("Shodan total hits: %d (spill=%s)", total_count, use_spill)
    return all_hits, queries_used, total_count


def _prioritize_targets_for_gpt(targets: list[DiscoveryTarget]) -> list[DiscoveryTarget]:
    """Order GPT candidates without applying the per-run limit."""
    tier_key: list[DiscoveryTarget] = []
    tier_shodan: list[DiscoveryTarget] = []
    tier_rest: list[DiscoveryTarget] = []

    for target in targets:
        hit = target.to_hit()
        blob = (hit.get("header", "") or "") + " " + (hit.get("banner", "") or "")
        if "shodan" in target.sources:
            blob += " " + (hit.get("cert", "") or "")
        if _SK_PATTERN.search(blob):
            tier_key.append(target)
        elif "shodan" in target.sources and (hit.get("banner") or hit.get("header")):
            tier_shodan.append(target)
        elif hit.get("header") or hit.get("banner") or hit.get("body"):
            tier_rest.append(target)
    return tier_key + tier_shodan + tier_rest


async def _select_gpt_targets(
    targets: list[DiscoveryTarget], dedup: DedupStore, limit: int = 5000
) -> list[DiscoveryTarget]:
    prioritized = _prioritize_targets_for_gpt(targets)
    unseen = await dedup.filter_unseen_targets("gpt", prioritized)
    return unseen[:limit]


def _sample_hits_for_gpt(hits: list[dict], limit: int = 5000) -> list[dict]:
    """Compatibility for one-off scripts: canonicalize, prioritize, then limit."""
    targets = _prioritize_targets_for_gpt(canonicalize_hits(hits))
    return [target.to_hit() for target in targets[:limit]]


def _trim_hits(hits: list[dict], limit: int = 500) -> list[dict]:
    if len(hits) <= limit:
        return hits
    return hits[:limit]
