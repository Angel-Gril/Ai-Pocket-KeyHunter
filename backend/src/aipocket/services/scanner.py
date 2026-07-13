from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from aipocket.clients.fofa import FofaClient
from aipocket.core.config import settings
from aipocket.core.metrics import QueryUsage
from aipocket.core.models import Credential, ScanRunResult, ValidationResult
from aipocket.core.targets import DiscoveryTarget, canonicalize_hits

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


async def run_scan(
    max_queries: int | None = None,
    run_dir: Path | None = None,
    *,
    skip_direct: bool = False,
    sources: set[str] | None = None,
) -> ScanRunResult:
    started = datetime.now(UTC).isoformat()

    # Stamp the run dir so GPT debug/failed-batch dumps land inside it.
    from . import analyzer as _analyzer

    _analyzer.set_run_dir(run_dir)

    # Propagate the run_id to deep write paths (high_value_writer.try_save) via a
    # ContextVar — set here, read there — instead of threading it through every
    # signature. The value is run_dir.name (the run_YYYY_… string), matching the
    # `runs.run_id` primary key.
    from aipocket.core.db import current_run_id

    run_id = run_dir.name if run_dir else None
    token = current_run_id.set(run_id)

    # Cross-run dedup store (Redis-backed; degrades to no-op if unavailable).
    dedup = await get_dedup_store()

    try:
        return await _run_scan_inner(
            max_queries,
            run_dir,
            skip_direct=skip_direct,
            started=started,
            dedup=dedup,
            sources=sources,
        )
    finally:
        await dedup.close()
        current_run_id.reset(token)


async def _run_scan_inner(
    max_queries: int | None,
    run_dir: Path | None,
    *,
    skip_direct: bool,
    started: str,
    dedup: DedupStore,
    sources: set[str] | None = None,
) -> ScanRunResult:

    all_hits: list[dict] = []
    queries_used: list[str] = []
    sources_used: list[str] = []
    hits_by_source: dict[str, int] = {}
    query_metrics = QueryMetricsCollector()

    # ------------------------------------------------------------------
    # Source fetching — run FOFA and Shodan in PARALLEL via threads
    # (both use synchronous httpx clients internally).
    #
    # We submit both to the pool, then AWAIT each via run_in_executor
    # instead of calling future.result() synchronously. future.result()
    # blocks the event-loop thread for the entire fetch (minutes), which
    # freezes every async endpoint — /api/scan/stop won't respond and the
    # SSE/polling log streams stall, even though logs keep flowing to the
    # container's stdout. Awaiting keeps the loop schedulable.
    # ------------------------------------------------------------------
    import concurrent.futures
    import functools

    fofa_hits: list[dict] = []
    shodan_hits: list[dict] = []

    # `sources` (when given) restricts which discovery backends run this scan —
    # e.g. the web UI's single-source mode. None means "every configured source".
    want_fofa = sources is None or "fofa" in sources
    want_shodan = sources is None or "shodan" in sources

    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        # run_in_executor returns an asyncio.Future (awaitable, loop-aware),
        # not a concurrent.futures.Future — so the loop stays schedulable while
        # the fetch threads run.
        fofa_future: asyncio.Future | None = None
        shodan_future: asyncio.Future | None = None

        if want_fofa and settings.keys:
            sources_used.append("fofa")
            fofa_future = loop.run_in_executor(
                pool, functools.partial(_fetch_fofa, max_queries, skip_direct=skip_direct)
            )
        elif want_fofa:
            log.info("FOFA keys not configured — skipping FOFA source")

        if want_shodan and settings.shodan_key_list:
            sources_used.append("shodan")
            shodan_future = loop.run_in_executor(
                pool, functools.partial(_fetch_shodan, max_queries, skip_direct=skip_direct)
            )
        elif want_shodan:
            log.info("Shodan keys not configured — skipping Shodan source")

        for name, future in (("fofa", fofa_future), ("shodan", shodan_future)):
            if future is None:
                continue
            try:
                hits, used_queries = await future
                for usage in used_queries:
                    query_metrics.increment(name, usage.query, query_credits=usage.credits)
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_source", name)
                if name == "fofa":
                    fofa_hits = hits
                else:
                    shodan_hits = hits
                queries_used.extend(usage.query for usage in used_queries)
            except Exception as e:
                log.error("Source %s failed: %s", name, e)

    all_hits = fofa_hits + shodan_hits
    targets = canonicalize_hits(all_hits)
    for hit in all_hits:
        source = str(hit.get("_source", ""))
        query = str(hit.get("_query_id", ""))
        if source and query:
            query_metrics.increment(source, query, raw_hits=1)
    for target in targets:
        for source, query in target.provenance_pairs:
            query_metrics.increment(source, query, unique_targets=1)
    target_hits = [target.to_hit() for target in targets]
    hits_by_source["fofa"] = len(fofa_hits)
    hits_by_source["shodan"] = len(shodan_hits)

    if not sources_used:
        raise RuntimeError(
            "No discovery source configured. Set FOFA_KEYS and/or SHODAN_KEYS in .env"
        )

    log.info(
        "Discovery: raw_hits=%d unique_targets=%d (sources: %s)",
        len(all_hits),
        len(targets),
        ", ".join(sources_used),
    )

    # ------------------------------------------------------------------
    # Shared downstream pipeline (source-agnostic): extract -> validate
    # -> GPT recheck -> balance
    # ------------------------------------------------------------------
    creds = extract_credentials(all_hits)
    # Map a credential back to its discovery target for per-query funnel metrics.
    # regex-extracted creds carry the RAW hit host (e.g. "1.2.3.4:8080"), while
    # probed/GPT creds carry the canonical identity url ("https://1.2.3.4:8080").
    # Index BOTH the canonical url and every raw alias (host/ip/link) so no
    # credential silently misses its target and drops out of the funnel counts.
    target_by_alias: dict[str, DiscoveryTarget] = {}
    for target in targets:
        for alias in (target.identity.url, *target.aliases):
            target_by_alias.setdefault(alias, target)

    def record_credentials(metric: str, credentials: list[Credential]) -> None:
        for credential in credentials:
            target = (
                target_by_alias.get(credential.host)
                or target_by_alias.get(credential.apiurl)
                or target_by_alias.get(credential.leak_host)
            )
            if target is None:
                continue
            for source, query in target.provenance_pairs:
                query_metrics.increment(source, query, **{metric: 1})

    record_credentials("candidates", creds)
    seen = {_credential_identity(c) for c in creds}
    log.info("Extracted %d candidate credentials (regex)", len(creds))

    # ------------------------------------------------------------------
    # Early credential filtering — reject known bad formats BEFORE
    # wasting HTTP calls on validation. This catches:
    # - Non-LLM key formats (Google OAuth, AWS, hex32 tokens)
    # - Too-short keys
    # - Obvious noise patterns
    # ------------------------------------------------------------------
    from .honeypot import pre_filter_credentials

    pre_filtered_count = len(creds)
    creds = pre_filter_credentials(creds)
    log.info(
        "Pre-filter: %d → %d credentials (rejected %d bad formats)",
        pre_filtered_count,
        len(creds),
        pre_filtered_count - len(creds),
    )

    # Active probing — order high-signal targets first; the runner then applies
    # evidence gates and a per-target request budget before issuing requests.
    from aipocket.prober import probe_hosts

    probed_creds: list[Credential] = []
    if settings.scan_prober:
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
        before_probe = len(ordered_targets)
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

        probe_report = await probe_hosts(ordered_targets, safe_products)
        probed_creds = list(probe_report.credentials)
        target_by_identity = {
            target.identity.identity_hash: target for target in ordered_targets
        }
        outcome_counts: dict[str, int] = {}
        for outcome in probe_report.outcomes:
            label = outcome.status.value
            outcome_counts[label] = outcome_counts.get(label, 0) + 1
            if outcome.request_count <= 0:
                continue
            target = target_by_identity.get(outcome.identity_hash)
            if target is not None:
                await dedup.mark_target("probe", target)
        log.info(
            "Prober outcomes: attempted=%d rejected_by_evidence=%d skipped=%d failed=%d",
            outcome_counts.get("attempted", 0),
            outcome_counts.get("rejected_by_evidence", 0),
            outcome_counts.get("skipped", 0),
            outcome_counts.get("failed", 0),
        )
        seen = _merge_credentials(creds, probed_creds, seen)
        log.info("After active probing: %d candidate credentials", len(creds))

    from .analyzer import extract_with_gpt

    before_gpt = len(_prioritize_targets_for_gpt(targets))
    sampled_targets = await _select_gpt_targets(targets, dedup)
    sampled = []
    target_by_entry_id: dict[str, DiscoveryTarget] = {}
    for target in sampled_targets:
        entry_id = target.identity.identity_hash
        hit = target.to_hit()
        hit["_entry_id"] = entry_id
        sampled.append(hit)
        target_by_entry_id[entry_id] = target
    if before_gpt != len(sampled):
        log.info(
            "Dedup: GPT candidates %d → %d selected unseen hosts",
            before_gpt,
            len(sampled),
        )
    fofa_sampled = sum(1 for h in sampled if "fofa" in str(h.get("_source", "")).split(","))
    shodan_sampled = sum(
        1 for h in sampled if "shodan" in str(h.get("_source", "")).split(",")
    )
    log.info(
        "GPT sampling: %d hits (fofa=%d, shodan=%d)",
        len(sampled),
        fofa_sampled,
        shodan_sampled,
    )
    gpt_report = await extract_with_gpt(sampled)
    for entry_id in gpt_report.successful_entry_ids:
        target = target_by_entry_id.get(entry_id)
        if target is not None:
            await dedup.mark_target("gpt", target)
    gpt_creds = list(gpt_report.credentials)
    if gpt_creds:
        seen = _merge_credentials(creds, gpt_creds, seen)
        log.info("After GPT enrichment: %d candidate credentials", len(creds))

    if not creds:
        log.info("No credentials found — writing empty scan results")
        finished = datetime.now(UTC).isoformat()
        empty_meta = {
            "started_at": started,
            "finished_at": finished,
            "state": "finished",
            "sources": sources_used,
            "hits_by_source": hits_by_source,
            "raw_hits": len(all_hits),
            "unique_targets": len(targets),
            "total_hosts": len(targets),
            "total_credentials": 0,
            "candidates": 0,
            "active_requests": 0,
            "final_verified": 0,
            "suspicious": 0,
            "high_value_final": 0,
            "queries_used": queries_used,
        }
        if run_dir:
            write_scan_metadata(empty_meta, run_dir)
            write_valid_results([], run_dir)
            if settings.pg_enabled:
                from .writer import persist_run_pg

                await asyncio.to_thread(
                    persist_run_pg,
                    run_dir.name,
                    empty_meta,
                    [],
                    [],
                    query_metrics.snapshot(),
                )
        return ScanRunResult(
            started_at=started,
            finished_at=finished,
            sources=sources_used,
            hits_by_source=hits_by_source,
            total_hosts=len(targets),
            raw_hits_count=len(all_hits),
            unique_targets=len(targets),
            total_credentials=0,
            total_valid=0,
            queries_used=queries_used,
            results=[],
            raw_hits=_trim_hits(all_hits),
        )

    # Cross-run dedup: reuse valid results, skip cached failure outcomes, and
    # validate every remaining canonical credential freshly.
    cached_results: list[ValidationResult] = []
    to_validate: list[Credential] = []
    failure_counts = {"rejected": 0, "transient": 0}
    for credential in creds:
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
    fresh_results: list[ValidationResult] = await validate_all(to_validate) if to_validate else []
    results: list[ValidationResult] = cached_results + fresh_results
    record_credentials("auth_confirmed", [result.credential for result in results if result.valid])

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
        no_auth_urls, suspicious_urls = await verify_no_auth(results)

    # GPT recheck — disabled by default since honeypot filter catches the same
    # cases faster. Enable with GPT_RECHECK=true for extra verification.
    if settings.gpt_recheck:
        from .analyzer import recheck_all_with_gpt

        results = list(await recheck_all_with_gpt(results))

    from .finalizer import commit_final_results, finalize_results

    finalized = await finalize_results(
        results,
        dedup=dedup,
        no_auth_hosts=no_auth_urls,
        suspicious_hosts=suspicious_urls,
    )
    valid = finalized.final_verified
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

    if valid:
        from .balance import enrich_results

        log.info("Querying balance for %d valid credentials...", len(valid))
        # Enrich only non-suspicious valid results. enrich_results mutates each
        # ValidationResult in place and returns the same objects, so the changes
        # are visible in `results` (and therefore `valid`/`suspicious`) directly.
        enrichable = [r for r in results if r.valid and not r.suspicious]
        await enrich_results(enrichable, dedup=dedup)
        log.info("Balance enrichment done.")

    # Cache + persist high-value AFTER balance enrichment so the saved record
    # carries balance/tier evidence (not the pre-enrichment snapshot).
    await commit_final_results(valid, dedup=dedup)

    # Write valid_*.jsonl + suspicious_*.jsonl after honeypot + balance enrichment
    if run_dir:
        write_valid_results(valid, run_dir)
        if suspicious:
            write_suspicious_results(suspicious, run_dir)

    finished = datetime.now(UTC).isoformat()
    run_meta = {
        "started_at": started,
        "finished_at": finished,
        "state": "finished",
        "sources": sources_used,
        "hits_by_source": hits_by_source,
        "raw_hits": len(all_hits),
        "unique_targets": len(targets),
        "candidates": len(creds),
        "active_requests": len(to_validate),
        "final_verified": len(valid),
        "suspicious": len(suspicious),
        "high_value_final": 0,
        "total_hosts": len(targets),
        "total_credentials": len(creds),
        "queries_used": queries_used,
    }

    if run_dir:
        scan_path = write_scan_metadata(run_meta, run_dir)
        for result in results:
            append_scan_result(result, scan_path)

    # Persist the whole run (metadata + valid + suspicious) to PG in one
    # transaction — the source of truth when DATABASE_URL is set.
    # Offloaded to a worker thread: it's a synchronous write of (potentially)
    # hundreds of rows, and running it on the event loop blocks every other
    # async endpoint for the whole transaction.
    if run_dir and settings.pg_enabled:
        from .writer import persist_run_pg

        await asyncio.to_thread(
            persist_run_pg,
            run_dir.name,
            run_meta,
            valid,
            suspicious,
            query_metrics.snapshot(),
        )

    return ScanRunResult(
        started_at=started,
        finished_at=finished,
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(targets),
        raw_hits_count=len(all_hits),
        unique_targets=len(targets),
        candidates=len(creds),
        active_requests=len(to_validate),
        final_verified=len(valid),
        suspicious=len(suspicious),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=queries_used,
        results=results,
        raw_hits=_trim_hits(all_hits),
    )


def _fetch_fofa(
    max_queries: int | None, *, skip_direct: bool = False
) -> tuple[list[dict], list[QueryUsage]]:
    """Run the FOFA backend: build queries, paginate each, tag hits with _cve/_product."""
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
        ),
    )
    selected = {candidate.query for candidate in planned}
    queries = [query for query in queries if query["query"] in selected]
    log.info("Built %d FOFA queries from CVE map", len(queries))

    all_hits: list[dict] = []
    queries_used: list[QueryUsage] = []
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
            hits = fofa.search(q["query"], pages=settings.fofa_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                        h.setdefault("_cves", q.get("advisory_ids", []))
                        h.setdefault("_product_hints", q.get("product_hints", []))
                        h.setdefault("_query_id", q["query"])
                all_hits.extend(hits)
            log.info("  FOFA accumulated %d hits", len(all_hits))
    log.info("FOFA total hits: %d", len(all_hits))
    return all_hits, queries_used


def _fetch_shodan(
    max_queries: int | None, *, skip_direct: bool = False
) -> tuple[list[dict], list[QueryUsage]]:
    """Run the Shodan backend: build Shodan-syntax queries, paginate each."""
    from aipocket.clients.shodan import ShodanClient

    from .shodan_queries import build_shodan_queries

    all_hits: list[dict] = []
    queries_used: list[QueryUsage] = []
    with ShodanClient() as shodan:
        queries = build_shodan_queries(
            skip_direct=skip_direct,
            count=shodan.count,
            max_pages=settings.shodan_max_pages,
            request_budget=settings.query_request_budget,
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
            hits = shodan.search(q["query"], pages=settings.shodan_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                        h.setdefault("_cves", q.get("advisory_ids", []))
                        h.setdefault("_product_hints", q.get("product_hints", []))
                        h.setdefault("_query_id", q["query"])
                all_hits.extend(hits)
            log.info("  Shodan accumulated %d hits", len(all_hits))
    log.info("Shodan total hits: %d", len(all_hits))
    return all_hits, queries_used


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
