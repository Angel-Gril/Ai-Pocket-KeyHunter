from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from .config import settings
from .dedup import DedupStore, get_dedup_store
from .extractor import extract_credentials
from .fofa_client import FofaClient
from .models import Credential, ScanRunResult, ValidationResult
from .queries import build_queries
from .validator import validate_all
from .writer import (
    append_scan_result,
    write_scan_metadata,
    write_suspicious_results,
    write_valid_results,
)

log = logging.getLogger(__name__)

# Quick regex to detect potential credentials in hit blobs — used for sampling priority.
_SK_PATTERN = re.compile(r"sk-[A-Za-z0-9_\-]{20,}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{20,}")



def _merge_credentials(
    existing: list[Credential],
    new: list[Credential],
    seen: set[tuple[str, str]] | None = None,
) -> set[tuple[str, str]]:
    """Merge *new* credentials into *existing* in-place, deduplicating by (apikey, apiurl).
    Returns the updated seen-set."""
    if seen is None:
        seen = {(c.apikey, c.apiurl) for c in existing}
    for c in new:
        if (c.apikey, c.apiurl) not in seen:
            existing.append(c)
            seen.add((c.apikey, c.apiurl))
    return seen

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
    from .db import current_run_id

    run_id = run_dir.name if run_dir else None
    token = current_run_id.set(run_id)

    # Cross-run dedup store (Redis-backed; degrades to no-op if unavailable).
    dedup = await get_dedup_store()

    try:
        return await _run_scan_inner(
            max_queries, run_dir, skip_direct=skip_direct, started=started, dedup=dedup, sources=sources
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

    # ------------------------------------------------------------------
    # Source fetching — run FOFA and Shodan in PARALLEL via threads
    # (both use synchronous httpx clients internally)
    # ------------------------------------------------------------------
    import concurrent.futures

    fofa_hits: list[dict] = []
    shodan_hits: list[dict] = []

    # `sources` (when given) restricts which discovery backends run this scan —
    # e.g. the web UI's single-source mode. None means "every configured source".
    want_fofa = sources is None or "fofa" in sources
    want_shodan = sources is None or "shodan" in sources

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        if want_fofa and settings.keys:
            sources_used.append("fofa")
            futures["fofa"] = pool.submit(_fetch_fofa, max_queries, skip_direct=skip_direct)
        elif want_fofa:
            log.info("FOFA keys not configured — skipping FOFA source")

        if want_shodan and settings.shodan_key_list:
            sources_used.append("shodan")
            futures["shodan"] = pool.submit(_fetch_shodan, max_queries, skip_direct=skip_direct)
        elif want_shodan:
            log.info("Shodan keys not configured — skipping Shodan source")

        for name, future in futures.items():
            try:
                hits, used_queries = future.result()
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_source", name)
                if name == "fofa":
                    fofa_hits = hits
                else:
                    shodan_hits = hits
                queries_used.extend(used_queries)
            except Exception as e:
                log.error("Source %s failed: %s", name, e)

    all_hits = fofa_hits + shodan_hits
    hits_by_source["fofa"] = len(fofa_hits)
    hits_by_source["shodan"] = len(shodan_hits)

    if not sources_used:
        raise RuntimeError(
            "No discovery source configured. Set FOFA_KEYS and/or SHODAN_KEYS in .env"
        )

    log.info(
        "Total hits: %d (sources: %s)", len(all_hits), ", ".join(sources_used)
    )

    # ------------------------------------------------------------------
    # Shared downstream pipeline (source-agnostic): extract -> validate
    # -> GPT recheck -> balance
    # ------------------------------------------------------------------
    creds = extract_credentials(all_hits)
    seen = {(c.apikey, c.apiurl) for c in creds}
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
        pre_filtered_count, len(creds), pre_filtered_count - len(creds),
    )

    # Active probing — probe all hosts. Signal-based ordering ensures high-value
    # targets (those with key patterns in banner/header) are probed first, but
    # ALL hosts are probed (no cap — precision queries already limit the set).
    from .prober import probe_hosts

    probed_creds: list[Credential] = []
    if settings.scan_prober:
        # Sort: high-signal hosts first (have sk- / api_key / OPENAI / ANTHROPIC in banner/header)
        _SIGNAL_RE = re.compile(r"sk-[A-Za-z0-9_\-]{6,}|api[_-]?key|OPENAI|ANTHROPIC|authorization", re.I)

        def _has_signal(h: dict) -> bool:
            blob = (h.get("header", "") or "") + " " + (h.get("banner", "") or "")
            return bool(_SIGNAL_RE.search(blob))

        # Stable sort: high-signal first, rest after
        probe_targets = sorted(all_hits, key=lambda h: (0 if _has_signal(h) else 1))

        # Cross-run dedup: skip hosts already probed in a previous run.
        before_probe = len(probe_targets)
        probe_targets = await dedup.filter_unseen_hosts(probe_targets)
        if before_probe != len(probe_targets):
            log.info(
                "Dedup: host probe %d → %d (skipped %d seen)",
                before_probe, len(probe_targets), before_probe - len(probe_targets),
            )
        # Recount after dedup so the probe-log numbers are self-consistent.
        high_count = sum(1 for h in probe_targets if _has_signal(h))

        log.info(
            "Probing %d hosts (high-signal=%d, low-signal=%d)",
            len(probe_targets), high_count, len(probe_targets) - high_count,
        )
        probed_creds = await probe_hosts(probe_targets)
        for h in probe_targets:
            await dedup.mark_host(h.get("host", ""))
        seen = _merge_credentials(creds, probed_creds, seen)
        log.info("After active probing: %d candidate credentials", len(creds))

    from .analyzer import extract_with_gpt

    sampled = _sample_hits_for_gpt(all_hits)
    # Cross-run dedup: hosts already GPT-extracted in a previous run are skipped.
    before_gpt = len(sampled)
    sampled = await dedup.filter_unseen_hosts(sampled)
    if before_gpt != len(sampled):
        log.info(
            "Dedup: GPT sampling %d → %d (skipped %d seen hosts)",
            before_gpt, len(sampled), before_gpt - len(sampled),
        )
    fofa_sampled = sum(1 for h in sampled if h.get("_source") == "fofa")
    shodan_sampled = sum(1 for h in sampled if h.get("_source") == "shodan")
    log.info(
        "GPT sampling: %d hits (fofa=%d, shodan=%d)",
        len(sampled), fofa_sampled, shodan_sampled,
    )
    gpt_creds = await extract_with_gpt(sampled)
    for h in sampled:
        await dedup.mark_host(h.get("host", ""))
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
            "total_hosts": len(all_hits),
            "total_credentials": 0,
            "queries_used": queries_used,
        }
        if run_dir:
            write_scan_metadata(empty_meta, run_dir)
            write_valid_results([], run_dir)
            if settings.pg_enabled:
                from .writer import persist_run_pg

                persist_run_pg(run_dir.name, empty_meta, [], [])
        return ScanRunResult(
            started_at=started,
            finished_at=finished,
            sources=sources_used,
            hits_by_source=hits_by_source,
            total_hosts=len(all_hits),
            total_credentials=0,
            total_valid=0,
            queries_used=queries_used,
            results=[],
            raw_hits=_trim_hits(all_hits),
        )

    # Cross-run dedup: split creds into cache hits (reuse), recently-failed
    # (skip this run), and the rest (validate fresh).
    cached_results: list[ValidationResult] = []
    to_validate: list[Credential] = []
    n_recent_fail = 0
    for c in creds:
        hit = await dedup.get_cached_valid(c)
        if hit is not None:
            cached_results.append(hit)
            continue
        if await dedup.is_recently_failed(c):
            n_recent_fail += 1
            continue
        to_validate.append(c)
    log.info(
        "Dedup: %d creds → %d cached / %d to validate / %d recently-failed (skipped)",
        len(creds), len(cached_results), len(to_validate), n_recent_fail,
    )

    log.info("Validating %d credentials (concurrency=%d)...", len(to_validate), settings.validate_concurrency)
    fresh_results: list[ValidationResult] = await validate_all(to_validate) if to_validate else []
    for r in fresh_results:
        if r.valid:
            await dedup.cache_valid(r)
        else:
            await dedup.mark_failed(r.credential)
    results: list[ValidationResult] = cached_results + fresh_results

    # No-auth honeypot probe: for each host that has a valid result, send a
    # FORGED key. If it also validates, the endpoint ignores Authorization and
    # every key on it is fake. Runs once per host (not per key) to bound volume.
    from . import honeypot as _honeypot
    from .validator import verify_no_auth

    valid_after_probe = [r for r in results if r.valid]
    if valid_after_probe:
        distinct_hosts = len({r.credential.host or r.credential.apiurl for r in valid_after_probe})
        log.info(
            "Probing %d host(s) with a forged key to detect no-auth honeypots...",
            distinct_hosts,
        )
        no_auth_urls, suspicious_urls = await verify_no_auth(results)
        _honeypot.no_auth_hosts = no_auth_urls
        _honeypot.suspicious_hosts = suspicious_urls

    # Write scan metadata + per-result JSONL lines
    scan_path: Path | None = None
    if run_dir:
        scan_path = write_scan_metadata({
            "started_at": started,
            "sources": sources_used,
            "hits_by_source": hits_by_source,
            "total_hosts": len(all_hits),
            "total_credentials": len(creds),
            "queries_used": queries_used,
        }, run_dir)
        for r in results:
            append_scan_result(r, scan_path)

    # GPT recheck — disabled by default since honeypot filter catches the same
    # cases faster. Enable with GPT_RECHECK=true for extra verification.
    if settings.gpt_recheck:
        from .analyzer import recheck_all_with_gpt

        results = list(await recheck_all_with_gpt(results))

    # Honeypot / cluster detection — reject fake positives before balance queries
    from .honeypot import filter_honeypots

    results = filter_honeypots(results)

    valid = [r for r in results if r.valid]
    # Split suspicious results out BEFORE balance enrichment: they passed
    # validation but sit on a host flagged by verify_no_auth (forged-429 /
    # non-completion). They are quarantined to suspicious_*.jsonl and do NOT
    # consume balance-query budget.
    suspicious = [r for r in valid if r.suspicious]
    valid = [r for r in valid if not r.suspicious]
    log.info(
        "Validation done: %d valid / %d total (%d suspicious quarantined)",
        len(valid), len(results), len(suspicious),
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

    # Write valid_*.jsonl + suspicious_*.jsonl after honeypot + balance enrichment
    if run_dir:
        write_valid_results(valid, run_dir)
        if suspicious:
            write_suspicious_results(suspicious, run_dir)

    finished = datetime.now(UTC).isoformat()

    # Persist the whole run (metadata + valid + suspicious) to PG in one
    # transaction — the source of truth when DATABASE_URL is set.
    if run_dir and settings.pg_enabled:
        from .writer import persist_run_pg

        persist_run_pg(
            run_dir.name,
            {
                "started_at": started,
                "finished_at": finished,
                "state": "finished",
                "sources": sources_used,
                "hits_by_source": hits_by_source,
                "total_hosts": len(all_hits),
                "total_credentials": len(creds),
                "queries_used": queries_used,
            },
            valid,
            suspicious,
        )

    return ScanRunResult(
        started_at=started,
        finished_at=finished,
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(all_hits),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=queries_used,
        results=results,
        raw_hits=_trim_hits(all_hits),
    )


def _fetch_fofa(max_queries: int | None, *, skip_direct: bool = False) -> tuple[list[dict], list[str]]:
    """Run the FOFA backend: build queries, paginate each, tag hits with _cve/_product."""
    queries = build_queries(skip_direct=skip_direct)
    if max_queries:
        queries = queries[:max_queries]
    log.info("Built %d FOFA queries from CVE map", len(queries))

    all_hits: list[dict] = []
    queries_used: list[str] = []
    with FofaClient() as fofa:
        for i, q in enumerate(queries, 1):
            log.info("[FOFA %d/%d] %s | %s", i, len(queries), q["cve_id"], q["query"][:80])
            hits = fofa.search(q["query"], pages=settings.fofa_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                all_hits.extend(hits)
                queries_used.append(q["query"])
            log.info("  FOFA accumulated %d hits", len(all_hits))
    log.info("FOFA total hits: %d", len(all_hits))
    return all_hits, queries_used


def _fetch_shodan(max_queries: int | None, *, skip_direct: bool = False) -> tuple[list[dict], list[str]]:
    """Run the Shodan backend: build Shodan-syntax queries, paginate each."""
    from .shodan_client import ShodanClient
    from .shodan_queries import build_shodan_queries

    queries = build_shodan_queries(skip_direct=skip_direct)
    if max_queries:
        queries = queries[:max_queries]
    log.info("Built %d Shodan queries from CVE map", len(queries))

    # Report remaining credit budget so the 200k/month plan isn't blown silently.
    all_hits: list[dict] = []
    queries_used: list[str] = []
    with ShodanClient() as shodan:
        try:
            info = shodan.info()
            if info:
                log.info(
                    "  Shodan keys=%d dead=%d total_query_credits=%s",
                    info.get("n_keys"), info.get("n_dead"), info.get("total_query_credits"),
                )
                for k in info.get("keys", []):
                    log.info(
                        "    key %s plan=%s query_credits=%s",
                        k.get("_key_masked"), k.get("plan"), k.get("query_credits"),
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
                log.info("  shodan count=0, skipping (credit saved)")
                continue
            if total is None:
                log.info("  shodan count unknown, proceeding")
            else:
                log.info("  shodan count=%s", total)

            hits = shodan.search(q["query"], pages=settings.shodan_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                all_hits.extend(hits)
                queries_used.append(q["query"])
            log.info("  Shodan accumulated %d hits", len(all_hits))
    log.info("Shodan total hits: %d", len(all_hits))
    return all_hits, queries_used


def _sample_hits_for_gpt(hits: list[dict], limit: int = 5000) -> list[dict]:
    """Sample hits for GPT extraction with three-tier priority.

    Tier 1: Hits whose header/banner/body/cert text contains a credential-like pattern.
    Tier 2: Shodan hits (they carry http.html as banner — the richest text source).
    Tier 3: Remaining FOFA hits with header/banner content.

    This ensures Shodan's page-body data is never starved out by the larger FOFA set.
    """
    seen_hosts: set[str] = set()
    tier_key: list[dict] = []
    tier_shodan: list[dict] = []
    tier_rest: list[dict] = []

    for h in hits:
        host = h.get("host", "")
        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        blob = (h.get("header", "") or "") + " " + (h.get("banner", "") or "")
        if h.get("_source") == "shodan":
            blob += " " + (h.get("cert", "") or "")
        if _SK_PATTERN.search(blob):
            tier_key.append(h)
        elif h.get("_source") == "shodan" and (h.get("banner") or h.get("header")):
            tier_shodan.append(h)
        elif h.get("header") or h.get("banner") or h.get("body"):
            tier_rest.append(h)

    result = tier_key + tier_shodan + tier_rest
    if len(result) > limit:
        result = result[:limit]
    return result


def _trim_hits(hits: list[dict], limit: int = 500) -> list[dict]:
    if len(hits) <= limit:
        return hits
    return hits[:limit]
