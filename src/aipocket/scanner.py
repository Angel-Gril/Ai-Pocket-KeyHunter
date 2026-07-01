from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from .config import settings
from .extractor import extract_credentials
from .fofa_client import FofaClient
from .models import Credential, ScanRunResult, ValidationResult
from .queries import build_queries
from .validator import validate_all

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

async def run_scan(max_queries: int | None = None, run_dir: Path | None = None, *, skip_direct: bool = False) -> ScanRunResult:
    started = datetime.now(UTC).isoformat()

    # Stamp the run dir so GPT debug/failed-batch dumps land inside it.
    from . import analyzer as _analyzer

    _analyzer.set_run_dir(run_dir)

    all_hits: list[dict] = []
    queries_used: list[str] = []
    sources_used: list[str] = []
    hits_by_source: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Source 1: FOFA (skipped silently if no FOFA keys configured)
    # ------------------------------------------------------------------
    if settings.keys:
        sources_used.append("fofa")
        fofa_hits = _fetch_fofa(max_queries, skip_direct=skip_direct)
        for h in fofa_hits:
            if isinstance(h, dict):
                h.setdefault("_source", "fofa")
        all_hits.extend(fofa_hits)
        hits_by_source["fofa"] = len(fofa_hits)
    else:
        log.info("FOFA keys not configured — skipping FOFA source")

    # ------------------------------------------------------------------
    # Source 2: Shodan (skipped silently if no SHODAN keys configured)
    # ------------------------------------------------------------------
    if settings.shodan_key_list:
        sources_used.append("shodan")
        shodan_hits = _fetch_shodan(max_queries, skip_direct=skip_direct)
        for h in shodan_hits:
            if isinstance(h, dict):
                h.setdefault("_source", "shodan")
        all_hits.extend(shodan_hits)
        hits_by_source["shodan"] = len(shodan_hits)
    else:
        log.info("Shodan keys not configured — skipping Shodan source")

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

    from .writer import write_raw_hits

    write_raw_hits(all_hits, run_dir=run_dir)

    # Active probing — read exposed config/credential endpoints on fingerprinted
    # gateways. Catches live keys that passive banner extraction misses.
    from .prober import probe_hosts

    probed_creds: list[Credential] = []
    if settings.scan_prober:
        log.info("Probing %d hosts for exposed credentials...", len(all_hits))
        probed_creds = await probe_hosts(all_hits)
        seen = _merge_credentials(creds, probed_creds, seen)
        log.info("After active probing: %d candidate credentials", len(creds))

    from .analyzer import extract_with_gpt

    sampled = _sample_hits_for_gpt(all_hits)
    fofa_sampled = sum(1 for h in sampled if h.get("_source") == "fofa")
    shodan_sampled = sum(1 for h in sampled if h.get("_source") == "shodan")
    log.info(
        "GPT sampling: %d hits (fofa=%d, shodan=%d)",
        len(sampled), fofa_sampled, shodan_sampled,
    )
    gpt_creds = await extract_with_gpt(sampled)
    if gpt_creds:
        seen = _merge_credentials(creds, gpt_creds, seen)
        log.info("After GPT enrichment: %d candidate credentials", len(creds))

    if not creds:
        return ScanRunResult(
            started_at=started,
            finished_at=datetime.now(UTC).isoformat(),
            sources=sources_used,
            hits_by_source=hits_by_source,
            total_hosts=len(all_hits),
            total_credentials=0,
            total_valid=0,
            queries_used=queries_used,
            results=[],
            raw_hits=_trim_hits(all_hits),
        )

    log.info("Validating %d credentials (concurrency=%d)...", len(creds), settings.validate_concurrency)
    results: list[ValidationResult] = await validate_all(creds)

    if settings.gpt_key:
        from .analyzer import recheck_all_with_gpt

        results = list(await recheck_all_with_gpt(results))

    # Honeypot / cluster detection — reject fake positives before balance queries
    from .honeypot import filter_honeypots

    results = filter_honeypots(results)

    valid = [r for r in results if r.valid]
    log.info("Validation done: %d valid / %d total", len(valid), len(results))

    if valid:
        from .balance import enrich_results

        log.info("Querying balance for %d valid credentials...", len(valid))
        results = await enrich_results(results)
        valid = [r for r in results if r.valid]
        log.info("Balance enrichment done.")

    return ScanRunResult(
        started_at=started,
        finished_at=datetime.now(UTC).isoformat(),
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(all_hits),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=queries_used,
        results=results,
        raw_hits=_trim_hits(all_hits),
    )


def _fetch_fofa(max_queries: int | None, *, skip_direct: bool = False) -> list[dict]:
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
    return all_hits


def _fetch_shodan(max_queries: int | None, *, skip_direct: bool = False) -> list[dict]:
    """Run the Shodan backend: build Shodan-syntax queries, paginate each."""
    from .shodan_client import ShodanClient
    from .shodan_queries import build_shodan_queries

    queries = build_shodan_queries(skip_direct=skip_direct)
    if max_queries:
        queries = queries[:max_queries]
    log.info("Built %d Shodan queries from CVE map", len(queries))

    # Report remaining credit budget so the 200k/month plan isn't blown silently.
    all_hits: list[dict] = []
    with ShodanClient() as shodan:
        try:
            info = shodan.info()
            if info:
                log.info(
                    "  Shodan plan=%s query_credits_remaining=%s",
                    info.get("plan"),
                    info.get("query_credits"),
                )
        except Exception:  # noqa: BLE001 - info is best-effort
            pass

        for i, q in enumerate(queries, 1):
            log.info("[SHODAN %d/%d] %s | %s", i, len(queries), q["cve_id"], q["query"][:80])
            hits = shodan.search(q["query"], pages=settings.shodan_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                all_hits.extend(hits)
            log.info("  Shodan accumulated %d hits", len(all_hits))
    log.info("Shodan total hits: %d", len(all_hits))
    return all_hits


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
