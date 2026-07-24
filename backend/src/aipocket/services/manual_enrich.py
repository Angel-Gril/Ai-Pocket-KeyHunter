"""Domain enrichment for manual targets — FOFA / Shodan reverse lookup.

Manual hits have no FOFA/Shodan banner body, so product probers (NewAPI, etc.)
cannot ``identify()``. This module extracts hostnames from stored targets and
runs tight hostname/host queries against the selected engines, then merges
title/header/banner (and optional extra host hits) back into the discovery set.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from aipocket.core.config import settings
from aipocket.core.metrics import QueryUsage

log = logging.getLogger(__name__)

# Keep enrich cheap: one page per hostname, small FOFA page size.
_FOFA_PAGES = 1
_FOFA_PAGE_SIZE = 50
_SHODAN_PAGES = 1

_FINGERPRINT_FIELDS = ("title", "header", "banner", "server", "product", "cert")
_VALID_ENGINES = frozenset({"fofa", "shodan"})


def normalize_enrich_engines(raw: object) -> frozenset[str]:
    """Coerce API / CLI input into a frozenset of known enrich engines."""
    if not raw:
        return frozenset()
    if isinstance(raw, str):
        items = [p.strip().lower() for p in raw.split(",") if p.strip()]
    elif isinstance(raw, (set, frozenset, list, tuple)):
        items = [str(p).strip().lower() for p in raw if str(p).strip()]
    else:
        return frozenset()
    return frozenset(i for i in items if i in _VALID_ENGINES)


def _hostname_of_hit(hit: dict[str, Any]) -> str:
    raw = str(hit.get("host") or hit.get("link") or "").strip()
    if not raw:
        return ""
    scheme = str(hit.get("protocol") or "https").lower()
    if scheme not in {"http", "https"}:
        scheme = "https"
    parsed = urlsplit(raw if "://" in raw else f"{scheme}://{raw}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        return ""
    with contextlib.suppress(ValueError):
        hostname = ipaddress.ip_address(hostname).compressed
    return hostname


def _is_ip(hostname: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(hostname)
        return True
    return False


def _merge_fingerprint(base: dict[str, Any], enrich: dict[str, Any]) -> None:
    """Copy non-empty fingerprint fields from an engine hit onto a seed hit."""
    for field in _FINGERPRINT_FIELDS:
        val = str(enrich.get(field) or "").strip()
        if not val:
            continue
        existing = str(base.get(field) or "").strip()
        if not existing:
            base[field] = val
        elif field in {"header", "banner"} and val not in existing:
            # Keep both evidence blobs for extract / identify.
            base[field] = f"{existing}\n{val}"
        elif field == "title" and "new api" in val.lower() and "new api" not in existing.lower():
            base[field] = val

    product = str(enrich.get("product") or "").strip()
    if product:
        hints = [str(h) for h in (base.get("_product_hints") or []) if str(h).strip()]
        if product.lower() not in {h.lower() for h in hints}:
            hints.append(product)
            base["_product_hints"] = hints

    engines = list(base.get("_manual_enrich") or [])
    src = str(enrich.get("_source") or "").strip()
    if src and src not in engines:
        engines.append(src)
        base["_manual_enrich"] = engines


def _fofa_query(hostname: str) -> str:
    if _is_ip(hostname):
        return f'ip="{hostname}"'
    # host= matches the service hostname; domain= catches parent-domain indexes.
    return f'host="{hostname}" || domain="{hostname}"'


def _shodan_query(hostname: str) -> str:
    if _is_ip(hostname):
        return f"ip:{hostname}"
    return f'hostname:"{hostname}"'


def _tag_enrich_hit(
    row: dict[str, Any],
    *,
    engine: str,
    hostname: str,
    query: str,
) -> dict[str, Any]:
    hit = dict(row)
    hit["_source"] = engine
    hit["_query_id"] = f"manual-enrich:{engine}:{hostname}"
    hit["_manual_seed_host"] = hostname
    hit.setdefault("_query", query)
    return hit


def _search_fofa(hostname: str) -> tuple[list[dict[str, Any]], QueryUsage | None, str | None]:
    if not settings.keys:
        return [], None, "fofa keys not configured"
    query = _fofa_query(hostname)
    try:
        from aipocket.clients.fofa import FofaClient

        client = FofaClient(query_id=f"manual-enrich:{hostname}")
        rows = client.search(query, pages=_FOFA_PAGES, size=_FOFA_PAGE_SIZE)
    except Exception as e:  # noqa: BLE001 — isolate per-host enrich failures
        log.warning("Manual FOFA enrich %s failed: %s", hostname, e)
        return [], None, f"fofa {hostname}: {type(e).__name__}: {e}"
    tagged = [_tag_enrich_hit(r, engine="fofa", hostname=hostname, query=query) for r in rows]
    usage = QueryUsage(
        query=query,
        credits=1 if tagged else 0,
        query_id=f"manual-enrich:fofa:{hostname}",
        lane="manual-enrich",
    )
    log.info("Manual FOFA enrich %s: %d hit(s) query=%s", hostname, len(tagged), query)
    return tagged, usage, None


def _search_shodan(hostname: str) -> tuple[list[dict[str, Any]], QueryUsage | None, str | None]:
    if not settings.shodan_key_list:
        return [], None, "shodan keys not configured"
    query = _shodan_query(hostname)
    try:
        from aipocket.clients.shodan import ShodanClient

        client = ShodanClient(query_id=f"manual-enrich:{hostname}")
        rows = client.search(query, pages=_SHODAN_PAGES)
    except Exception as e:  # noqa: BLE001 — isolate per-host enrich failures
        log.warning("Manual Shodan enrich %s failed: %s", hostname, e)
        return [], None, f"shodan {hostname}: {type(e).__name__}: {e}"
    tagged = [_tag_enrich_hit(r, engine="shodan", hostname=hostname, query=query) for r in rows]
    usage = QueryUsage(
        query=query,
        credits=1 if tagged else 0,
        query_id=f"manual-enrich:shodan:{hostname}",
        lane="manual-enrich",
    )
    log.info("Manual Shodan enrich %s: %d hit(s) query=%s", hostname, len(tagged), query)
    return tagged, usage, None


def enrich_manual_hits(
    seed_hits: list[dict[str, Any]],
    *,
    engines: frozenset[str] | set[str] | list[str] | tuple[str, ...] | str,
) -> tuple[list[dict[str, Any]], tuple[QueryUsage, ...], tuple[str, ...]]:
    """Enrich manual seed hits via FOFA/Shodan hostname reverse lookup.

    Returns ``(all_hits, query_usage, soft_errors)``. Soft errors (missing keys,
    per-host API failures) never drop the original seed hits.
    """
    wanted = normalize_enrich_engines(engines)
    if not wanted or not seed_hits:
        return list(seed_hits), (), ()

    # Work on copies so callers can retry safely.
    seeds = [dict(h) for h in seed_hits]
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for hit in seeds:
        host = _hostname_of_hit(hit)
        if host:
            by_host[host].append(hit)

    hostnames = sorted(by_host)
    if not hostnames:
        return seeds, (), ()

    log.info(
        "Manual enrich: %d hostname(s) × engines=%s",
        len(hostnames),
        ",".join(sorted(wanted)),
    )

    extra: list[dict[str, Any]] = []
    usage: list[QueryUsage] = []
    errors: list[str] = []

    for hostname in hostnames:
        if "fofa" in wanted:
            rows, u, err = _search_fofa(hostname)
            if err:
                errors.append(err)
            if u is not None:
                usage.append(u)
            for row in rows:
                for seed in by_host[hostname]:
                    _merge_fingerprint(seed, row)
                extra.append(row)
        if "shodan" in wanted:
            rows, u, err = _search_shodan(hostname)
            if err:
                errors.append(err)
            if u is not None:
                usage.append(u)
            for row in rows:
                for seed in by_host[hostname]:
                    _merge_fingerprint(seed, row)
                extra.append(row)

    merged = seeds + extra
    log.info(
        "Manual enrich done: seeds=%d extra=%d usage=%d errors=%d",
        len(seeds),
        len(extra),
        len(usage),
        len(errors),
    )
    return merged, tuple(usage), tuple(errors)
