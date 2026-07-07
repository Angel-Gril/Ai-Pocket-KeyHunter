"""Shodan search backend.

A second, fully-independent data source for aipocket — kept separate from the
FOFA client because Shodan's query syntax, REST API and result shape are all
different. Hits returned by :meth:`ShodanClient.search` are normalized into the
same dict shape the extractor/validator already consume for FOFA
(``host/ip/port/header/banner/title/product/protocol``), so the downstream
pipeline is shared while the source itself stays distinct.

Shodan REST API reference:
    GET https://api.shodan.io/shodan/host/search
        ?key=KEY&query=QUERY&page=N&minify=false
    -> {"matches": [...], "total": N}

Query credit billing (important, the user has 200k/month, 1 credit = 100 results):
    - 1 credit is deducted when the query contains any filter
    - 1 credit per 100 results past the 1st page
"""

from __future__ import annotations

import itertools
import logging
import time
from typing import Any

import httpx

from aipocket.core.config import settings

log = logging.getLogger(__name__)


def _cert_to_str(ssl: dict[str, Any] | None) -> str:
    """Render the parts of an SSL cert the extractor can scan for leaked URLs."""
    if not ssl:
        return ""
    cert = ssl.get("cert") or {}
    if not cert:
        return ""
    parts: list[str] = []
    for field in ("subject", "issuer"):
        node = cert.get(field) or {}
        for d in node if isinstance(node, list) else [node]:
            if isinstance(d, dict):
                cn = d.get("commonName") or d.get("commonname")
                if cn:
                    parts.append(str(cn))
                    on = d.get("organizationName") or d.get("organizationname")
                    if on:
                        parts.append(str(on))
    issued = cert.get("issued")
    if issued:
        parts.append(str(issued))
    return " ".join(parts)


def map_match(m: dict[str, Any]) -> dict[str, Any]:
    """Normalize one Shodan match into the FOFA-style dict the extractor expects.

    Field mapping (Shodan -> FOFA shape):
        data       -> header  (the banner, which for HTTP includes response headers)
        http.html  -> banner  (the crawled page body — richer than what FOFA returns)
        http.title -> title
        ssl.cert   -> cert
        product    -> product
        ip_str     -> ip
        port       -> port
    """
    http = m.get("http") or {}
    ip = m.get("ip_str", "") or ""
    port = m.get("port", "")
    port_str = str(port) if port != "" else ""

    hostnames = m.get("hostnames") or []
    http_host = (http.get("host") or "").strip()

    # Build a usable host: prefer hostname (resolvable), fall back to http.host / ip
    base = hostnames[0] if hostnames else (http_host or ip)
    # Keep the port when it's non-standard so the validator hits the right endpoint
    if base and port_str not in ("", "80", "443") and ":" not in base:
        host = f"{base}:{port_str}"
    else:
        host = base

    scheme = "https" if port_str == "443" else "http"

    data_banner = m.get("data", "") or ""
    html_body = http.get("html", "") or ""

    return {
        "host": host,
        "ip": ip,
        "port": port_str,
        "protocol": scheme,
        "title": http.get("title", "") or "",
        # `data` is the banner / HTTP response headers — the highest-ROI field for
        # keys leaked via Authorization / x-api-key headers.
        "header": data_banner,
        # Shodan gives us the page body too — FOFA doesn't. Scan it as `banner`.
        "banner": html_body,
        "cert": _cert_to_str(m.get("ssl")),
        "product": m.get("product", "") or "",
        "server": http.get("server", "") or "",
        "link": hostnames[0] if hostnames else "",
    }


class ShodanClient:
    """Minimal Shodan REST client with multi-key rotation, mirroring FofaClient."""

    def __init__(
        self,
        keys: list[str] | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ):
        if keys is None:
            keys = settings.shodan_key_list
        if not keys:
            raise RuntimeError("No Shodan keys configured. Set SHODAN_KEYS in .env")
        self.keys = keys
        self.base_url = (base_url or settings.shodan_base_url).rstrip("/")
        self.timeout = timeout or settings.shodan_timeout
        self._key_cycle = itertools.cycle(self.keys)
        self._dead: set[str] = set()
        self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)

    def info(self) -> dict[str, Any]:
        """Per-key /api-info aggregated across ALL keys (best-effort).

        Unlike search/count, this iterates every key directly (not via the
        rotation cycle) so each key's plan & remaining credits are reported —
        accounts often pair a high-quota key with a low-quota one, and only
        seeing the first key's budget is misleading for credit planning.

        Returns a dict:
            {
              "keys": [{"_key_masked": "...", "plan": ..., "query_credits": N}, ...],
              "total_query_credits": int,
              "n_keys": int, "n_dead": int,
            }
        Empty dict if every key failed. Invalid (401/403) keys are marked dead.
        """
        url = f"{self.base_url}/api-info"
        per_key: list[dict[str, Any]] = []
        for key in self.keys:
            if key in self._dead:
                continue
            try:
                r = self._client.get(url, params={"key": key})
            except httpx.HTTPError as e:
                log.warning("  shodan key %s… info network error: %s", key[:6], e)
                continue
            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    continue
                data["_key_masked"] = f"{key[:6]}…{key[-4:]}"
                per_key.append(data)
                continue
            if r.status_code in (401, 403):
                log.warning("  shodan key %s… invalid (HTTP %d)", key[:6], r.status_code)
                self._dead.add(key)
        if not per_key:
            return {}
        total = sum(int(k.get("query_credits", 0) or 0) for k in per_key)
        return {
            "keys": per_key,
            "total_query_credits": total,
            "n_keys": len(self.keys),
            "n_dead": len(self._dead),
        }

    def count(self, query: str) -> int | None:
        """Total matches for a query WITHOUT consuming query credits.

        Returns ``None`` when the count endpoint itself failed (network error,
        all keys dead, non-200 / non-JSON) — callers MUST treat ``None`` as
        "unknown, proceed with search" so a transient Shodan hiccup doesn't
        silently drop a live query. Returns ``0`` ONLY when Shodan explicitly
        reported zero matches (safe to skip).
        """
        data = self._request("/shodan/host/count", {"query": query})
        if data is None:
            return None
        try:
            return int(data.get("total", 0))
        except (TypeError, ValueError):
            return None

    def search(
        self,
        query: str,
        pages: int | None = None,
    ) -> list[dict[str, Any]]:
        pages = pages or settings.shodan_max_pages
        all_results: list[dict[str, Any]] = []

        for page in range(1, pages + 1):
            data = self._request(
                "/shodan/host/search",
                {"query": query, "page": page, "minify": "false"},
            )
            if data is None:
                break

            matches = data.get("matches", []) or []
            if not matches:
                log.info("  shodan page %d: empty, stopping", page)
                break

            mapped = [map_match(m) for m in matches]
            all_results.extend(mapped)
            total = data.get("total", 0)
            log.info("  shodan page %d: +%d (total est. %s)", page, len(mapped), total)

            if len(matches) < 100:
                break
            # Shodan rate-limits the search API (~1 req/sec). Back off between pages.
            time.sleep(settings.shodan_page_delay)

        return all_results

    def _request(self, path: str, params: dict[str, Any]) -> dict[str, Any] | None:
        url = f"{self.base_url}{path}"
        last_err = ""
        for _ in range(len(self.keys)):
            key = next(self._key_cycle)
            if key in self._dead:
                continue
            req_params = {**params, "key": key}
            try:
                r = self._client.get(url, params=req_params)
            except httpx.HTTPError as e:
                last_err = f"network: {e}"
                log.warning("  shodan key %s… network error: %s", key[:6], e)
                continue

            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    last_err = f"non-json: {r.text[:200]}"
                    log.warning("  shodan key %s… %s", key[:6], last_err)
                    continue

            last_err = f"HTTP {r.status_code}: {r.text[:200]}"
            if r.status_code in (401, 403):
                # Invalid / disabled key — stop using it, try the next one.
                log.error("  shodan key %s… invalid key (%s)", key[:6], last_err)
                self._dead.add(key)
                continue
            if r.status_code == 429:
                # Rate limited — this key is fine, just slow down and retry next.
                log.warning("  shodan key %s… rate limited, backing off", key[:6])
                time.sleep(max(settings.shodan_page_delay, 1.0))
                continue
            log.warning("  shodan key %s… %s", key[:6], last_err)
            # For other errors (e.g. 400 malformed query) don't burn all keys.
            return None

        log.error("  shodan all keys failed for %s: %s", path, last_err)
        return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
