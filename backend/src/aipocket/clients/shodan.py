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

Rate limit: ~1 request/second per key (membership plans vary). We enforce a
global min interval and multi-round retries so a transient 429 does not kill
the whole search when another key (or a later retry) would succeed.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from aipocket.clients.key_pool import KeyPool, rate_limit_backoff
from aipocket.core.config import settings

log = logging.getLogger(__name__)

# Shodan search pagination uses a server-side cursor. When it expires the API
# returns HTTP 500 with this message — retrying the same page never helps;
# the query must be restarted from page 1.
_CURSOR_TIMEOUT_MARKERS = (
    "search cursor timed out",
    "restart the search query from page 1",
)


class SearchCursorTimedOut(Exception):
    """Raised when Shodan says the search cursor expired (restart from page 1)."""


def _is_cursor_timeout(body: str) -> bool:
    low = body.lower()
    return any(m in low for m in _CURSOR_TIMEOUT_MARKERS)


def _result_dedupe_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (str(row.get("ip") or ""), str(row.get("port") or ""), str(row.get("host") or ""))


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


def _is_credits_exhausted(status_code: int, body: str) -> bool:
    if status_code not in (401, 403):
        return False
    low = body.lower()
    return (
        "insufficient query credits" in low
        or "query credits" in low
        or "monthly limit" in low
        or "upgrade your api plan" in low
    )


class ShodanClient:
    """Minimal Shodan REST client with multi-key rotation, mirroring FofaClient."""

    def __init__(
        self,
        keys: list[str] | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        *,
        min_interval: float | None = None,
        max_rounds: int = 3,
        query_id: str = "",
    ):
        if keys is None:
            keys = settings.shodan_key_list
        if not keys:
            raise RuntimeError("No Shodan keys configured. Set SHODAN_KEYS in .env")
        self.keys = keys
        self.base_url = (base_url or settings.shodan_base_url).rstrip("/")
        self.timeout = timeout or settings.shodan_timeout
        # Default ≥1s to match Shodan's common free/member rate limit message.
        # Tests may pass min_interval=0 to disable sleeping.
        if min_interval is None:
            interval = max(float(settings.shodan_page_delay), 1.0)
        else:
            interval = max(float(min_interval), 0.0)
        self.query_id = query_id
        self._pool = KeyPool(
            keys,
            min_interval=interval,
            label="shodan key",
            max_rounds=max_rounds,
        )
        self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)

    def _instrumented_get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        attempt: int = 1,
        endpoint_class: str = "/shodan/host/search",
    ) -> httpx.Response:
        """GET with one RequestLedger row per physical attempt (no secrets)."""
        import time

        from aipocket.services.http_transport import record_sync_attempt

        started = time.perf_counter()
        error_class = ""
        status_code: int | None = None
        response_bytes = 0
        try:
            r = self._client.get(url, params=params)
            status_code = r.status_code
            response_bytes = len(r.content or b"")
            return r
        except httpx.TimeoutException:
            error_class = "timeout"
            raise
        except httpx.HTTPError:
            error_class = "network"
            raise
        finally:
            record_sync_attempt(
                method="GET",
                url=url,
                stage="discovery",
                source="shodan",
                status_code=status_code,
                error_class=error_class,
                latency_ms=int((time.perf_counter() - started) * 1000),
                attempt=attempt,
                endpoint_class=endpoint_class,
                response_bytes=response_bytes,
                query_id=self.query_id,
            )

    @property
    def _dead(self) -> set[str]:
        """Compatibility for callers/tests that inspect ``client._dead``."""
        return self._pool.dead

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
        Keys with zero query_credits are still reported but skipped for future
        search/count traffic (count is free, but a 0-credit key often 401s on
        search and burns rotation slots).
        """
        url = f"{self.base_url}/api-info"
        per_key: list[dict[str, Any]] = []
        for key in self.keys:
            if key in self._pool.dead:
                continue
            self._pool.throttle()
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
                credits = int(data.get("query_credits", 0) or 0)
                data["query_credits"] = credits
                per_key.append(data)
                if credits <= 0:
                    # Keep key out of search/count rotation for this client lifetime.
                    self._pool.mark_dead(key, "query_credits=0 (skip for this run)")
                continue
            if r.status_code in (401, 403):
                body = r.text[:300]
                if _is_credits_exhausted(r.status_code, body):
                    self._pool.mark_dead(key, f"credits exhausted ({body[:120]})")
                else:
                    self._pool.mark_dead(key, f"invalid (HTTP {r.status_code})")
        if not per_key:
            return {}
        total = sum(int(k.get("query_credits", 0) or 0) for k in per_key)
        return {
            "keys": per_key,
            "total_query_credits": total,
            "n_keys": len(self.keys),
            "n_dead": len(self._pool.dead),
        }

    def count(self, query: str) -> int | None:
        """Total matches for a query WITHOUT consuming query credits.

        Returns ``None`` when the count endpoint itself failed (network error,
        all keys dead, non-200 / non-JSON) — callers MUST treat ``None`` as
        "unknown, proceed with search" so a transient Shodan hiccup doesn't
        silently drop a live query. Returns ``0`` ONLY when Shodan explicitly
        reported zero matches (safe to skip).
        """
        self.query_id = query
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
        *,
        max_cursor_restarts: int = 1,
    ) -> list[dict[str, Any]]:
        """Paginate a Shodan host search.

        If Shodan reports a search-cursor timeout mid-pagination, restart the
        query from page 1 (up to ``max_cursor_restarts`` times) and merge
        results with de-duplication so earlier pages are not lost.
        """
        self.query_id = query
        pages = pages or settings.shodan_max_pages
        all_results: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        restarts = 0
        page = 1

        while page <= pages:
            try:
                data = self._request(
                    "/shodan/host/search",
                    {"query": query, "page": page, "minify": "false"},
                )
            except SearchCursorTimedOut:
                # Retrying the same page never works — Shodan requires page 1.
                if page <= 1 or restarts >= max_cursor_restarts:
                    log.warning(
                        "  shodan cursor timed out at page %d "
                        "(restarts=%d/%d); keeping %d partial results",
                        page,
                        restarts,
                        max_cursor_restarts,
                        len(all_results),
                    )
                    break
                restarts += 1
                log.warning(
                    "  shodan cursor timed out at page %d; "
                    "restarting query from page 1 (restart %d/%d, have %d hits)",
                    page,
                    restarts,
                    max_cursor_restarts,
                    len(all_results),
                )
                page = 1
                continue

            if data is None:
                break

            matches = data.get("matches", []) or []
            if not matches:
                log.info("  shodan page %d: empty, stopping", page)
                break

            mapped = [map_match(m) for m in matches]
            added = 0
            for row in mapped:
                key = _result_dedupe_key(row)
                if key in seen:
                    continue
                seen.add(key)
                all_results.append(row)
                added += 1
            total = data.get("total", 0)
            log.info(
                "  shodan page %d: +%d (unique +%d, total est. %s)",
                page,
                len(mapped),
                added,
                total,
            )

            if len(matches) < 100:
                break
            page += 1
            # Interval between pages is enforced by KeyPool.throttle on the next
            # request; no extra sleep needed here.

        return all_results

    def _request(self, path: str, params: dict[str, Any]) -> dict[str, Any] | None:
        url = f"{self.base_url}{path}"
        last_err = ""
        rate_limit_hits = 0
        max_attempts = self._pool.max_attempts()

        for attempt in range(1, max_attempts + 1):
            key = self._pool.pick()
            if key is None:
                last_err = last_err or "no live keys"
                break

            self._pool.throttle()
            req_params = {**params, "key": key}
            # Map path to a stable endpoint_class without query secrets.
            ep = path if path.startswith("/") else f"/{path}"
            try:
                r = self._instrumented_get(
                    url,
                    params=req_params,
                    attempt=attempt,
                    endpoint_class=ep,
                )
            except httpx.HTTPError as e:
                last_err = f"network: {e}"
                log.warning("  shodan key %s… network error: %s", key[:6], e)
                # Short cooldown so we don't spin on a broken network path.
                self._pool.cooldown(key, 0.5)
                continue

            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    last_err = f"non-json: {r.text[:200]}"
                    log.warning("  shodan key %s… %s", key[:6], last_err)
                    continue

            body = r.text[:300]
            last_err = f"HTTP {r.status_code}: {body[:200]}"

            # Cursor expiry is not key-specific and never recovers on the same
            # page — surface immediately so search() can restart from page 1.
            if _is_cursor_timeout(body):
                log.warning(
                    "  shodan key %s… search cursor timed out (page=%s)",
                    key[:6],
                    params.get("page", "?"),
                )
                raise SearchCursorTimedOut(last_err)

            if r.status_code in (401, 403):
                if _is_credits_exhausted(r.status_code, body):
                    self._pool.mark_dead(
                        key, f"credits exhausted (HTTP {r.status_code}: {body[:120]})"
                    )
                else:
                    self._pool.mark_dead(key, f"invalid key ({last_err})")
                continue

            if r.status_code == 429:
                rate_limit_hits += 1
                delay = rate_limit_backoff(
                    rate_limit_hits,
                    base=max(self._pool.min_interval, 1.0),
                )
                log.warning(
                    "  shodan key %s… rate limited, backing off %.1fs (attempt %d/%d)",
                    key[:6],
                    delay,
                    attempt,
                    max_attempts,
                )
                self._pool.cooldown(key, delay)
                continue

            # Hard client errors (malformed query etc.) — don't burn all keys.
            if 400 <= r.status_code < 500:
                log.warning("  shodan key %s… %s", key[:6], last_err)
                return None

            log.warning("  shodan key %s… %s", key[:6], last_err)
            self._pool.cooldown(key, 1.0)

        log.error("  shodan all keys failed for %s: %s", path, last_err)
        return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
