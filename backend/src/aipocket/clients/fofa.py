from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from aipocket.clients.key_pool import KeyPool, rate_limit_backoff
from aipocket.core.config import settings

log = logging.getLogger(__name__)

DEFAULT_FIELDS = "host,ip,port,protocol,title,header,banner,server,product,link,domain,cert"

# FOFA / fofoapi often return HTTP 200 with error payload in body.
_QUOTA_MARKERS = (
    "已用完",
    "账号无效",
    "F点不足",
    "f点不足",
    "额度不足",
    "请求次数已用完",
    "无权限",
)
_INVALID_KEY_MARKERS = (
    "key 不存在",
    "key不存在",
    "[-700]",  # common FOFA invalid-key code text
    "api key error",
    "invalid key",
)
# fofoapi / FOFA upstream overload — transient; never mark key dead.
_BUSY_MARKERS = (
    "[-501]",
    "系统繁忙",
    "service unavailable",
    "temporarily unavailable",
)
_BUSY_HTTP_STATUS = frozenset({502, 503, 504})


def _rows_to_dicts(rows: list[Any], field_names: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            out.append(row)
            continue
        if isinstance(row, list):
            d: dict[str, Any] = {}
            for i, name in enumerate(field_names):
                d[name] = row[i] if i < len(row) else ""
            out.append(d)
            continue
        out.append({"_raw": str(row)})
    return out


def _errmsg_of(data: dict[str, Any], raw_text: str) -> str:
    for k in ("errmsg", "message", "msg", "error"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, bool):
            continue
    return raw_text[:200]


def _is_quota_error(text: str) -> bool:
    return any(m in text for m in _QUOTA_MARKERS)


def _is_invalid_key(text: str) -> bool:
    low = text.lower()
    return any(m.lower() in low for m in _INVALID_KEY_MARKERS)


def _is_busy_error(status_code: int, text: str) -> bool:
    """True for fofoapi/FOFA system-busy responses (HTTP 503 + [-501], etc.)."""
    if status_code in _BUSY_HTTP_STATUS:
        return True
    low = text.lower()
    return any(m.lower() in low for m in _BUSY_MARKERS)


class FofaClient:
    def __init__(
        self,
        keys: list[str] | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        *,
        min_interval: float | None = None,
        max_rounds: int = 3,
    ):
        if keys is None:
            keys = settings.keys
        if not keys:
            raise RuntimeError("No FOFA keys configured. Set FOFA_KEYS in .env")
        self.keys = keys
        self.base_url = (base_url or settings.fofa_base_url).rstrip("/")
        self.timeout = timeout or settings.fofa_timeout
        # Tests may pass min_interval=0 to disable sleeping.
        if min_interval is None:
            interval = max(float(settings.fofa_page_delay), 0.0)
        else:
            interval = max(float(min_interval), 0.0)
        self._pool = KeyPool(
            keys,
            min_interval=interval,
            label="fofa key",
            max_rounds=max_rounds,
        )
        self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)

    @property
    def _dead(self) -> set[str]:
        """Compatibility for callers/tests that inspect ``client._dead``."""
        return self._pool.dead

    def info(self) -> dict[str, Any]:
        """Per-key ``/api/v1/info/my`` aggregation (best-effort, no search cost).

        Returns::
            {
              "keys": [{...api fields..., "_key_masked": "..."}, ...],
              "total_remain_api_query": int,
              "total_remain_api_data": int,
              "n_keys": int, "n_dead": int,
            }
        """
        url = f"{self.base_url}/api/v1/info/my"
        per_key: list[dict[str, Any]] = []
        for key in self.keys:
            if key in self._pool.dead:
                continue
            self._pool.throttle()
            try:
                r = self._client.get(url, params={"key": key})
            except httpx.HTTPError as e:
                log.warning("  fofa key %s… info network error: %s", key[:6], e)
                continue
            if r.status_code != 200:
                if r.status_code in (401, 403):
                    self._pool.mark_dead(key, f"info HTTP {r.status_code}")
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            if data.get("error") is True:
                msg = _errmsg_of(data, r.text)
                if _is_quota_error(msg) or _is_invalid_key(msg):
                    self._pool.mark_dead(key, msg)
                continue
            data["_key_masked"] = f"{key[:6]}…{key[-4:]}"
            per_key.append(data)
            # Soft skip keys with no remaining query budget.
            remain_q = data.get("remain_api_query")
            try:
                if remain_q is not None and int(remain_q) <= 0:
                    self._pool.mark_dead(key, "remain_api_query=0 (skip for this run)")
            except (TypeError, ValueError):
                pass
        if not per_key:
            return {}
        return {
            "keys": per_key,
            "total_remain_api_query": sum(int(k.get("remain_api_query", 0) or 0) for k in per_key),
            "total_remain_api_data": sum(int(k.get("remain_api_data", 0) or 0) for k in per_key),
            "n_keys": len(self.keys),
            "n_dead": len(self._pool.dead),
        }

    def search(
        self,
        query: str,
        pages: int | None = None,
        size: int | None = None,
        fields: str = DEFAULT_FIELDS,
    ) -> list[dict[str, Any]]:
        pages = pages or settings.fofa_max_pages
        size = size or settings.fofa_page_size
        qbase64 = base64.b64encode(query.encode()).decode()
        field_names = [f.strip() for f in fields.split(",")]
        all_results: list[dict[str, Any]] = []

        for page in range(1, pages + 1):
            data = self._request_page(qbase64, page, size, fields)
            if data is None:
                break

            raw_rows = data.get("results", [])
            if not raw_rows:
                log.info("  page %d: empty, stopping", page)
                break

            mapped = _rows_to_dicts(raw_rows, field_names)
            all_results.extend(mapped)
            total = data.get("size", 0)
            log.info("  page %d: +%d (total est. %s)", page, len(mapped), total)

            if len(raw_rows) < size:
                break
            if len(all_results) >= 10000:
                log.warning("  hit 10000 cap, stopping")
                break
            # Inter-page spacing is handled by KeyPool.throttle on next request.

        return all_results

    def _busy_backoff(self, busy_hits: int) -> float:
        """Exponential backoff for system-busy (base ≥1s, cap 8s).

        Sequence with default base: 1s → 2s → 4s → 8s → 8s …
        Cap stays short so a single-key pool does not stall a whole page for 30s;
        multi-key pools already rotate while the failing key cools down.
        """
        return rate_limit_backoff(
            busy_hits,
            base=max(self._pool.min_interval, 1.0),
            cap=8.0,
        )

    def _request_page(
        self, qbase64: str, page: int, size: int, fields: str
    ) -> dict[str, Any] | None:
        url = f"{self.base_url}/api/v1/search/all"
        last_err = ""
        rate_limit_hits = 0
        busy_hits = 0
        max_attempts = self._pool.max_attempts()

        for attempt in range(1, max_attempts + 1):
            key = self._pool.pick()
            if key is None:
                last_err = last_err or "no live keys"
                break

            self._pool.throttle()
            params = {
                "qbase64": qbase64,
                "key": key,
                "page": page,
                "size": size,
                "fields": fields,
            }
            try:
                r = self._client.get(url, params=params)
            except httpx.HTTPError as e:
                last_err = f"network: {e}"
                log.warning("  fofa key %s… network error: %s", key[:6], e)
                self._pool.cooldown(key, 0.5)
                continue

            if r.status_code == 429:
                rate_limit_hits += 1
                delay = rate_limit_backoff(
                    rate_limit_hits,
                    base=max(self._pool.min_interval, 0.5),
                )
                last_err = f"HTTP 429: {r.text[:200]}"
                log.warning(
                    "  fofa key %s… rate limited, backing off %.1fs (attempt %d/%d)",
                    key[:6],
                    delay,
                    attempt,
                    max_attempts,
                )
                self._pool.cooldown(key, delay)
                continue

            # HTTP 503 + [-501] 系统繁忙 (and 502/504) — longer backoff, rotate key.
            if _is_busy_error(r.status_code, r.text):
                busy_hits += 1
                delay = self._busy_backoff(busy_hits)
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                log.warning(
                    "  fofa key %s… system busy, backing off %.1fs (attempt %d/%d)",
                    key[:6],
                    delay,
                    attempt,
                    max_attempts,
                )
                self._pool.cooldown(key, delay)
                continue

            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                log.warning("  fofa key %s… %s", key[:6], last_err)
                if r.status_code in (401, 403):
                    self._pool.mark_dead(key, last_err)
                else:
                    self._pool.cooldown(key, 0.5)
                continue

            try:
                data = r.json()
            except ValueError:
                last_err = f"non-json: {r.text[:200]}"
                log.warning("  fofa key %s… %s", key[:6], last_err)
                continue

            # FOFA commonly returns HTTP 200 + {"error": true, "errmsg": "..."}
            if data.get("error") is True:
                msg = _errmsg_of(data, r.text)
                last_err = msg
                if _is_quota_error(msg):
                    self._pool.mark_dead(key, f"quota exhausted: {msg[:120]}")
                    continue
                if _is_invalid_key(msg):
                    self._pool.mark_dead(key, f"invalid key: {msg[:120]}")
                    continue
                if _is_busy_error(200, msg):
                    busy_hits += 1
                    delay = self._busy_backoff(busy_hits)
                    log.warning(
                        "  fofa key %s… system busy (%s), backing off %.1fs (attempt %d/%d)",
                        key[:6],
                        msg[:80],
                        delay,
                        attempt,
                        max_attempts,
                    )
                    self._pool.cooldown(key, delay)
                    continue
                # Transient / unknown API error — try next live key.
                log.warning("  fofa key %s… api error: %s", key[:6], msg[:160])
                self._pool.cooldown(key, 0.5)
                continue

            # Some gateways still embed Chinese errors without error=true.
            body_text = r.text
            if _is_quota_error(body_text):
                last_err = "quota exhausted or invalid account"
                self._pool.mark_dead(key, last_err)
                continue
            if _is_invalid_key(body_text):
                last_err = "key not found (wrong key)"
                self._pool.mark_dead(key, last_err)
                continue
            if _is_busy_error(200, body_text):
                busy_hits += 1
                delay = self._busy_backoff(busy_hits)
                last_err = body_text[:200]
                log.warning(
                    "  fofa key %s… system busy, backing off %.1fs (attempt %d/%d)",
                    key[:6],
                    delay,
                    attempt,
                    max_attempts,
                )
                self._pool.cooldown(key, delay)
                continue

            return data

        log.error("  fofa all keys failed for page %d: %s", page, last_err)
        return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
