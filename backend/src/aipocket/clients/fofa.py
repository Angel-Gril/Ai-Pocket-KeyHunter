from __future__ import annotations

import base64
import itertools
import logging
import time
from typing import Any

import httpx

from aipocket.core.config import settings

log = logging.getLogger(__name__)

DEFAULT_FIELDS = "host,ip,port,protocol,title,header,banner,server,product,link,domain,cert"


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


class FofaClient:
    def __init__(
        self,
        keys: list[str] | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
    ):
        if keys is None:
            keys = settings.keys
        if not keys:
            raise RuntimeError("No FOFA keys configured. Set FOFA_KEYS in .env")
        self.keys = keys
        self.base_url = (base_url or settings.fofa_base_url).rstrip("/")
        self.timeout = timeout or settings.fofa_timeout
        self._key_cycle = itertools.cycle(self.keys)
        self._dead: set[str] = set()
        self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)

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
            time.sleep(0.3)

        return all_results

    def _request_page(
        self, qbase64: str, page: int, size: int, fields: str
    ) -> dict[str, Any] | None:
        url = f"{self.base_url}/api/v1/search/all"
        last_err = ""
        for _ in range(len(self.keys)):
            key = next(self._key_cycle)
            if key in self._dead:
                continue
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
                log.warning("  key %s… network error: %s", key[:6], e)
                continue

            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                log.warning("  key %s… %s", key[:6], last_err)
                continue

            try:
                data = r.json()
            except ValueError:
                last_err = f"non-json: {r.text[:200]}"
                log.warning("  key %s… %s", key[:6], last_err)
                continue

            body_text = r.text
            if "已用完" in body_text or "账号无效" in body_text:
                last_err = "quota exhausted or invalid account"
                log.error("  key %s… %s — STOP this key", key[:6], last_err)
                self._dead.add(key)
                continue
            if "key 不存在" in body_text or "key不存在" in body_text:
                last_err = "key not found (wrong key)"
                log.error("  key %s… %s", key[:6], last_err)
                self._dead.add(key)
                continue

            return data

        log.error("  all keys failed for page %d: %s", page, last_err)
        return None

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
