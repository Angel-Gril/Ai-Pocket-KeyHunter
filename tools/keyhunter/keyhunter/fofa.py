from __future__ import annotations

import base64
from typing import Any, Self

import httpx

from keyhunter.config import BROWSER_USER_AGENT, Settings
from keyhunter.util import normalize_origin


class FofaClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._owns = http is None
        self.http = http or httpx.Client(
            timeout=settings.timeout,
            proxy=settings.proxy,
            headers={"User-Agent": BROWSER_USER_AGENT},
        )

    def close(self) -> None:
        if self._owns:
            self.http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def search(
        self, query: str, page: int = 1, size: int | None = None
    ) -> dict[str, Any]:
        if not self.settings.fofa_key:
            raise RuntimeError("FOFA_KEY is not set (copy .env.example → .env)")
        size = size or self.settings.fofa_page_size
        qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
        params: dict[str, str | int] = {
            "key": self.settings.fofa_key,
            "qbase64": qbase64,
            "page": page,
            "size": size,
            "fields": "host,ip,port,protocol,title,header,banner,server,product,link,domain,cert",
        }
        if self.settings.fofa_email:
            params["email"] = self.settings.fofa_email
        resp = self.http.get(
            f"{self.settings.fofa_base_url}/api/v1/search/all", params=params
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            raise RuntimeError(f"FOFA API error: {data.get('errmsg') or data}")
        return data

    def search_all(
        self, query: str, max_pages: int | None = None
    ) -> list[dict[str, Any]]:
        pages = max_pages or self.settings.fofa_max_pages
        hits: list[dict[str, Any]] = []
        seen: set[str] = set()
        for page in range(1, pages + 1):
            payload = self.search(query, page=page)
            rows = payload.get("results") or []
            if not rows:
                break
            fields = [
                f.strip()
                for f in (
                    payload.get("fields")
                    or "host,ip,port,protocol,title,header,banner,server,product,link,domain,cert"
                ).split(",")
            ]
            for row in rows:
                if not isinstance(row, list):
                    continue
                item = {
                    fields[i]: row[i] if i < len(row) else ""
                    for i in range(len(fields))
                }
                origin = normalize_origin(
                    str(item.get("host") or item.get("link") or ""),
                    str(item.get("ip") or ""),
                    item.get("port"),
                    str(item.get("protocol") or "") or None,
                )
                if not origin or origin in seen:
                    continue
                seen.add(origin)
                item["origin"] = origin
                item["query"] = query
                hits.append(item)
            size = int(payload.get("size") or self.settings.fofa_page_size)
            if len(rows) < size:
                break
        return hits
