"""OpenWebUI prober — config + model endpoint exposure.

OpenWebUI instances frequently expose:
  - GET /api/config → server configuration
  - GET /api/v1/models → model list (sometimes includes API keys)
  - GET /api/config/banners → check it's OpenWebUI
"""

from __future__ import annotations

import logging
from typing import Any

from ...models import Credential
from ..base import Prober

log = logging.getLogger(__name__)


class OpenWebUIProber(Prober):
    product_name = "openwebui"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "open webui" in blob or "open-webui" in blob or "openwebui" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        for path in ("/api/config", "/api/v1/models", "/ollama/api/tags"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"openwebui_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        return creds
