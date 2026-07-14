"""OpenRouter (self-hosted mirror / gateway) prober — fingerprint + key leaks."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import Prober
from ..capability import ProbeSpec, RiskLevel, VulnClass
from ._l2l3 import rce_spec, sqli_spec, ssrf_spec

log = logging.getLogger(__name__)

SPECS = [
    ProbeSpec(
        id="openrouter.unauth",
        product="openrouter",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/api/v1/models",
                "/v1/models",
                "/api/v1/auth/key",
                "/api/v1/keys",
                "/api/config",
                "/.env",
                "/health",
            ],
            "tag_prefix": "openrouter",
        },
        max_requests=8,
    ),
    ProbeSpec(
        id="openrouter.weak_password",
        product="openrouter",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "hybrid",
            "bearer_paths": ["/api/v1/keys", "/api/v1/auth/key", "/api/config"],
            "login": "/api/auth/login",
            "body": {"email": "{user}", "password": "{pass}"},
            "token_fields": ["token", "access_token", "key"],
            "post_auth_paths": ["/api/v1/keys", "/api/v1/auth/key"],
        },
        max_requests=12,
    ),
    # L2/L3 minimal surfaces (self-hosted mirrors)
    ssrf_spec(
        "openrouter",
        path="/api/v1/fetch",
        url_param="url",
        body={},
        use_auth=True,
        suffix="ssrf_fetch",
    ),
    sqli_spec(
        "openrouter",
        path="/api/v1/keys",
        param="name",
        use_auth=True,
        suffix="sqli_keys",
    ),
    rce_spec(
        "openrouter",
        path="/api/admin/exec",
        param="command",
        use_auth=True,
        suffix="rce_admin",
    ),

]


class OpenRouterProber(Prober):
    product_name = "openrouter"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "openrouter" in blob or "open router" in blob or "sk-or-v1" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
