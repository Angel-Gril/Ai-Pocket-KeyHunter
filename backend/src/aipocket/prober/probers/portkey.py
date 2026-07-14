"""Portkey AI Gateway prober — gateway status/config/key exposure."""

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
        id="portkey.unauth",
        product="portkey",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/v1/models",
                "/v1/health",
                "/health",
                "/v1/config",
                "/api/config",
                "/v1/keys",
                "/.env",
            ],
            "tag_prefix": "portkey",
        },
        max_requests=8,
    ),
    ProbeSpec(
        id="portkey.weak_password",
        product="portkey",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "hybrid",
            "bearer_paths": ["/v1/keys", "/v1/config", "/api/config"],
            "login": "/v1/auth/login",
            "body": {"email": "{user}", "password": "{pass}", "username": "{user}"},
            "token_fields": ["token", "access_token", "api_key", "key"],
            "post_auth_paths": ["/v1/keys", "/v1/config", "/api/config"],
        },
        max_requests=14,
    ),
    # L2/L3 minimal surfaces (gateway proxy / config)
    ssrf_spec(
        "portkey",
        path="/v1/proxy",
        url_param="url",
        body={},
        use_auth=True,
        suffix="ssrf_proxy",
    ),
    sqli_spec(
        "portkey",
        path="/v1/logs",
        param="q",
        use_auth=True,
        suffix="sqli_logs",
    ),
    rce_spec(
        "portkey",
        path="/v1/debug/exec",
        param="command",
        use_auth=True,
        suffix="rce_debug",
    ),
]


class PortkeyProber(Prober):
    product_name = "portkey"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "portkey" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
