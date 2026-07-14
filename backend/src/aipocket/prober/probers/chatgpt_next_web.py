"""ChatGPT-Next-Web / NextChat prober — frontend env/config key leaks."""

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
        id="chatgpt-next-web.unauth",
        product="chatgpt-next-web",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/",
                "/api/config",
                "/api/openai",
                "/api/openai/v1/models",
                "/.env",
                "/api/auth",
            ],
            "tag_prefix": "chatgpt_next_web",
        },
        max_requests=8,
    ),
    ProbeSpec(
        id="chatgpt-next-web.weak_password",
        product="chatgpt-next-web",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            # Access-code style gate used by many NextChat deployments
            "auth_style": "login_json",
            "login": "/api/auth",
            "body": {"password": "{pass}", "code": "{pass}"},
            "token_fields": ["token", "access_token", "status"],
            "post_auth_paths": ["/api/config", "/api/openai/v1/models"],
            "extra_credentials": [
                ("", "123456"),
                ("", "password"),
                ("", "admin"),
            ],
        },
        max_requests=10,
    ),
    # L2/L3 minimal surfaces
    ssrf_spec(
        "chatgpt-next-web",
        path="/api/proxy",
        url_param="url",
        body={},
        use_auth=False,
        suffix="ssrf_proxy",
    ),
    sqli_spec(
        "chatgpt-next-web",
        path="/api/openai",
        param="path",
        use_auth=False,
        suffix="sqli_openai_path",
    ),
    rce_spec(
        "chatgpt-next-web",
        path="/api/run",
        param="command",
        use_auth=False,
        suffix="rce_run",
    ),

]


class ChatGPTNextWebProber(Prober):
    product_name = "chatgpt-next-web"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return any(
            token in blob
            for token in (
                "nextchat",
                "chatgpt-next-web",
                "chatgpt next web",
                "next-web",
                "next chat",
            )
        )

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
