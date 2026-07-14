"""OpenWebUI prober — config/models + weak admin + optional SSRF/RCE."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import Prober
from ..capability import ProbeSpec, RiskLevel, VulnClass
from ._l2l3 import rce_spec, sqli_spec

log = logging.getLogger(__name__)

SPECS = [
    ProbeSpec(
        id="openwebui.unauth",
        product="openwebui",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": ["/api/config", "/api/v1/models", "/ollama/api/tags", "/api/models"],
            "tag_prefix": "openwebui",
        },
        max_requests=5,
    ),
    ProbeSpec(
        id="openwebui.weak_password",
        product="openwebui",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/v1/auths/signin",
            "body": {"email": "{user}", "password": "{pass}"},
            "token_fields": ["token", "access_token"],
            "post_auth_paths": [
                "/api/v1/auths/",
                "/api/v1/models",
                "/api/v1/configs/export",
                "/api/config",
            ],
            "extra_credentials": [
                ("admin@localhost", "admin"),
                ("admin@admin.com", "admin"),
            ],
        },
        max_requests=14,
    ),
    ProbeSpec(
        id="openwebui.idor.users",
        product="openwebui",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        requires_auth=True,
        depends_on=("openwebui.weak_password",),
        entry={
            "list": "/api/v1/users/",
            "object": "/api/v1/users/{id}",
            "id_enum_max": 5,
            "id_fields": ["id", "user_id"],
            "use_auth": True,
        },
        max_requests=6,
    ),
    ProbeSpec(
        id="openwebui.ssrf.tools",
        product="openwebui",
        vuln_class=VulnClass.SSRF,
        risk_level=RiskLevel.L2,
        entry={
            "path": "/api/v1/tools/",
            "method": "POST",
            "url_param": "url",
            "body": {"name": "probe"},
            "target_urls": ["http://127.0.0.1/", "http://localhost/"],
            "use_auth": True,
        },
        max_requests=3,
    ),
    sqli_spec(
        "openwebui",
        path="/api/v1/users/",
        param="query",
        use_auth=True,
        suffix="sqli_users",
    ),
    rce_spec(
        "openwebui",
        path="/api/v1/pipelines/upload",
        param="code",
        use_auth=True,
        suffix="rce_pipelines",
    ),
]


class OpenWebUIProber(Prober):
    product_name = "openwebui"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "open webui" in blob or "open-webui" in blob or "openwebui" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
