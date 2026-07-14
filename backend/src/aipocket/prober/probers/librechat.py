"""LibreChat prober — config reads + weak password + true IDOR on keys."""

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
        id="librechat.unauth",
        product="librechat",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": ["/api/config", "/api/endpoints", "/api/health"],
            "tag_prefix": "librechat",
        },
        max_requests=4,
    ),
    ProbeSpec(
        id="librechat.weak_password",
        product="librechat",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/auth/login",
            "body": {"email": "{user}", "password": "{pass}", "username": "{user}"},
            "token_fields": ["token", "access_token"],
            # Own resources after login — not IDOR
            "post_auth_paths": ["/api/keys", "/api/endpoints"],
        },
        max_requests=12,
    ),
    ProbeSpec(
        id="librechat.idor.keys",
        product="librechat",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        cve_ids=("CVE-2026-31942",),
        requires_auth=True,
        depends_on=("librechat.weak_password",),
        entry={
            "list": "/api/keys",
            "object": "/api/keys/{id}",
            "id_enum_max": 5,
            "id_fields": ["id", "_id", "userId", "keyId"],
            "use_auth": True,
        },
        max_requests=6,
    ),
    ssrf_spec(
        "librechat",
        path="/api/files/download",
        method="GET",
        url_param="url",
        use_auth=True,
        suffix="ssrf_files",
    ),
    ssrf_spec(
        "librechat",
        path="/api/agents/tools/call",
        url_param="url",
        body={"tool": "web_search"},
        use_auth=True,
        suffix="ssrf_agents",
    ),
    sqli_spec(
        "librechat",
        path="/api/messages",
        param="conversationId",
        use_auth=True,
        suffix="sqli_messages",
    ),
    rce_spec(
        "librechat",
        path="/api/run/code",
        param="code",
        use_auth=True,
        suffix="rce_code",
    ),
]


class LibreChatProber(Prober):
    product_name = "librechat"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "librechat" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
