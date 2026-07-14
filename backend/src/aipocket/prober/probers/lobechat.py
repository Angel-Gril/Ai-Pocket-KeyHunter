"""LobeChat prober — environment variable leak via /api/config."""

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
        id="lobechat.unauth",
        product="lobechat",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": ["/api/config", "/api/client/config", "/api/env", "/api/market"],
            "tag_prefix": "lobechat",
        },
        max_requests=5,
    ),
    # L2/L3 minimal surfaces
    ssrf_spec(
        "lobechat",
        path="/api/proxy",
        url_param="url",
        body={},
        use_auth=False,
        suffix="ssrf_proxy",
    ),
    sqli_spec(
        "lobechat",
        path="/api/user/list",
        param="q",
        use_auth=False,
        suffix="sqli_user",
    ),
    rce_spec(
        "lobechat",
        path="/api/debug/exec",
        param="command",
        use_auth=False,
        suffix="rce_debug",
    ),
]


class LobeChatProber(Prober):
    product_name = "lobechat"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "lobe-chat" in blob or "lobechat" in blob or "lobehub" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
