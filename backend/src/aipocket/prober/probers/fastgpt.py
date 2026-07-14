"""FastGPT prober — system config + open API + optional weak admin."""

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
        id="fastgpt.unauth",
        product="fastgpt",
        vuln_class=VulnClass.UNAUTH_READ,
        risk_level=RiskLevel.L0,
        entry={
            "paths": [
                "/api/systemConfig",
                "/api/openapi",
                "/api/v1/models",
                "/api/getInitData",
                "/api/common/system/getInitData",
            ],
            "tag_prefix": "fastgpt",
        },
        max_requests=6,
    ),
    ProbeSpec(
        id="fastgpt.weak_password",
        product="fastgpt",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/support/user/account/loginByPassword",
            "body": {"username": "{user}", "password": "{pass}"},
            "token_fields": ["token", "access_token"],
            "post_auth_paths": [
                "/api/support/user/account/tokenLogin",
                "/api/core/dataset/list",
                "/api/support/openapi/list",
            ],
        },
        max_requests=12,
    ),
    # L2/L3 minimal surfaces
    ssrf_spec(
        "fastgpt",
        path="/api/common/file/uploadLink",
        url_param="url",
        body={},
        use_auth=True,
        suffix="ssrf_upload_link",
    ),
    sqli_spec(
        "fastgpt",
        path="/api/core/dataset/list",
        param="searchText",
        use_auth=True,
        suffix="sqli_dataset",
    ),
    rce_spec(
        "fastgpt",
        path="/api/core/plugin/run",
        param="code",
        use_auth=True,
        suffix="rce_plugin",
    ),

]


class FastGPTProber(Prober):
    product_name = "fastgpt"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "fastgpt" in blob or "fast-gpt" in blob or "fast gpt" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, SPECS)
