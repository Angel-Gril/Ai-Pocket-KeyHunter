"""Shared L2/L3 ProbeSpec builders for product adapters.

These are audited *minimal* surfaces only (fixed paths / read-only payloads).
They do nothing unless RiskPolicy enables SSRF/SQLi/RCE and max_risk allows.
"""

from __future__ import annotations

from ..capability import ProbeSpec, RiskLevel, VulnClass


def ssrf_spec(
    product: str,
    *,
    path: str,
    method: str = "POST",
    url_param: str = "url",
    body: dict | None = None,
    use_auth: bool = False,
    cve_ids: tuple[str, ...] = (),
    suffix: str = "ssrf",
    max_requests: int = 3,
) -> ProbeSpec:
    return ProbeSpec(
        id=f"{product}.{suffix}",
        product=product,
        vuln_class=VulnClass.SSRF,
        risk_level=RiskLevel.L2,
        cve_ids=cve_ids,
        entry={
            "path": path,
            "method": method,
            "url_param": url_param,
            "body": body or {},
            "target_urls": ["http://127.0.0.1/", "http://localhost/"],
            "use_auth": use_auth,
            "success_markers": ["127.0.0.1", "localhost", "api_key", "OPENAI", "sk-"],
        },
        max_requests=max_requests,
    )


def sqli_spec(
    product: str,
    *,
    path: str,
    param: str = "id",
    method: str = "GET",
    use_auth: bool = False,
    cve_ids: tuple[str, ...] = (),
    suffix: str = "sqli",
    max_requests: int = 4,
) -> ProbeSpec:
    return ProbeSpec(
        id=f"{product}.{suffix}",
        product=product,
        vuln_class=VulnClass.SQLI,
        risk_level=RiskLevel.L2,
        cve_ids=cve_ids,
        entry={
            "path": path,
            "method": method,
            "param": param,
            "baseline": "1",
            # Read-only proof templates only (engine also bans write keywords).
            "payloads": ["' OR '1'='1", "'", "1 OR 1=1"],
            "use_auth": use_auth,
        },
        max_requests=max_requests,
    )


def rce_spec(
    product: str,
    *,
    path: str,
    param: str = "command",
    method: str = "POST",
    use_auth: bool = False,
    cve_ids: tuple[str, ...] = (),
    suffix: str = "rce",
    max_requests: int = 2,
) -> ProbeSpec:
    return ProbeSpec(
        id=f"{product}.{suffix}",
        product=product,
        vuln_class=VulnClass.RCE,
        risk_level=RiskLevel.L3,
        cve_ids=cve_ids,
        entry={
            "path": path,
            "method": method,
            "param": param,
            "proof_command": "echo aipocket-rce-proof",
            "secret_commands": ["printenv", "cat /.env"],
            "body": {},
            "use_auth": use_auth,
        },
        max_requests=max_requests,
    )
