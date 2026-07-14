"""L0 unauthenticated config/key path reads."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .common import EngineResult, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext


async def run_unauth_read(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    paths: list[str] = list(spec.entry.get("paths") or ())
    params_by_path: dict[str, dict[str, Any]] = dict(spec.entry.get("params") or {})
    # Optional multi-value param expansion, e.g. organizationId in {"", "1", "default"}
    expand: dict[str, list[str]] = dict(spec.entry.get("expand_params") or {})
    tag_prefix = spec.entry.get("tag_prefix") or f"{spec.product}_unauth"
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed

    if expand:
        # First path with expand: try until credentials found or variants exhausted
        path = paths[0] if paths else ""
        param_name, variants = next(iter(expand.items()))
        for variant in variants:
            url = prober._url(ctx.hit, path)
            params = {param_name: variant} if variant else {}
            resp = await prober._get(url, params=params)
            result.requests_used = prober.budget_consumed - before
            if resp and resp.status_code == 200 and len(resp.text or "") > 50:
                found = prober._extract_from_response(
                    resp, ctx.hit, f"{tag_prefix}_{path.strip('/').replace('/', '_') or 'root'}"
                )
                if found:
                    result.credentials.extend(found)
                    result.findings.append(
                        make_finding(
                            vuln_class=spec.vuln_class,
                            product=spec.product,
                            target_origin=origin,
                            spec_id=spec.id,
                            cve_ids=spec.cve_ids,
                            confirmed=True,
                            summary=f"Unauth read leaked credentials via {path}",
                            credentials=found,
                            evidence={"path": path, "param": param_name, "variant": variant},
                        )
                    )
                    break
        # Remaining fixed paths
        for path in paths[1:]:
            if result.requests_used >= spec.max_requests:
                break
            resp = await prober._get(prober._url(ctx.hit, path), params=params_by_path.get(path))
            result.requests_used = prober.budget_consumed - before
            found = prober._extract_from_response(
                resp, ctx.hit, f"{tag_prefix}_{path.strip('/').replace('/', '_')}"
            )
            result.credentials.extend(found)
        return result

    for path in paths:
        if result.requests_used >= spec.max_requests:
            break
        resp = await prober._get(prober._url(ctx.hit, path), params=params_by_path.get(path))
        result.requests_used = prober.budget_consumed - before
        found = prober._extract_from_response(
            resp, ctx.hit, f"{tag_prefix}_{path.strip('/').replace('/', '_')}"
        )
        result.credentials.extend(found)

    if result.credentials:
        result.findings.append(
            make_finding(
                vuln_class=spec.vuln_class,
                product=spec.product,
                target_origin=origin,
                spec_id=spec.id,
                cve_ids=spec.cve_ids,
                confirmed=True,
                summary=f"Unauthenticated read returned credentials ({len(result.credentials)})",
                credentials=result.credentials,
                evidence={"paths": paths},
            )
        )
    return result
