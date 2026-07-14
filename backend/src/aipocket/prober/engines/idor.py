"""L1 IDOR — object-level unauthorized/low-privilege reads.

Post-auth reads of *own* resources belong in weak_password; this engine only
handles list + object ID enumeration against isolation boundaries.

Confirmation semantics (a finding is evidence of a *vulnerability*, not merely
that we sent some requests):

- Enumerating IDs and getting 401/403/404 back is NOT IDOR — it is the access
  control *working*. Those runs produce a telemetry-only outcome (``reason``),
  never a finding.
- A finding requires a **successful object response** (HTTP 200) plus a
  **privilege-boundary** signal: the same object is re-read with NO auth, and
  the unauthenticated context can also read it (200, or the same credential is
  recovered). That demonstrates a context lacking authorization reaching the
  resource, which is the actual IDOR condition.
- "Surface exercised" (candidate IDs + a template but no authorized-vs-unauth
  gap) is reported via ``reason`` for observability, not as a finding.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .common import EngineResult, format_path, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext


def _collect_ids_from_json(data: Any, id_fields: list[str], limit: int) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            for field in id_fields:
                val = node.get(field)
                if val is not None and str(val) and str(val) not in found:
                    found.append(str(val))
                    if len(found) >= limit:
                        return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return found


async def run_idor(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    entry = spec.entry
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed
    id_enum_max = min(int(entry.get("id_enum_max", 5)), 5)
    id_fields = list(entry.get("id_fields") or ["id", "_id", "uuid", "keyId", "chatflowId"])
    headers: dict[str, str] = {}
    if entry.get("use_auth", True) and ctx.auth_headers:
        headers = dict(ctx.auth_headers)
    # Explicit unauth IDOR (omit auth even if session exists)
    if entry.get("force_unauth"):
        headers = {}

    object_ids: list[str] = list(ctx.object_ids)

    # 1) List endpoint → harvest IDs
    list_path = entry.get("list")
    if list_path and result.requests_used < spec.max_requests:
        resp = await prober._get(prober._url(ctx.hit, list_path), headers=headers or None)
        result.requests_used = prober.budget_consumed - before
        if resp is not None and resp.status_code == 200:
            # Credentials may already be in the list response
            found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_idor_list")
            result.credentials.extend(found)
            try:
                data = resp.json()
            except ValueError:
                data = None
            if data is not None:
                object_ids.extend(_collect_ids_from_json(data, id_fields, id_enum_max))

    # 2) Predictable candidates
    predictable = list(entry.get("predictable_ids") or [str(i) for i in range(1, id_enum_max + 1)])
    for pid in predictable:
        if pid not in object_ids:
            object_ids.append(pid)
    object_ids = object_ids[:id_enum_max]
    ctx.object_ids = list(dict.fromkeys(ctx.object_ids + object_ids))

    # 3) Object reads — track objects that actually returned 200 (a successful
    #    object response is a precondition for any IDOR claim).
    object_template = entry.get("object") or entry.get("object_path") or ""
    successful_ids: list[str] = []
    for oid in object_ids:
        if result.requests_used >= spec.max_requests:
            break
        if not object_template:
            break
        path = format_path(object_template, id=oid)
        resp = await prober._get(prober._url(ctx.hit, path), headers=headers or None)
        result.requests_used = prober.budget_consumed - before
        if resp is not None and resp.status_code == 200:
            successful_ids.append(oid)
            found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_idor_{oid}")
            result.credentials.extend(found)

    # 4) Privilege-boundary proof: re-read the successful objects with NO auth.
    #    If an unauthenticated context can also read them, that is genuine broken
    #    object-level authorization (not "we read our own resource").
    cross_auth_ids: list[str] = []
    cross_auth_creds = 0
    if successful_ids and object_template and headers:
        for oid in successful_ids:
            if result.requests_used >= spec.max_requests:
                break
            path = format_path(object_template, id=oid)
            unauth = await prober._get(prober._url(ctx.hit, path), headers=None)
            result.requests_used = prober.budget_consumed - before
            if unauth is not None and unauth.status_code == 200:
                cross_auth_ids.append(oid)
                found = prober._extract_from_response(
                    unauth, ctx.hit, f"{spec.product}_idor_unauth_{oid}"
                )
                if found:
                    cross_auth_creds += len(found)
                    result.credentials.extend(found)
    elif successful_ids and object_template and not headers:
        # Already unauthenticated (force_unauth / no session): a 200 here is
        # itself an unauthorized object read — the objects ARE the boundary proof.
        cross_auth_ids = list(successful_ids)

    confirmed = bool(cross_auth_ids)
    if confirmed:
        result.findings.append(
            make_finding(
                vuln_class=spec.vuln_class,
                product=spec.product,
                target_origin=origin,
                spec_id=spec.id,
                cve_ids=spec.cve_ids,
                confirmed=True,
                summary=(
                    f"IDOR: {len(cross_auth_ids)} object(s) readable across an "
                    f"authorization boundary"
                    + (f"; {cross_auth_creds} credential(s) exposed" if cross_auth_creds else "")
                ),
                severity="high" if cross_auth_creds else "medium",
                credentials=result.credentials,
                evidence={
                    "cross_auth_object_ids": cross_auth_ids[:id_enum_max],
                    "authorized_object_ids": successful_ids[:id_enum_max],
                    "list": list_path,
                },
            )
        )
    elif successful_ids:
        # We read objects with our own session but could not prove a boundary
        # crossing — own-resource read, not IDOR. Telemetry only.
        result.reason = (
            f"authorized object reads only ({len(successful_ids)}); "
            "no unauthorized cross-boundary access proven"
        )
    else:
        result.reason = "no successful object response (access control held)"
    return result
