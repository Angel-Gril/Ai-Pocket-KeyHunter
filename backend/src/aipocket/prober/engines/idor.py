"""L1 IDOR — object-level unauthorized/low-privilege reads.

Post-auth reads of *own* resources belong in weak_password; this engine only
handles list + object ID enumeration against isolation boundaries.
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

    # 3) Object reads
    object_template = entry.get("object") or entry.get("object_path") or ""
    for oid in object_ids:
        if result.requests_used >= spec.max_requests:
            break
        if not object_template:
            break
        path = format_path(object_template, id=oid)
        resp = await prober._get(prober._url(ctx.hit, path), headers=headers or None)
        result.requests_used = prober.budget_consumed - before
        found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_idor_{oid}")
        result.credentials.extend(found)

    confirmed = bool(result.credentials) or bool(object_ids and object_template)
    if confirmed:
        result.findings.append(
            make_finding(
                vuln_class=spec.vuln_class,
                product=spec.product,
                target_origin=origin,
                spec_id=spec.id,
                cve_ids=spec.cve_ids,
                confirmed=bool(result.credentials),
                summary=(
                    f"IDOR object reads executed ({len(object_ids)} ids)"
                    + (f"; {len(result.credentials)} credentials" if result.credentials else "")
                ),
                severity="high" if result.credentials else "medium",
                credentials=result.credentials,
                evidence={"object_ids": object_ids[:id_enum_max], "list": list_path},
            )
        )
    else:
        result.reason = "no idor surface exercised"
    return result
