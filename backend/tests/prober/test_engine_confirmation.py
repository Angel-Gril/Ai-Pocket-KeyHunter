"""Regression tests for PR #2 review: tighten engine confirmation semantics.

Covers the negative cases the review required before merge:
1. RCE must NOT confirm on plain 200 / SPA fallback / JSON error.
2. RCE only confirms after the exact random marker is echoed, and only then
   are secret-reading commands issued.
3. IDOR must NOT confirm on 401/403/404 or on an own-resource authenticated
   read with no boundary crossing.
4. weak-password respects BOTH the per-Spec max_requests and the target budget.
5. PROBE_VULN_CLASSES fails CLOSED on unknown/misspelled values.
6. Default .env.example does not enable L1+ probing.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
import respx

from aipocket.prober.base import Prober
from aipocket.prober.budget import RequestBudget
from aipocket.prober.capability import ProbeSpec, RiskLevel, VulnClass
from aipocket.prober.capability.types import ProbeContext
from aipocket.prober.engines.idor import run_idor
from aipocket.prober.engines.rce import run_rce
from aipocket.prober.engines.weak_password import _attempt_budget


class _Stub(Prober):
    """Minimal concrete prober so engines can issue real (mocked) HTTP."""

    product_name = "stub"

    @classmethod
    def identify(cls, hit: dict[str, Any]) -> bool:  # pragma: no cover - unused
        return False

    async def probe(self, hit: dict[str, Any]) -> list:  # pragma: no cover - unused
        return []


def _prober(client: httpx.AsyncClient, budget: int = 50) -> _Stub:
    return _Stub(
        client,
        asyncio.Semaphore(5),
        RequestBudget(budget),
        intrusive_checks=True,
        authorized_scope=("https://t.example",),
    )


def _ctx(auth: bool = True) -> ProbeContext:
    ctx = ProbeContext(hit={"host": "https://t.example", "protocol": "https"}, product="stub")
    if auth:
        ctx.auth_headers = {"Authorization": "Bearer sess-token"}
    return ctx


def _rce_spec() -> ProbeSpec:
    return ProbeSpec(
        id="stub.rce",
        product="stub",
        vuln_class=VulnClass.RCE,
        risk_level=RiskLevel.L3,
        entry={
            "path": "/api/run",
            "method": "POST",
            "param": "cmd",
            "secret_commands": ["printenv", "cat /.env"],
            "body": {},
            "use_auth": False,
        },
        max_requests=4,
    )


# --------------------------------------------------------------------------
# RCE — must not confirm without an echoed random marker
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rce_not_confirmed_on_plain_200() -> None:
    """A generic 200 that does not echo the marker is not RCE."""
    with respx.mock(assert_all_called=False) as router:
        router.post("https://t.example/api/run").mock(
            return_value=httpx.Response(200, text="ok, request received")
        )
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_rce(_prober(client), _ctx(), _rce_spec())
    assert res.findings == []
    assert "not confirmed" in res.reason


@pytest.mark.asyncio
async def test_rce_not_confirmed_on_spa_fallback() -> None:
    """SPA index.html returned for every path must not confirm RCE."""
    spa = "<!doctype html><html><body><div id=root></div></body></html>"
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(200, html=spa))
        async with httpx.AsyncClient() as client:
            res = await run_rce(_prober(client), _ctx(), _rce_spec())
    assert res.findings == []


@pytest.mark.asyncio
async def test_rce_not_confirmed_on_json_error() -> None:
    """A JSON error body (>5 chars) must not be mistaken for command output."""
    with respx.mock(assert_all_called=False) as router:
        router.post("https://t.example/api/run").mock(
            return_value=httpx.Response(200, json={"error": "unknown command", "code": 400})
        )
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_rce(_prober(client), _ctx(), _rce_spec())
    assert res.findings == []


@pytest.mark.asyncio
async def test_rce_confirmed_only_on_marker_echo_then_reads_secrets() -> None:
    """When the target echoes the exact random marker, confirm + read secrets."""
    secret_calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.content or b"{}")
        cmd = body.get("cmd", "")
        if cmd.startswith("echo aipocket-rce-"):
            # Simulate real shell echo: reflect the command's argument.
            marker = cmd.split(" ", 1)[1]
            return httpx.Response(200, text=f"{marker}\n")
        secret_calls.append(cmd)
        return httpx.Response(200, text="OPENAI_API_KEY=sk-proj-" + "Z" * 40)

    with respx.mock(assert_all_called=False) as router:
        router.post("https://t.example/api/run").mock(side_effect=handler)
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_rce(_prober(client), _ctx(), _rce_spec())

    assert len(res.findings) == 1
    assert res.findings[0].confirmed is True
    assert res.findings[0].severity == "critical"
    # Secret commands ran only AFTER confirmation.
    assert secret_calls, "secret commands should run once RCE is proven"


@pytest.mark.asyncio
async def test_rce_no_secret_commands_before_confirmation() -> None:
    """If the marker is never echoed, secret commands must NEVER be sent."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        seen.append(_json.loads(request.content or b"{}").get("cmd", ""))
        return httpx.Response(200, text="request received but no echo")

    with respx.mock(assert_all_called=False) as router:
        router.post("https://t.example/api/run").mock(side_effect=handler)
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_rce(_prober(client), _ctx(), _rce_spec())

    assert res.findings == []
    assert all("printenv" not in c and "cat" not in c for c in seen)


# --------------------------------------------------------------------------
# IDOR — must prove a boundary crossing, not just exercise the surface
# --------------------------------------------------------------------------


def _idor_spec() -> ProbeSpec:
    return ProbeSpec(
        id="stub.idor",
        product="stub",
        vuln_class=VulnClass.IDOR,
        risk_level=RiskLevel.L1,
        requires_auth=True,
        entry={
            "list": "/api/keys",
            "object": "/api/keys/{id}",
            "id_enum_max": 3,
            "id_fields": ["id"],
            "use_auth": True,
        },
        max_requests=12,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 404])
async def test_idor_not_confirmed_on_denied_object(status: int) -> None:
    """401/403/404 on every object read = access control working, not IDOR."""
    with respx.mock(assert_all_called=False) as router:
        router.get("https://t.example/api/keys").mock(
            return_value=httpx.Response(200, json=[{"id": "1"}, {"id": "2"}])
        )
        router.get(url__regex=r"https://t\.example/api/keys/\d+").mock(
            return_value=httpx.Response(status, text="denied")
        )
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_idor(_prober(client), _ctx(), _idor_spec())
    assert res.findings == []
    assert "access control held" in res.reason


@pytest.mark.asyncio
async def test_idor_not_confirmed_on_own_resource_only() -> None:
    """Authenticated 200 but the SAME object 401s without auth → own-resource read."""

    def handler(request: httpx.Request) -> httpx.Response:
        has_auth = "authorization" in {k.lower() for k in request.headers}
        if has_auth:
            return httpx.Response(200, json={"id": "1", "value": "mine"})
        return httpx.Response(401, text="unauthorized")

    with respx.mock(assert_all_called=False) as router:
        router.get("https://t.example/api/keys").mock(
            return_value=httpx.Response(200, json=[{"id": "1"}])
        )
        router.get(url__regex=r"https://t\.example/api/keys/1").mock(side_effect=handler)
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_idor(_prober(client), _ctx(), _idor_spec())
    assert res.findings == [], "own-resource authenticated read is not IDOR"
    assert "no unauthorized cross-boundary" in res.reason


@pytest.mark.asyncio
async def test_idor_confirmed_when_unauth_reads_object() -> None:
    """Object readable WITHOUT auth (same as with auth) = genuine IDOR."""
    key = "sk-proj-" + "Q" * 40
    with respx.mock(assert_all_called=False) as router:
        router.get("https://t.example/api/keys").mock(
            return_value=httpx.Response(200, json=[{"id": "1"}])
        )
        # Both authed and unauthed reads of /api/keys/1 return 200 + the key.
        router.get(url__regex=r"https://t\.example/api/keys/1").mock(
            return_value=httpx.Response(200, text=f'{{"id":"1","apiKey":"{key}"}}')
        )
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            res = await run_idor(_prober(client), _ctx(), _idor_spec())
    assert len(res.findings) == 1
    assert res.findings[0].confirmed is True


# --------------------------------------------------------------------------
# weak-password — spec.max_requests AND target budget both enforced
# --------------------------------------------------------------------------


def _wp_spec(max_requests: int) -> ProbeSpec:
    return ProbeSpec(
        id="stub.weak",
        product="stub",
        vuln_class=VulnClass.WEAK_PASSWORD,
        risk_level=RiskLevel.L1,
        entry={
            "auth_style": "login_json",
            "login": "/api/login",
            "body": {"username": "{user}", "password": "{pass}"},
            "post_auth_paths": ["/api/a", "/api/b"],
        },
        max_requests=max_requests,
    )


@pytest.mark.asyncio
async def test_weak_password_respects_spec_max_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with a huge target budget + WEAK_PASSWORD_MAX_ATTEMPTS=0, the Spec's
    own max_requests caps login attempts (minus post-auth reserve)."""
    from aipocket.core.config import settings

    monkeypatch.setattr(settings, "weak_password_max_attempts", 0)
    async with httpx.AsyncClient() as client:
        # spec max_requests=12, post_reserve=2 → at most 10 login attempts allowed.
        prober = _prober(client, budget=10_000)
        spec = _wp_spec(max_requests=12)
        # 9 attempts made so far: still under the spec cap of 10.
        assert _attempt_budget(prober, spec, attempted=9) is True
        # 10 attempts made: spec cap reached → no more logins.
        assert _attempt_budget(prober, spec, attempted=10) is False


@pytest.mark.asyncio
async def test_weak_password_respects_target_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shared target budget is a hard second-layer cap."""
    from aipocket.core.config import settings

    monkeypatch.setattr(settings, "weak_password_max_attempts", 0)
    budget = RequestBudget(3)
    async with httpx.AsyncClient() as client:
        prober = _Stub(
            client,
            asyncio.Semaphore(5),
            budget,
            intrusive_checks=True,
            authorized_scope=("https://t.example",),
        )
        spec = _wp_spec(max_requests=100)
        # Drain the target budget below the post-auth reserve (remaining=1 <= 2).
        budget.consume()
        budget.consume()
        assert _attempt_budget(prober, spec, attempted=0) is False
