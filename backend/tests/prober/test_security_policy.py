from __future__ import annotations

import asyncio
from collections.abc import Callable

import httpx
import pytest
import respx

from aipocket.core.models import Credential
from aipocket.prober.base import Prober
from aipocket.prober.budget import RequestBudget
from aipocket.prober.probers import (
    FlowiseProber,
    LibreChatProber,
    LiteLLMProber,
    NewAPIProber,
    OneAPIProber,
)

ProberFactory = Callable[..., Prober]


@pytest.mark.parametrize(
    ("start_url", "location"),
    [
        ("https://redirect.example/start", "/finish"),
        ("https://redirect.example/start", "https://redirect.example:443/finish"),
        ("https://redirect.example:443/start", "https://redirect.example/finish"),
        ("http://redirect.example/start", "http://redirect.example:80/finish"),
        ("http://redirect.example:80/start", "http://redirect.example/finish"),
    ],
)
@pytest.mark.asyncio
async def test_redirect_accepts_same_normalized_origin(start_url: str, location: str) -> None:
    budget = RequestBudget(2)
    with respx.mock as router:
        router.get(start_url).mock(return_value=httpx.Response(302, headers={"location": location}))
        router.get(location).mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await _PolicyProber(client, asyncio.Semaphore(1), budget)._get(start_url)

    assert response is not None
    assert response.status_code == 200
    assert budget.remaining == 0


@pytest.mark.parametrize(
    "location",
    [
        "http://redirect.example/finish",
        "https://other.example/finish",
        "https://user@redirect.example/finish",
        "https://user:password@redirect.example/finish",
        "https://redirect.example:not-a-port/finish",
        "https://redirect.example:70000/finish",
        "https://[::1/finish",
        "https:///missing-host",
    ],
)
@pytest.mark.asyncio
async def test_redirect_rejects_unsafe_or_malformed_location(location: str) -> None:
    start_url = "https://redirect.example/start"
    budget = RequestBudget(2)
    with respx.mock(assert_all_called=False) as router:
        router.get(start_url).mock(return_value=httpx.Response(302, headers={"location": location}))
        router.route().mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await _PolicyProber(client, asyncio.Semaphore(1), budget)._get(start_url)

        request_count = len(router.calls)

    assert response is None
    assert request_count == 1
    assert budget.remaining == 1


@pytest.mark.asyncio
async def test_redirect_loop_stops_at_exact_max_redirect_boundary() -> None:
    budget = RequestBudget(4)
    with respx.mock(assert_all_called=False) as router:
        for current, following in (("start", "one"), ("one", "two"), ("two", "three")):
            router.get(f"https://loop.example/{current}").mock(
                return_value=httpx.Response(302, headers={"location": f"/{following}"})
            )
        final = router.get("https://loop.example/three").mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await _PolicyProber(
                client, asyncio.Semaphore(1), budget, max_redirects=2
            )._get("https://loop.example/start")

    assert response is None
    assert final.call_count == 0
    assert budget.remaining == 1


@pytest.mark.parametrize(
    ("prober_factory", "intrusive_paths"),
    [
        (FlowiseProber, ("/api/v1/auth/login",)),
        (LibreChatProber, ("/api/auth/login",)),
        (LiteLLMProber, ("/key/list", "/config/list", "/sso/key/generate")),
        (NewAPIProber, ("/api/user/login",)),
        (OneAPIProber, ("/api/user/login",)),
    ],
)
@pytest.mark.parametrize(
    ("intrusive_checks", "scope", "expected_intrusive"),
    [
        # Empty scope + intrusive = unrestricted (all targets)
        (True, (), 1),
        (False, ("https://target.example",), 0),
        # Non-empty scope: only exact origin match; malformed entries never match
        (True, ("https://target.example/path",), 0),
        (True, ("https://target.example?query=1",), 0),
        (True, ("https://user@target.example",), 0),
        (True, ("https://other.example",), 0),
        (True, ("https://target.example:443",), 1),
    ],
)
@pytest.mark.asyncio
async def test_intrusive_requests_require_flag_and_optional_scope(
    prober_factory: ProberFactory,
    intrusive_paths: tuple[str, ...],
    intrusive_checks: bool,
    scope: tuple[str, ...],
    expected_intrusive: int,
) -> None:
    hit = {"host": "https://target.example", "protocol": "https"}
    with respx.mock(assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            await prober_factory(
                client,
                asyncio.Semaphore(1),
                intrusive_checks=intrusive_checks,
                authorized_scope=scope,
            ).probe(hit)
        intrusive_requests = [
            call
            for call in router.calls
            if call.request.url.path in intrusive_paths
            and (call.request.method == "POST" or "authorization" in call.request.headers)
        ]
    if expected_intrusive:
        assert intrusive_requests
    else:
        assert intrusive_requests == []


class _PolicyProber(Prober):
    product_name = "policy-test"

    @classmethod
    def identify(cls, hit: dict[str, object]) -> bool:
        return True

    async def probe(self, hit: dict[str, object]) -> list[Credential]:
        return []
