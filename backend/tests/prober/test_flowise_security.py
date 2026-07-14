from __future__ import annotations

import asyncio
import logging

import httpx
import pytest
import respx

from aipocket.prober.probers import FlowiseProber


@pytest.mark.asyncio
async def test_flowise_success_log_excludes_password_and_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Weak-password path must not log cleartext password or session token."""
    password = "plain-weak-password"
    token = "returned-secret-token"
    hit = {"host": "https://flowise.example", "protocol": "https"}

    with (
        pytest.MonkeyPatch.context() as monkeypatch,
        respx.mock(assert_all_called=False) as router,
    ):
        monkeypatch.setattr(
            "aipocket.prober.engines.weak_password.get_weak_credentials",
            lambda **_kwargs: (("admin", password),),
        )
        router.post("https://flowise.example/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"token": token})
        )
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            with caplog.at_level(logging.DEBUG):
                await FlowiseProber(
                    client,
                    asyncio.Semaphore(1),
                    intrusive_checks=True,
                    authorized_scope=("https://flowise.example",),
                ).probe(hit)

    assert password not in caplog.text
    assert token not in caplog.text
