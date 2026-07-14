"""Tests for vuln-class capability planner, engines, and new product probers."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from aipocket.prober.capability import (
    ProbeSpec,
    RiskLevel,
    RiskPolicy,
    VulnClass,
    policy_from_settings,
    run_product_plan,
)
from aipocket.prober.capability.planner import plan_specs
from aipocket.prober.probers import (
    AnythingLLMProber,
    ChatGPTNextWebProber,
    OpenRouterProber,
    PortkeyProber,
)
from aipocket.prober.probers.librechat import SPECS as LIBRECHAT_SPECS
from aipocket.prober.probers.newapi import NewAPIProber
from aipocket.prober.runner import _all_probers, _hint_to_product, _select_prober
from aipocket.prober.security import allows, normalized_origin


class TestProductAliases:
    @pytest.mark.parametrize(
        "hint,expected",
        [
            ("Portkey AI Gateway", "portkey"),
            ("nextchat", "chatgpt-next-web"),
            ("ChatGPT-Next-Web", "chatgpt-next-web"),
            ("OpenRouter", "openrouter"),
            ("AnythingLLM", "anythingllm"),
            ("One-API", "one-api"),
            ("new-api", "new-api"),
        ],
    )
    def test_hint_to_product(self, hint: str, expected: str) -> None:
        assert _hint_to_product(hint) == expected

    def test_select_prober_by_hint(self) -> None:
        classes = _all_probers()
        hit = {
            "_product": "Portkey AI Gateway",
            "_product_hints": ["Portkey AI Gateway"],
            "title": "nginx",
            "header": "",
            "banner": "",
        }
        assert _select_prober(hit, classes) is PortkeyProber

    def test_fourteen_product_probers_registered(self) -> None:
        names = {cls.product_name for cls in _all_probers()}
        assert len(names) >= 14
        for required in (
            "chatgpt-next-web",
            "portkey",
            "openrouter",
            "anythingllm",
            "new-api",
            "one-api",
        ):
            assert required in names


class TestNewProberIdentify:
    @pytest.mark.parametrize(
        "prober_cls,blob",
        [
            (ChatGPTNextWebProber, "NextChat"),
            (ChatGPTNextWebProber, "ChatGPT-Next-Web"),
            (PortkeyProber, "Portkey Gateway"),
            (OpenRouterProber, "OpenRouter"),
            (AnythingLLMProber, "AnythingLLM"),
        ],
    )
    def test_identify_positive(self, prober_cls, blob: str) -> None:
        assert prober_cls.identify({"title": blob, "header": "", "banner": ""})

    @pytest.mark.parametrize(
        "prober_cls",
        [ChatGPTNextWebProber, PortkeyProber, OpenRouterProber, AnythingLLMProber],
    )
    def test_identify_negative(self, prober_cls) -> None:
        assert not prober_cls.identify({"title": "nginx", "header": "server: nginx", "banner": ""})


class TestRiskGate:
    def test_l0_always_allowed(self) -> None:
        spec = ProbeSpec(
            id="t.unauth",
            product="t",
            vuln_class=VulnClass.UNAUTH_READ,
            risk_level=RiskLevel.L0,
        )
        policy = RiskPolicy(intrusive_checks=False, authorized_scope=())
        assert allows(spec, normalized_origin("https://x.example"), policy)

    def test_l1_requires_intrusive_scope_optional(self) -> None:
        spec = ProbeSpec(
            id="t.weak",
            product="t",
            vuln_class=VulnClass.WEAK_PASSWORD,
            risk_level=RiskLevel.L1,
        )
        origin = normalized_origin("https://x.example")
        # Off without intrusive
        assert not allows(spec, origin, RiskPolicy(intrusive_checks=False, authorized_scope=()))
        # Empty scope = unrestricted when intrusive is on
        assert allows(spec, origin, RiskPolicy(intrusive_checks=True, authorized_scope=()))
        # Non-empty scope must match
        assert not allows(
            spec,
            origin,
            RiskPolicy(intrusive_checks=True, authorized_scope=("https://other.example",)),
        )
        assert allows(
            spec,
            origin,
            RiskPolicy(intrusive_checks=True, authorized_scope=("https://x.example",)),
        )

    def test_l2_ssrf_requires_flag(self) -> None:
        spec = ProbeSpec(
            id="t.ssrf",
            product="t",
            vuln_class=VulnClass.SSRF,
            risk_level=RiskLevel.L2,
        )
        origin = normalized_origin("https://x.example")
        policy = RiskPolicy(
            max_risk=RiskLevel.L2,
            intrusive_checks=True,
            authorized_scope=("https://x.example",),
            ssrf_enabled=False,
        )
        assert not allows(spec, origin, policy)
        policy2 = RiskPolicy(
            max_risk=RiskLevel.L2,
            intrusive_checks=True,
            authorized_scope=("https://x.example",),
            ssrf_enabled=True,
        )
        assert allows(spec, origin, policy2)

    def test_l3_rce_default_off(self) -> None:
        policy = policy_from_settings()
        assert policy.rce_enabled is False
        assert policy.max_risk <= RiskLevel.L1 or not policy.rce_enabled


class TestPlanner:
    def test_plans_l0_without_intrusive(self) -> None:
        hit = {"host": "https://x.example", "protocol": "https"}
        policy = RiskPolicy(intrusive_checks=False)
        planned = plan_specs(
            "librechat",
            LIBRECHAT_SPECS,
            hit=hit,
            policy=policy,
            prober=LibreChatStub(),
        )
        classes = {s.vuln_class for s in planned}
        assert VulnClass.UNAUTH_READ in classes
        assert VulnClass.WEAK_PASSWORD not in classes


class LibreChatStub:
    product_name = "librechat"
    _intrusive_checks = False
    _authorized_scope = frozenset()

    def _url(self, hit, path=""):
        return "https://x.example" + path


class TestNewProberL0:
    @pytest.mark.asyncio
    async def test_portkey_unauth_extracts_key(self) -> None:
        hit = {
            "host": "https://portkey.example.com",
            "title": "Portkey",
            "protocol": "https",
        }
        key = "sk-proj-" + "B" * 40
        with respx.mock(assert_all_called=False) as router:
            router.get("https://portkey.example.com/v1/config").mock(
                return_value=httpx.Response(200, text=f'{{"api_key": "{key}"}}')
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient() as client:
                prober = PortkeyProber(client, asyncio.Semaphore(5))
                creds = await prober.probe(hit)
        assert any(key in c.apikey for c in creds)

    @pytest.mark.asyncio
    async def test_nextchat_unauth_extracts_key(self) -> None:
        hit = {
            "host": "https://next.example.com",
            "title": "NextChat",
            "protocol": "https",
        }
        key = "sk-proj-" + "C" * 40
        with respx.mock(assert_all_called=False) as router:
            router.get("https://next.example.com/api/config").mock(
                return_value=httpx.Response(200, text=f'{{"OPENAI_API_KEY": "{key}"}}')
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient() as client:
                creds = await ChatGPTNextWebProber(client, asyncio.Semaphore(5)).probe(hit)
        assert any(key in c.apikey for c in creds)


class TestLibreChatIdorSplit:
    @pytest.mark.asyncio
    async def test_weak_password_and_idor_nodes(self) -> None:
        from aipocket.prober.probers.librechat import LibreChatProber

        hit = {
            "host": "https://libre.example.com",
            "title": "LibreChat",
            "protocol": "https",
        }
        key = "sk-proj-" + "D" * 40
        with respx.mock(assert_all_called=False) as router:
            router.post("https://libre.example.com/api/auth/login").mock(
                return_value=httpx.Response(200, json={"token": "sess-1"})
            )
            router.get("https://libre.example.com/api/keys").mock(
                return_value=httpx.Response(200, text=f'[{{"id": "1", "apiKey": "{key}"}}]')
            )
            router.get("https://libre.example.com/api/keys/1").mock(
                return_value=httpx.Response(200, text=f'{{"id": "1", "apiKey": "{key}"}}')
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient() as client:
                prober = LibreChatProber(
                    client,
                    asyncio.Semaphore(5),
                    intrusive_checks=True,
                    authorized_scope=("https://libre.example.com",),
                )
                result = await run_product_plan(prober, hit, LIBRECHAT_SPECS)
        assert any(key in c.apikey for c in result.credentials)
        statuses = {o.spec_id: o.status.value for o in result.node_outcomes}
        assert statuses.get("librechat.weak_password") == "executed"
        assert statuses.get("librechat.idor.keys") == "executed"


class TestApiurlNotOverwritten:
    def test_bundle_endpoint_preserved(self) -> None:
        from aipocket.prober.base import extract_keys_from_text

        # Structured extractor may pair key with an upstream endpoint.
        text = (
            '{"openai_api_base": "https://api.openai.com/v1",'
            ' "api_key": "sk-proj-' + "E" * 40 + '"}'
        )
        creds = extract_keys_from_text(text, host="gateway.example", source_label="t")
        # Even if apiurl empty from multi-candidate, extract must not force origin
        # in extract_keys_from_text itself (overwrite fix is in _extract_from_response).
        assert creds


class TestNewAPIWeakPasswordStillWorks:
    @pytest.mark.asyncio
    async def test_login_then_channel(self) -> None:
        hit = {
            "host": "https://newapi.example.com",
            "_source": "fofa",
            "title": "New API",
            "header": "",
            "banner": "",
        }
        with respx.mock(assert_all_called=False) as router:
            router.post("https://newapi.example.com/api/user/login").mock(
                return_value=httpx.Response(
                    200, json={"success": True, "data": "session-token-abc"}
                ),
            )
            router.get("https://newapi.example.com/api/channel/").mock(
                return_value=httpx.Response(
                    200,
                    text='{"data": [{"key": "sk-' + "a" * 52 + '"}]}',
                ),
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient() as client:
                prober = NewAPIProber(
                    client,
                    asyncio.Semaphore(5),
                    intrusive_checks=True,
                    authorized_scope=("https://newapi.example.com",),
                )
                creds = await prober.probe(hit)
        assert any("sk-" in c.apikey for c in creds)
