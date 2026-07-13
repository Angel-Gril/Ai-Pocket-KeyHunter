"""Tests for the prober module — key extraction + product fingerprinting."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx
from aipocket.core.targets import canonicalize_hits

from aipocket.prober.base import (
    WEAK_CREDENTIALS,
    extract_keys_from_text,
)
from aipocket.prober.probers import (
    DifyProber,
    FastGPTProber,
    FlowiseProber,
    LangflowProber,
    LibreChatProber,
    LiteLLMProber,
    LobeChatProber,
    NewAPIProber,
    OneAPIProber,
    OpenWebUIProber,
)
from aipocket.prober.runner import _select_prober, probe_hosts

# ---------------------------------------------------------------------------
# Key extraction
# ---------------------------------------------------------------------------


class TestExtractKeys:
    def test_openrouter_uuid_format(self):
        key = "sk-or-v1-12345678-1234-1234-1234-123456789abc"
        creds = extract_keys_from_text(key, source_label="t")
        assert len(creds) == 1
        assert creds[0].source == "t:openrouter"

    def test_anthropic_full_prefix(self):
        key = "sk-ant-api03-" + "A" * 40
        creds = extract_keys_from_text(key, source_label="t")
        assert len(creds) == 1
        assert creds[0].source == "t:anthropic"

    def test_deepseek_long_hex_caught(self):
        key = "sk-" + "a" * 52
        creds = extract_keys_from_text(key, source_label="t")
        assert len(creds) >= 1
        assert creds[0].apikey.startswith("sk-")

    def test_siliconflow_32_hex_caught(self):
        key = "sk-" + "a" * 32
        creds = extract_keys_from_text(key, source_label="t")
        assert len(creds) >= 1

    def test_glm_double_segment(self):
        key = "f7638a0d932046079d9900bda54cdde9.79EtThsVS0IEdssm"
        creds = extract_keys_from_text(key, source_label="t")
        assert any(c.source == "t:glm" for c in creds)

    def test_google_gemini(self):
        key = "AIzaSy" + "A" * 35
        creds = extract_keys_from_text(key, source_label="t")
        assert any(c.source == "t:google" for c in creds)

    def test_groq_prefix(self):
        key = "gsk_" + "A" * 32
        creds = extract_keys_from_text(key, source_label="t")
        assert any(c.source == "t:groq" for c in creds)

    def test_jwt_io_example_filtered(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        creds = extract_keys_from_text(jwt, source_label="t")
        assert len(creds) == 0

    def test_placeholder_filtered(self):
        creds = extract_keys_from_text("OPENAI_API_KEY=sk-replace_with_your_key", source_label="t")
        assert len(creds) == 0

    def test_generic_key_value_pairs(self):
        text = '{"api_key": "sk-proj-Kx9mWq2vRtLp7nBcYfJh4sDgUoA8eN3iZl"}'
        creds = extract_keys_from_text(text, source_label="t")
        assert any("openai" in c.source for c in creds)


# ---------------------------------------------------------------------------
# Product fingerprinting
# ---------------------------------------------------------------------------


class TestFingerprinting:
    @pytest.mark.parametrize(
        "prober_cls,blob",
        [
            (FlowiseProber, "Flowise - Build AI Apps"),
            (LangflowProber, "langflow"),
            (LiteLLMProber, "LiteLLM Proxy"),
            (NewAPIProber, "New API Dashboard"),
            (OneAPIProber, "One API"),
            (LobeChatProber, "LobeChat"),
            (OpenWebUIProber, "Open WebUI"),
            (LibreChatProber, "LibreChat"),
            (DifyProber, "Dify"),
            (FastGPTProber, "FastGPT"),
        ],
    )
    def test_identify_positive(self, prober_cls, blob):
        hit = {"title": blob, "header": "", "banner": ""}
        assert prober_cls.identify(hit)

    @pytest.mark.parametrize(
        "prober_cls",
        [
            FlowiseProber,
            LangflowProber,
            LiteLLMProber,
            NewAPIProber,
            OneAPIProber,
            LobeChatProber,
            OpenWebUIProber,
            LibreChatProber,
            DifyProber,
            FastGPTProber,
        ],
    )
    def test_identify_negative(self, prober_cls):
        hit = {"title": "nginx", "header": "server: nginx", "banner": ""}
        assert not prober_cls.identify(hit)

    def test_explicit_product_provenance_precedes_textual_fingerprint(self):
        hit = {
            "_product": "Dify",
            "_product_hints": ["dify"],
            "title": "Flowise - Build AI Apps",
            "header": "",
            "banner": "",
        }

        assert _select_prober(hit, [FlowiseProber, DifyProber]) is DifyProber


# ---------------------------------------------------------------------------
# Active probe with mocked HTTP
# ---------------------------------------------------------------------------


class TestLobeChatProbe:
    @pytest.mark.asyncio
    async def test_config_leak(self):
        from aipocket.prober.probers.lobechat import LobeChatProber

        hit = {
            "host": "https://lobe.example.com",
            "_source": "fofa",
            "title": "LobeChat",
            "header": "",
            "banner": "",
        }
        import asyncio

        sem = asyncio.Semaphore(5)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://lobe.example.com/api/config").mock(
                return_value=httpx.Response(
                    200,
                    text='{"OPENAI_API_KEY": "sk-proj-' + "A" * 30 + '"}',
                )
            )
            router.get("https://lobe.example.com/api/client/config").mock(
                return_value=httpx.Response(404)
            )
            router.get("https://lobe.example.com/api/env").mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient() as client:
                prober = LobeChatProber(client, sem)
                creds = await prober.probe(hit)
        assert len(creds) >= 1
        assert creds[0].apikey.startswith("sk-proj-")
        assert creds[0].source.startswith("prober:")


class TestNewAPIProbe:
    @pytest.mark.asyncio
    async def test_weak_password_login_then_read(self):
        from aipocket.prober.probers.newapi import NewAPIProber

        hit = {
            "host": "https://newapi.example.com",
            "_source": "fofa",
            "title": "New API",
            "header": "",
            "banner": "",
        }
        import asyncio

        sem = asyncio.Semaphore(5)
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
            router.get("https://newapi.example.com/api/token/").mock(
                return_value=httpx.Response(404)
            )
            router.get("https://newapi.example.com/api/user/self").mock(
                return_value=httpx.Response(404)
            )
            router.get("https://newapi.example.com/api/status").mock(
                return_value=httpx.Response(404)
            )
            router.get("https://newapi.example.com/v1/models").mock(
                return_value=httpx.Response(404)
            )
            async with httpx.AsyncClient() as client:
                prober = NewAPIProber(
                    client,
                    sem,
                    intrusive_checks=True,
                    authorized_scope=("https://newapi.example.com",),
                )
                creds = await prober.probe(hit)
        assert len(creds) >= 1
        assert any("sk-" in c.apikey for c in creds)

    @pytest.mark.asyncio
    async def test_normal_mode_never_attempts_weak_passwords(self):
        hit = {"host": "https://safe.example.com", "title": "New API", "protocol": "https"}
        import asyncio

        with respx.mock(assert_all_called=False) as router:
            login = router.post("https://safe.example.com/api/user/login").mock(
                return_value=httpx.Response(200, json={"success": True, "data": "token"})
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient(follow_redirects=False) as client:
                await NewAPIProber(client, asyncio.Semaphore(1)).probe(hit)

        assert login.call_count == 0

    @pytest.mark.asyncio
    async def test_intrusive_mode_requires_matching_authorized_scope(self):
        hit = {"host": "https://outside.example.com", "title": "New API", "protocol": "https"}
        import asyncio

        with respx.mock(assert_all_called=False) as router:
            login = router.post("https://outside.example.com/api/user/login").mock(
                return_value=httpx.Response(200, json={"success": True, "data": "token"})
            )
            router.route().mock(return_value=httpx.Response(404))
            async with httpx.AsyncClient(follow_redirects=False) as client:
                await NewAPIProber(
                    client,
                    asyncio.Semaphore(1),
                    intrusive_checks=True,
                    authorized_scope=("https://authorized.example.com",),
                ).probe(hit)

        assert login.call_count == 0


class TestStagedProbeDispatch:
    @pytest.mark.asyncio
    async def test_low_score_target_receives_zero_requests(self):
        hit = {"host": "https://low.example.com", "title": "docs", "protocol": "https"}
        with respx.mock(assert_all_called=False) as router:
            router.route().mock(return_value=httpx.Response(200, text="unexpected"))
            await probe_hosts(canonicalize_hits([hit]), frozenset())
        assert len(router.calls) == 0

    @pytest.mark.asyncio
    async def test_high_score_target_enters_product_path(self):
        hit = {
            "host": "https://product.example.com",
            "title": "New API",
            "protocol": "https",
            "_product": "new-api",
        }
        with (
            patch.object(NewAPIProber, "probe", return_value=[]) as product_probe,
            respx.mock(assert_all_called=False),
        ):
            await probe_hosts(canonicalize_hits([hit]), frozenset({"new-api"}))
        product_probe.assert_awaited_once()


class TestProbeBatching:
    """Large scans must schedule hosts in waves, not one giant task list."""

    @staticmethod
    def _product_hits(n: int) -> list[dict]:
        return [
            {
                "host": f"https://h{i}.example.com",
                "title": "New API",
                "protocol": "https",
                "_product": "new-api",
            }
            for i in range(n)
        ]

    @pytest.mark.asyncio
    async def test_large_host_set_runs_in_multiple_batches(self, monkeypatch, caplog):
        import logging

        from aipocket.core.config import settings

        monkeypatch.setattr(settings, "prober_batch_size", 2)
        monkeypatch.setattr(settings, "prober_concurrency", 2)

        hits = self._product_hits(5)
        with (
            patch.object(NewAPIProber, "probe", return_value=[]) as product_probe,
            respx.mock(assert_all_called=False),
            caplog.at_level(logging.INFO, logger="aipocket.prober.runner"),
        ):
            report = await probe_hosts(canonicalize_hits(hits), frozenset({"new-api"}))

        assert product_probe.await_count == 5
        assert report.credentials == ()

        text = "\n".join(r.message for r in caplog.records)
        assert "batch_size=2 → 3 batch(es)" in text
        assert "Prober batch 1/3:" in text
        assert "Prober batch 2/3:" in text
        assert "Prober batch 3/3:" in text
        assert "Prober extracted 0 credentials from 5 attempted assignments (3 batches)" in text

    @pytest.mark.asyncio
    async def test_small_host_set_is_single_batch(self, monkeypatch, caplog):
        import logging

        from aipocket.core.config import settings

        monkeypatch.setattr(settings, "prober_batch_size", 500)
        monkeypatch.setattr(settings, "prober_concurrency", 10)

        hits = self._product_hits(3)
        with (
            patch.object(NewAPIProber, "probe", return_value=[]) as product_probe,
            respx.mock(assert_all_called=False),
            caplog.at_level(logging.INFO, logger="aipocket.prober.runner"),
        ):
            await probe_hosts(canonicalize_hits(hits), frozenset({"new-api"}))

        assert product_probe.await_count == 3
        text = "\n".join(r.message for r in caplog.records)
        assert "batch_size=500 → 1 batch(es)" in text
        assert "Prober batch 1/1:" in text


class TestWeakCredentials:
    def test_has_common_defaults(self):
        pairs = {(u, p) for u, p in WEAK_CREDENTIALS}
        assert ("admin", "admin") in pairs
        assert ("admin", "123456") in pairs
