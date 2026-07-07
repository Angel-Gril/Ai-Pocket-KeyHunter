"""Tests for the prober module — key extraction + product fingerprinting."""

from __future__ import annotations

import httpx
import pytest
import respx

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
    @pytest.mark.parametrize("prober_cls,blob", [
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
    ])
    def test_identify_positive(self, prober_cls, blob):
        hit = {"title": blob, "header": "", "banner": ""}
        assert prober_cls.identify(hit)

    @pytest.mark.parametrize("prober_cls", [
        FlowiseProber, LangflowProber, LiteLLMProber, NewAPIProber,
        OneAPIProber, LobeChatProber, OpenWebUIProber, LibreChatProber,
        DifyProber, FastGPTProber,
    ])
    def test_identify_negative(self, prober_cls):
        hit = {"title": "nginx", "header": "server: nginx", "banner": ""}
        assert not prober_cls.identify(hit)


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
            router.get("https://lobe.example.com/api/env").mock(
                return_value=httpx.Response(404)
            )
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
                return_value=httpx.Response(200, json={"success": True, "data": "session-token-abc"}),
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
                prober = NewAPIProber(client, sem)
                creds = await prober.probe(hit)
        assert len(creds) >= 1
        assert any("sk-" in c.apikey for c in creds)


class TestWeakCredentials:
    def test_has_common_defaults(self):
        pairs = { (u, p) for u, p in WEAK_CREDENTIALS }
        assert ("admin", "admin") in pairs
        assert ("admin", "123456") in pairs
