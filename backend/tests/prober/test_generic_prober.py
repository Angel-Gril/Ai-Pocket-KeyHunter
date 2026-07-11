"""Tests for GenericPageProber and pre_filter_credentials."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from aipocket.core.models import Credential
from aipocket.prober.budget import RequestBudget
from aipocket.prober.probers.generic import GenericPageProber
from aipocket.services.honeypot import pre_filter_credentials

# ---------------------------------------------------------------------------
# GenericPageProber tests
# ---------------------------------------------------------------------------


class TestGenericPageProberIdentify:
    """GenericPageProber.identify() should always return False — it's only
    assigned to unmatched hosts by the runner, never auto-matched."""

    def test_never_matches(self):
        hit = {"title": "anything", "header": "content", "banner": "stuff"}
        assert not GenericPageProber.identify(hit)

    def test_empty_hit(self):
        assert not GenericPageProber.identify({})


class TestGenericPageProberProbe:
    @pytest.mark.asyncio
    async def test_medium_evidence_uses_one_confirmation_request(self):
        hit = {"host": "https://medium.example.com", "protocol": "https", "_evidence_score": 60}
        sem = asyncio.Semaphore(1)
        with respx.mock() as router:
            confirmation = router.get("https://medium.example.com/").mock(
                return_value=httpx.Response(200, text="confirmed target")
            )
            budget = RequestBudget(12)
            async with httpx.AsyncClient(follow_redirects=False) as client:
                await GenericPageProber(client, sem, budget).probe(hit)

        assert confirmation.call_count == 1
        assert budget.remaining == 11

    @pytest.mark.asyncio
    async def test_cross_origin_redirect_is_rejected(self):
        hit = {"host": "https://redirect.example.com", "protocol": "https", "_evidence_score": 60}
        sem = asyncio.Semaphore(1)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://redirect.example.com/").mock(
                return_value=httpx.Response(
                    302, headers={"location": "https://other.example.com/leak"}
                )
            )
            escaped = router.get("https://other.example.com/leak").mock(
                return_value=httpx.Response(200, text="API_KEY=sk-proj-" + "A" * 30)
            )
            async with httpx.AsyncClient(follow_redirects=False) as client:
                creds = await GenericPageProber(client, sem, RequestBudget(12)).probe(hit)

        assert creds == []
        assert escaped.call_count == 0

    @pytest.mark.asyncio
    async def test_same_origin_redirects_are_bounded_and_budgeted(self):
        hit = {"host": "https://bounded.example.com", "protocol": "https", "_evidence_score": 60}
        sem = asyncio.Semaphore(1)
        budget = RequestBudget(2)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://bounded.example.com/").mock(
                return_value=httpx.Response(302, headers={"location": "/one"})
            )
            router.get("https://bounded.example.com/one").mock(
                return_value=httpx.Response(302, headers={"location": "/two"})
            )
            final = router.get("https://bounded.example.com/two").mock(
                return_value=httpx.Response(200, text="API_KEY=sk-proj-" + "A" * 30)
            )
            async with httpx.AsyncClient(follow_redirects=False) as client:
                creds = await GenericPageProber(client, sem, budget, max_redirects=5).probe(hit)

        assert creds == []
        assert final.call_count == 0
        assert budget.remaining == 0

    @pytest.mark.asyncio
    async def test_extracts_anthropic_key_from_env(self):
        """Simulates finding an exposed .env with a Claude key."""
        hit = {
            "host": "https://target.example.com",
            "_source": "fofa",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "https",
        }
        sem = asyncio.Semaphore(5)
        env_content = (
            "# App config\n"
            "NODE_ENV=production\n"
            "ANTHROPIC_API_KEY=sk-ant-api03-RealKeyHere123456789012345678901234567890\n"
            "PORT=3000\n"
        )
        with respx.mock(assert_all_called=False) as router:
            router.get("https://target.example.com/").mock(
                return_value=httpx.Response(200, text="<html><body>Hello</body></html>")
            )
            router.get("https://target.example.com/.env").mock(
                return_value=httpx.Response(200, text=env_content)
            )
            # Remaining paths return 404
            router.route().mock(return_value=httpx.Response(404))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        assert len(creds) >= 1
        assert any("sk-ant-api03-" in c.apikey for c in creds)
        assert all(c.source.startswith("prober:") for c in creds)

    @pytest.mark.asyncio
    async def test_extracts_openai_key_from_index_page(self):
        """Simulates a page that leaks an OpenAI key in its body."""
        hit = {
            "host": "https://leaky.example.com",
            "_source": "shodan",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "https",
        }
        sem = asyncio.Semaphore(5)
        page_content = (
            "<html><body>"
            '<script>const config = {apiKey: "sk-proj-Kx9mWq2vRtLp7nBcYfJh4sDgUoA8eN3iZl"};</script>'
            "</body></html>"
        )
        with respx.mock(assert_all_called=False) as router:
            router.get("https://leaky.example.com/").mock(
                return_value=httpx.Response(200, text=page_content)
            )
            router.route().mock(return_value=httpx.Response(404))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        assert len(creds) >= 1
        assert any("sk-proj-" in c.apikey for c in creds)

    @pytest.mark.asyncio
    async def test_extracts_deepseek_key_from_config(self):
        """Simulates an /api/config endpoint leaking a deepseek key.
        Tier 2 path — requires a Tier 1 file to be exposed first."""
        hit = {
            "host": "http://192.168.1.100:8080",
            "_source": "fofa",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "http",
        }
        sem = asyncio.Semaphore(5)
        config_content = '{"DEEPSEEK_API_KEY": "sk-e5b48a0e80564bc8924bff1383a08c77deadbeef"}'
        with respx.mock(assert_all_called=False) as router:
            router.get("http://192.168.1.100:8080/").mock(
                return_value=httpx.Response(
                    200, text="<h1>Welcome</h1>", headers={"content-type": "text/html"}
                )
            )
            # .env returns a real text file (triggers tier 2)
            router.get("http://192.168.1.100:8080/.env").mock(
                return_value=httpx.Response(
                    200, text="PORT=8080\n", headers={"content-type": "text/plain"}
                )
            )
            # /api/config is in tier 2 — contains the actual key
            router.get("http://192.168.1.100:8080/api/config").mock(
                return_value=httpx.Response(
                    200, text=config_content, headers={"content-type": "application/json"}
                )
            )
            router.route().mock(return_value=httpx.Response(404))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        assert len(creds) >= 1
        assert any("sk-e5b48a0e" in c.apikey for c in creds)

    @pytest.mark.asyncio
    async def test_skips_if_index_unreachable(self):
        """If the index page fails, don't bother with other paths."""
        hit = {
            "host": "https://dead.example.com",
            "_source": "fofa",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "https",
        }
        sem = asyncio.Semaphore(5)
        with respx.mock(assert_all_called=False) as router:
            # Simulate connection timeout / error for all requests
            router.route().mock(side_effect=httpx.ConnectTimeout("timed out"))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        assert creds == []

    @pytest.mark.asyncio
    async def test_deduplicates_same_key(self):
        """Same key found in multiple paths should not produce duplicates."""
        hit = {
            "host": "https://dup.example.com",
            "_source": "fofa",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "https",
        }
        sem = asyncio.Semaphore(5)
        key_text = "sk-ant-api03-RealDupKey9a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p"
        with respx.mock(assert_all_called=False) as router:
            # Same key appears on index AND .env
            router.get("https://dup.example.com/").mock(
                return_value=httpx.Response(200, text=f"key={key_text}")
            )
            router.get("https://dup.example.com/.env").mock(
                return_value=httpx.Response(200, text=f"API_KEY={key_text}")
            )
            router.route().mock(return_value=httpx.Response(404))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        # Should only have 1 credential, not 2
        assert len(creds) == 1

    @pytest.mark.asyncio
    async def test_no_keys_in_clean_page(self):
        """Normal pages without keys should return empty."""
        hit = {
            "host": "https://clean.example.com",
            "_source": "fofa",
            "title": "",
            "header": "",
            "banner": "",
            "protocol": "https",
        }
        sem = asyncio.Semaphore(5)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://clean.example.com/").mock(
                return_value=httpx.Response(
                    200, text="<html><body>Welcome to our site</body></html>"
                )
            )
            router.route().mock(return_value=httpx.Response(404))

            async with httpx.AsyncClient() as client:
                prober = GenericPageProber(client, sem)
                creds = await prober.probe(hit)

        assert creds == []


# ---------------------------------------------------------------------------
# pre_filter_credentials tests
# ---------------------------------------------------------------------------


class TestPreFilterCredentials:
    def _cred(self, apikey: str, apiurl: str = "https://api.openai.com/v1") -> Credential:
        return Credential(
            apikey=apikey,
            apiurl=apiurl,
            source="test",
            source_type="header",
            host="1.2.3.4",
        )

    def test_keeps_valid_openai_key(self):
        creds = [self._cred("sk-proj-" + "A" * 30)]
        result = pre_filter_credentials(creds)
        assert len(result) == 1

    def test_keeps_valid_anthropic_key(self):
        creds = [self._cred("sk-ant-api03-" + "B" * 40)]
        result = pre_filter_credentials(creds)
        assert len(result) == 1

    def test_rejects_google_oauth(self):
        creds = [self._cred("GOCSPX-fake-google-oauth-secret")]
        result = pre_filter_credentials(creds)
        assert len(result) == 0

    def test_rejects_hex32_token(self):
        creds = [self._cred("abcdef1234567890abcdef1234567890")]
        result = pre_filter_credentials(creds)
        assert len(result) == 0

    def test_rejects_noise_placeholder(self):
        creds = [self._cred("sk-your_api_key_placeholder_here_changeme")]
        result = pre_filter_credentials(creds)
        assert len(result) == 0

    def test_rejects_short_keys(self):
        creds = [self._cred("sk-short")]
        result = pre_filter_credentials(creds)
        assert len(result) == 0

    def test_rejects_broadcast_key(self):
        """Same key on > 5 different URLs → honeypot/broadcast → reject."""
        key = "sk-real-looking-" + "R" * 30
        creds = [self._cred(key, f"https://host{i}.example.com/v1") for i in range(7)]
        result = pre_filter_credentials(creds)
        assert len(result) == 0

    def test_keeps_key_on_few_urls(self):
        """Same key on <= 5 URLs is OK."""
        key = "sk-legitimate-" + "L" * 30
        creds = [self._cred(key, f"https://host{i}.example.com/v1") for i in range(3)]
        result = pre_filter_credentials(creds)
        assert len(result) == 3

    def test_mixed_batch(self):
        """Mix of valid and invalid keys — only valid survive."""
        creds = [
            self._cred("sk-proj-" + "V" * 30),  # valid
            self._cred("GOCSPX-google-oauth-bad"),  # google oauth → reject
            self._cred("sk-ant-good-" + "G" * 30),  # valid
            self._cred("abcdef1234567890abcdef1234567890"),  # hex32 → reject
            self._cred("sk-example_key_placeholder_test"),  # noise → reject
        ]
        result = pre_filter_credentials(creds)
        assert len(result) == 2
        keys = {c.apikey for c in result}
        assert any("sk-proj-" in k for k in keys)
        assert any("sk-ant-good-" in k for k in keys)
