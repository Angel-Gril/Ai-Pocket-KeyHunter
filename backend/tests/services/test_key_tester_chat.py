"""test_chat must not treat models-list 200 as conversation success.

Regression suite for OpenAI / Anthropic: 401 and 429 on chat/messages must
surface as failure with the real status code — never success with HTTP 200.
"""

from __future__ import annotations

import httpx
import respx

# Alias: bare `test_chat` would be collected by pytest as a test case.
from aipocket.api.key_tester import test_chat as run_key_chat

OAI_KEY = "sk-proj-" + "a" * 40
OAI_BASE = "https://api.openai.com/v1"
ANT_KEY = "sk-ant-api03-" + "A" * 40
ANT_BASE = "https://api.anthropic.com/v1"


@respx.mock
async def test_openai_chat_success_requires_completion_200() -> None:
    respx.get(f"{OAI_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
    )
    respx.post(f"{OAI_BASE}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "chatcmpl_ok",
                "model": "gpt-4o-mini",
                "choices": [{"message": {"role": "assistant", "content": "hi"}}],
            },
        )
    )

    result = await run_key_chat(OAI_KEY, OAI_BASE, "gpt-4o-mini")

    assert result.valid is True
    assert result.status_code == 200
    assert result.model_available == "gpt-4o-mini"
    assert result.error == ""


@respx.mock
async def test_openai_chat_429_is_not_success_despite_models_200() -> None:
    """The old bug: models 200 → success even when chat would 429."""
    respx.get(f"{OAI_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
    )
    chat = respx.post(f"{OAI_BASE}/chat/completions").mock(
        return_value=httpx.Response(
            429,
            json={"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}},
        )
    )

    result = await run_key_chat(OAI_KEY, OAI_BASE, "gpt-4o-mini")

    assert chat.called
    assert result.valid is False
    assert result.status_code == 429
    assert result.error == "rate_limited"


@respx.mock
async def test_openai_chat_401_is_not_success_despite_models_200() -> None:
    respx.get(f"{OAI_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
    )
    respx.post(f"{OAI_BASE}/chat/completions").mock(
        return_value=httpx.Response(
            401,
            json={"error": {"message": "Incorrect API key provided"}},
        )
    )

    result = await run_key_chat(OAI_KEY, OAI_BASE, "gpt-4o-mini")

    assert result.valid is False
    assert result.status_code == 401
    assert result.error == "unauthorized"


@respx.mock
async def test_openai_chat_never_succeeds_on_models_only() -> None:
    """READ_ONLY models path must not be used for test_chat."""
    models = respx.get(f"{OAI_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
    )
    # No chat route — if test_chat only hits models, it would wrongly succeed.
    respx.post(f"{OAI_BASE}/chat/completions").mock(
        return_value=httpx.Response(500, json={"error": {"message": "boom"}})
    )
    respx.post(f"{OAI_BASE}/responses").mock(
        return_value=httpx.Response(500, json={"error": {"message": "boom"}})
    )

    result = await run_key_chat(OAI_KEY, OAI_BASE, "gpt-4o-mini")

    assert models.called
    assert result.valid is False
    assert result.status_code == 500


@respx.mock
async def test_anthropic_chat_success_requires_messages_200() -> None:
    respx.get(f"{ANT_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "claude-sonnet-4-6"}]})
    )
    respx.post(f"{ANT_BASE}/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "model": "claude-sonnet-4-6",
                "content": [{"type": "text", "text": "ok"}],
            },
        )
    )

    result = await run_key_chat(ANT_KEY, ANT_BASE, "claude-sonnet-4-6")

    assert result.valid is True
    assert result.status_code == 200
    assert result.model_available == "claude-sonnet-4-6"


@respx.mock
async def test_anthropic_chat_429_is_not_success_despite_models_200() -> None:
    respx.get(f"{ANT_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "claude-sonnet-4-6"}]})
    )
    messages = respx.post(f"{ANT_BASE}/messages").mock(
        return_value=httpx.Response(
            429,
            json={"error": {"type": "rate_limit_error", "message": "Rate limit"}},
        )
    )

    result = await run_key_chat(ANT_KEY, ANT_BASE, "claude-sonnet-4-6")

    assert messages.called
    assert result.valid is False
    assert result.status_code == 429
    assert result.error == "rate_limited"


@respx.mock
async def test_anthropic_chat_401_is_not_success_despite_models_200() -> None:
    respx.get(f"{ANT_BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "claude-sonnet-4-6"}]})
    )
    respx.post(f"{ANT_BASE}/messages").mock(
        return_value=httpx.Response(
            401,
            json={"error": {"type": "authentication_error", "message": "invalid x-api-key"}},
        )
    )

    result = await run_key_chat(ANT_KEY, ANT_BASE, "claude-sonnet-4-6")

    assert result.valid is False
    assert result.status_code == 401
    assert result.error == "unauthorized"
