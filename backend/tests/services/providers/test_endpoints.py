from __future__ import annotations

import pytest

from aipocket.services.providers.endpoints import build_operation_url, canonicalize_endpoint


@pytest.mark.parametrize(
    ("raw", "provider", "expected"),
    [
        ("api.anthropic.com", "anthropic", "https://api.anthropic.com/v1"),
        ("https://api.anthropic.com/v1/messages", "anthropic", "https://api.anthropic.com/v1"),
        ("https://api.deepseek.com/v1/chat/completions", "deepseek", "https://api.deepseek.com"),
        ("https://api.deepseek.com/v1", "deepseek", "https://api.deepseek.com"),
        ("https://api.moonshot.cn/v1/chat/completions", "kimi", "https://api.moonshot.cn/v1"),
        ("https://open.bigmodel.cn/api/paas/v4/chat/completions", "glm", "https://open.bigmodel.cn/api/paas/v4"),
        ("https://api.minimax.chat/v1/chat/completions", "minimax", "https://api.minimax.chat/v1"),
        ("https://relay.example/v1/chat/completions", "gateway", "https://relay.example/v1"),
        ("https://api.longcat.chat/openai/v1/chat/completions", "longcat", "https://api.longcat.chat/openai"),
        ("https://api.longcat.chat/anthropic/v1/messages", "longcat", "https://api.longcat.chat/anthropic"),
    ],
)
def test_canonical_api_bases(raw: str, provider: str, expected: str) -> None:
    assert canonicalize_endpoint(raw, provider=provider).api_base == expected


def test_origin_strips_default_port_query_and_fragment() -> None:
    endpoint = canonicalize_endpoint("HTTPS://EXAMPLE.COM:443/v1/models?q=1#x", provider="gateway")
    assert endpoint.origin == "https://example.com"
    assert endpoint.api_base == "https://example.com"


def test_ipv6_and_explicit_port_are_preserved() -> None:
    endpoint = canonicalize_endpoint("http://[2001:db8::1]:8080/v1/chat/completions", provider="gateway")
    assert endpoint.origin == "http://[2001:db8::1]:8080"
    assert endpoint.api_base == "http://[2001:db8::1]:8080/v1"


def test_longcat_operations_keep_protocol_base() -> None:
    openai = canonicalize_endpoint("https://api.longcat.chat/openai", provider="longcat")
    anthropic = canonicalize_endpoint("https://api.longcat.chat/anthropic", provider="longcat")
    assert build_operation_url(openai, provider="longcat", operation="chat") == "https://api.longcat.chat/openai/v1/chat/completions"
    assert build_operation_url(anthropic, provider="longcat", operation="messages") == "https://api.longcat.chat/anthropic/v1/messages"


@pytest.mark.parametrize(
    ("raw", "provider", "operation", "expected"),
    [
        ("https://api.anthropic.com/v1", "anthropic", "messages", "https://api.anthropic.com/v1/messages"),
        ("https://api.deepseek.com", "deepseek", "balance", "https://api.deepseek.com/user/balance"),
        ("https://api.moonshot.cn/v1", "kimi", "balance", "https://api.moonshot.cn/v1/users/me/balance"),
        ("https://api.minimax.io/v1", "minimax", "quota", "https://api.minimax.io/v1/token_plan/remains"),
        ("https://open.bigmodel.cn/api/paas/v4", "glm", "models", "https://open.bigmodel.cn/api/paas/v4/models"),
        ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen", "chat", "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"),
        ("https://relay.example/custom", "gateway", "chat", "https://relay.example/custom/v1/chat/completions"),
        ("https://relay.example/v1", "gateway", "models", "https://relay.example/v1/models"),
    ],
)
def test_provider_operation_urls(raw: str, provider: str, operation: str, expected: str) -> None:
    endpoint = canonicalize_endpoint(raw, provider=provider)
    assert build_operation_url(endpoint, provider=provider, operation=operation) == expected


def test_invalid_endpoint_and_unknown_operation_are_empty() -> None:
    endpoint = canonicalize_endpoint("https:///missing-host", provider="gateway")
    assert endpoint.api_base == ""
    assert build_operation_url(endpoint, provider="gateway", operation="chat") == ""
    valid = canonicalize_endpoint("https://relay.example/v1", provider="gateway")
    assert build_operation_url(valid, provider="gateway", operation="balance") == ""


def test_invalid_port_is_treated_as_no_explicit_port() -> None:
    endpoint = canonicalize_endpoint("https://example.com:invalid/v1", provider="gateway")
    assert endpoint.origin == "https://example.com"
