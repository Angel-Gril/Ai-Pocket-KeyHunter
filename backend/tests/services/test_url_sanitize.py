"""Tests for manual target URL sanitization."""

from __future__ import annotations

import pytest

from aipocket.services.url_sanitize import (
    sanitize_target_url,
    sanitize_target_urls,
    urls_to_host_hits,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://web.ymocode.com", "https://web.ymocode.com"),
        ("https://web.ymocode.com/login/xxxx", "https://web.ymocode.com"),
        ("https://web.ymocode.com/v1/models?foo=1#x", "https://web.ymocode.com"),
        ("http://web.ymocode.com/path", "http://web.ymocode.com"),
        ("https://web1.ymocode.com:8443/admin", "https://web1.ymocode.com:8443"),
        ("web.ymocode.com", "https://web.ymocode.com"),
        ("web.ymocode.com/login", "https://web.ymocode.com"),
        ("//cdn.example.com/x", "https://cdn.example.com"),
        ("HTTPS://Example.COM:443/", "https://example.com"),
        ("http://10.0.0.1:8080/v1", "http://10.0.0.1:8080"),
        ('  "https://web.ymocode.com/foo"  ', "https://web.ymocode.com"),
        ("https://web.ymocode.com.,", "https://web.ymocode.com"),
    ],
)
def test_sanitize_strips_path_and_normalizes(raw: str, expected: str) -> None:
    cleaned = sanitize_target_url(raw)
    assert cleaned is not None
    assert cleaned.url == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "javascript:alert(1)",
        "ftp://files.example.com",
        "data:text/html,hi",
        "not a host!!!",
        "http://",
        "https://[bad",
        "http://example.com:99999",
    ],
)
def test_sanitize_rejects_garbage(raw: str) -> None:
    assert sanitize_target_url(raw) is None


def test_sanitize_batch_dedupes_and_collects_rejects() -> None:
    accepted, rejected = sanitize_target_urls(
        """
        https://web.ymocode.com/login
        https://web.ymocode.com/other
        https://web2.ymocode.com
        not-valid!!!
        ftp://x.com
        https://web2.ymocode.com/again
        """
    )
    assert [a.url for a in accepted] == [
        "https://web.ymocode.com",
        "https://web2.ymocode.com",
    ]
    assert "not-valid!!!" in rejected
    assert "ftp://x.com" in rejected


def test_sanitize_batch_from_list() -> None:
    accepted, rejected = sanitize_target_urls(
        ["https://a.example.com/x", "", "not a host!!!", "https://b.example.com"]
    )
    assert len(accepted) == 2
    assert rejected == ["not a host!!!"]


def test_urls_to_host_hits_shape() -> None:
    hits = urls_to_host_hits(["https://web.ymocode.com/login/xxx", "javascript:alert(1)"])
    assert len(hits) == 1
    hit = hits[0]
    assert hit["host"] == "https://web.ymocode.com"
    assert hit["protocol"] == "https"
    assert hit["port"] == "443"
    assert hit["_source"] == "manual"
    assert hit["_query_id"] == "manual-target"


def test_host_key_and_port_defaults() -> None:
    https = sanitize_target_url("https://a.example.com")
    http = sanitize_target_url("http://a.example.com")
    assert https is not None and http is not None
    assert https.host_key == "a.example.com:443"
    assert http.host_key == "a.example.com:80"
    assert https.port == 443
    assert http.port == 80


def test_ipv6_url() -> None:
    cleaned = sanitize_target_url("https://[2001:db8::1]:8443/path")
    assert cleaned is not None
    assert cleaned.url == "https://[2001:db8::1]:8443"
    assert cleaned.host_key == "[2001:db8::1]:8443"
