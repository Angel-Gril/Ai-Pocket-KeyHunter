from dataclasses import FrozenInstanceError

import pytest

from aipocket.core.targets import TargetIdentity, canonicalize_hits


def test_same_endpoint_from_sources_becomes_one_target():
    hits = [
        {
            "host": "EXAMPLE.com:443",
            "protocol": "https",
            "_source": "fofa",
            "_query_id": "query-1",
            "_cve": "CVE-1",
            "_product": "Dify",
            "header": "server: a",
        },
        {
            "host": "https://example.com",
            "protocol": "https",
            "_source": "shodan",
            "_query_id": "query-2",
            "_cve": "CVE-2",
            "_product": "dify",
            "banner": "body-b",
        },
    ]

    merged = canonicalize_hits(hits)

    assert len(merged) == 1
    assert merged[0].identity == TargetIdentity("https", "example.com", 443)
    assert merged[0].sources == frozenset({"fofa", "shodan"})
    assert merged[0].query_ids == frozenset({"query-1", "query-2"})
    assert merged[0].advisory_ids == frozenset({"CVE-1", "CVE-2"})
    assert merged[0].product_hints == frozenset({"dify"})
    assert merged[0].content_evidence == ("server: a", "body-b")


@pytest.mark.parametrize(
    ("hit", "identity"),
    [
        ({"host": "http://Example.COM"}, TargetIdentity("http", "example.com", 80)),
        ({"host": "https://[2001:db8::1]"}, TargetIdentity("https", "2001:db8::1", 443)),
        (
            {"host": "[2001:db8::1]:8443", "protocol": "https"},
            TargetIdentity("https", "2001:db8::1", 8443),
        ),
        (
            {"host": "example.com:8080", "protocol": "http"},
            TargetIdentity("http", "example.com", 8080),
        ),
    ],
)
def test_canonicalizes_url_ipv6_and_ports(hit, identity):
    assert canonicalize_hits([hit])[0].identity == identity


def test_empty_hosts_are_skipped_safely():
    assert canonicalize_hits([{"host": ""}, {"host": "   "}, {}]) == []


def test_hostname_and_ip_aliases_remain_distinct_without_identity_evidence():
    merged = canonicalize_hits(
        [
            {"host": "example.com", "ip": "192.0.2.1", "protocol": "https"},
            {"host": "192.0.2.1", "protocol": "https"},
        ]
    )

    assert len(merged) == 2


def test_targets_are_immutable():
    target = canonicalize_hits([{"host": "example.com"}])[0]

    with pytest.raises(FrozenInstanceError):
        target.__setattr__("identity", TargetIdentity("http", "other.example", 80))
