"""Tests for honeypot site cache — key normalization, filter, record, CRUD."""

from __future__ import annotations

from aipocket.core.models import Credential, ProviderInfo, ValidationResult
from aipocket.core.targets import DiscoveryTarget, TargetIdentity
from aipocket.services import honeypot_store as store


def test_normalize_site_key_scheme_agnostic():
    assert store.normalize_site_key("https://Evil.Example.com:8080/v1") == "evil.example.com:8080"
    assert store.normalize_site_key("http://evil.example.com:8080") == "evil.example.com:8080"
    assert store.normalize_site_key("evil.example.com:8080") == "evil.example.com:8080"


def test_normalize_site_key_default_ports():
    assert store.normalize_site_key("https://api.example.com") == "api.example.com:443"
    assert store.normalize_site_key("http://api.example.com") == "api.example.com:80"
    assert store.normalize_site_key("api.example.com") == "api.example.com:80"


def test_normalize_site_key_empty():
    assert store.normalize_site_key("") == ""
    assert store.normalize_site_key("   ") == ""


def test_site_key_from_target_matches_normalize():
    target = DiscoveryTarget(
        identity=TargetIdentity(scheme="https", hostname="1.2.3.4", port=8443),
    )
    assert store.site_key_from_target(target) == "1.2.3.4:8443"
    assert store.normalize_site_key(target.identity.url) == "1.2.3.4:8443"


def test_is_host_level_honeypot_error():
    assert store.is_host_level_honeypot_error(
        "honeypot:no-auth-host (forged key also validated — endpoint ignores Authorization)"
    )
    assert store.is_host_level_honeypot_error("honeypot:steganography (20 zero-width chars)")
    assert store.is_host_level_honeypot_error("honeypot:response-cluster (5 hosts, same response)")
    assert not store.is_host_level_honeypot_error("honeypot:cluster-key (same key on 6 hosts)")
    assert not store.is_host_level_honeypot_error("blocked-key-format:hex-token-32-128")
    assert not store.is_host_level_honeypot_error("")
    assert not store.is_host_level_honeypot_error(None)


def test_extract_reason_label():
    assert (
        store.extract_reason_label("honeypot:no-auth-host (forged key…)") == "honeypot:no-auth-host"
    )


def test_filter_targets_skips_known():
    a = DiscoveryTarget(identity=TargetIdentity("http", "honeypot.example", 80))
    b = DiscoveryTarget(identity=TargetIdentity("https", "legit.example", 443))
    known = {"honeypot.example:80"}
    kept, skipped = store.filter_targets([a, b], known)
    assert skipped == 1
    assert len(kept) == 1
    assert kept[0].identity.hostname == "legit.example"


def test_filter_credentials_skips_known():
    bad = Credential(
        apikey="sk-aaa", host="https://hp.example:8139", apiurl="https://hp.example:8139/v1"
    )
    good = Credential(apikey="sk-bbb", host="https://ok.example", apiurl="https://ok.example/v1")
    known = {"hp.example:8139"}
    kept, skipped = store.filter_credentials([bad, good], known)
    assert skipped == 1
    assert len(kept) == 1
    assert kept[0].apikey == "sk-bbb"


def test_filter_empty_known_is_noop():
    targets = [DiscoveryTarget(identity=TargetIdentity("http", "x.com", 80))]
    kept, skipped = store.filter_targets(targets, set())
    assert skipped == 0
    assert kept is targets or kept == targets


def _result(host: str, error: str, valid: bool = False) -> ValidationResult:
    return ValidationResult(
        credential=Credential(apikey="sk-test1234567890", apiurl=f"http://{host}", host=host),
        valid=valid,
        error=error,
        status_code=200,
        provider_info=ProviderInfo(provider="unknown", category="unknown"),
    )


def test_record_from_results_pg_disabled_no_crash(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    results = [
        _result("hp.example:80", "honeypot:no-auth-host (forged)"),
        _result("ok.example:80", "", valid=True),
        _result("fmt.example:80", "blocked-key-format:hex-token-32-128"),
    ]
    n = store.record_from_results(results, run_id="run_test", no_auth_hosts={"extra.example:99"})
    assert n == 0


def test_record_site_pg_disabled_returns_dict(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    row = store.record_site("https://hp.example:9000", reason="honeypot:steganography")
    assert row is not None
    assert row["host_key"] == "hp.example:9000"
    assert row["reason"] == "honeypot:steganography"


def test_load_known_host_keys_pg_disabled(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    assert store.load_known_host_keys() == set()


def test_list_sites_pg_disabled(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    rows, total = store.list_sites()
    assert rows == []
    assert total == 0


def test_create_site_requires_pg(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    try:
        store.create_site("1.2.3.4:8080")
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "PostgreSQL" in str(e)


def test_create_site_bad_host(monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://x")
    # Still fails on empty host before needing a real pool
    try:
        store.create_site("   ")
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "无效" in str(e)
