from __future__ import annotations

from aipocket.clients.advisories import merge_advisories, parse_advisory_from_text
from aipocket.core.advisory import AdvisoryRecord


def test_parses_cve_including_older_still_affected_years() -> None:
    record = parse_advisory_from_text(
        title="LiteLLM authentication bypass CVE-2024-12345",
        content="Unauthenticated access to admin APIs in LiteLLM before 1.40.0 allows credential theft.",
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
    )
    assert record is not None
    assert record.advisory_id == "CVE-2024-12345"
    assert record.product == "litellm"
    assert "1.40.0" in record.affected_versions
    assert record.attack_surface == "auth_bypass"
    assert record.source_confidence == "high"
    assert record.safe_check_profile.startswith("readonly-")


def test_parses_ghsa_and_huntr_identifiers() -> None:
    ghsa = parse_advisory_from_text(
        title="GHSA-abcd-efgh-ijkl Dify SSRF",
        content="Dify server-side request forgery via webhook allows internal metadata access.",
        url="https://github.com/advisories/GHSA-abcd-efgh-ijkl",
    )
    huntr = parse_advisory_from_text(
        title="Flowise path traversal",
        content="Flowise information disclosure of .env containing API keys.",
        url="https://huntr.dev/bounties/12345678-aaaa-bbbb-cccc-dddddddddddd",
    )
    assert ghsa is not None and ghsa.advisory_id == "GHSA-ABCD-EFGH-IJKL"
    assert huntr is not None and huntr.advisory_id.startswith("HUNTR-")
    assert huntr.product == "flowise"


def test_accepts_credible_public_disclosure_without_cve_id() -> None:
    record = parse_advisory_from_text(
        title="Open WebUI exposed admin API without authentication",
        content=(
            "Security advisory: Open WebUI deployments with default config expose "
            "admin endpoints without authentication allowing API key extraction."
        ),
        url="https://vendor.example/security/open-webui-advisory",
    )
    assert record is not None
    assert record.advisory_id.startswith("DISCLOSURE-")
    assert record.product in {"open-webui", "openwebui"}
    assert record.source_confidence in {"medium", "low", "high"}


def test_rejects_uncorroborated_zero_day_claims() -> None:
    record = parse_advisory_from_text(
        title="BREAKING: 0-day in random AI tool",
        content="Zero-day RCE, no details, trust me bro.",
        url="https://sketchy-forum.example/posts/1",
    )
    assert record is None


def test_merge_updates_existing_advisory_fields() -> None:
    existing = [
        AdvisoryRecord(
            advisory_id="CVE-2024-1",
            product="dify",
            attack_surface="unknown",
            source_confidence="low",
            updated_at="2026-01-01T00:00:00Z",
            cvss=0.0,
        )
    ]
    discovered = [
        AdvisoryRecord(
            advisory_id="CVE-2024-1",
            product="dify",
            attack_surface="auth_bypass",
            source_confidence="high",
            updated_at="2026-07-01T00:00:00Z",
            cvss=9.1,
            sources=("https://nvd.nist.gov/vuln/detail/CVE-2024-1",),
            affected_versions=("0.6.0",),
        )
    ]
    merged, added = merge_advisories(existing, discovered)
    assert added == 0
    assert merged[0].cvss == 9.1
    assert merged[0].attack_surface == "auth_bypass"
    assert merged[0].affected_versions == ("0.6.0",)
    assert merged[0].sources[0].startswith("https://nvd.nist.gov/")


def test_legacy_cve_dict_preserves_query_compat_fields() -> None:
    record = parse_advisory_from_text(
        title="CVE-2025-99999 New-API key leak",
        content="New-API credential exposure via env dump.",
        url="https://nvd.nist.gov/vuln/detail/CVE-2025-99999",
    )
    assert record is not None
    legacy = record.to_legacy_cve_dict()
    assert legacy["id"] == "CVE-2025-99999"
    assert legacy["product"] == "new-api"
    assert legacy["type"] == "API key泄露"
    assert legacy["credential_relevance"] == "high"
