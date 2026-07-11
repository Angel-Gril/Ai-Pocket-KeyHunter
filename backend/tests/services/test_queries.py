from __future__ import annotations

from aipocket.services.queries import VULN_TYPE_PRIORITIES, _normalize_product, build_queries


def test_load_cves_returns_list(real_cves):
    assert isinstance(real_cves, list)
    assert len(real_cves) > 0
    assert "id" in real_cves[0]


def test_build_queries_from_sample(sample_cves):
    qs = build_queries(sample_cves)
    assert len(qs) > 0
    for q in qs:
        assert "query" in q
        assert "cve_id" in q
        assert "product" in q
        # FOFA queries are field-prefix filters (body=/header=/banner=/icon_hash=)
        assert any(q["query"].startswith(p) for p in ("body=", "header=", "banner=", "icon_hash="))


def test_build_queries_dedupes(sample_cves):
    doubled = sample_cves + sample_cves
    qs = build_queries(doubled)
    queries_set = {q["query"] for q in qs}
    assert len(queries_set) == len(qs)


def test_build_queries_filters_low_priority(sample_cves):
    qs = build_queries(sample_cves)
    products = {q["product"] for q in qs}
    assert "vLLM" not in products


def test_build_queries_real_file_includes_known_products(real_cves):
    qs = build_queries(real_cves)
    products = {q["product"] for q in qs}
    assert any("LiteLLM" in p for p in products)
    assert any("Dify" in p for p in products)


def test_build_queries_appends_status_code(sample_cves):
    qs = build_queries(sample_cves)
    for q in qs:
        if q["cve_id"] == "DIRECT-CRED-LEAK":
            continue
        assert 'status_code="200"' in q["query"]


def test_normalize_product_variants():
    assert _normalize_product("LiteLLM (AI Gateway)") == "LiteLLM"
    assert _normalize_product("IBM Langflow OSS") == "Langflow"
    assert _normalize_product("OpenWebUI") == "OpenWebUI"
    assert _normalize_product("unknown product") == "unknown product"


def test_normalize_product_rejects_empty_and_generic_short_names():
    assert _normalize_product("") == ""
    assert _normalize_product("api") == "api"
    assert _normalize_product("chat") == "chat"


def test_build_queries_empty_list_does_not_load_defaults(monkeypatch):
    monkeypatch.setattr(
        "aipocket.services.queries.load_cves",
        lambda: (_ for _ in ()).throw(AssertionError("defaults loaded")),
    )

    assert build_queries([], skip_direct=True) == []


def test_build_queries_unions_duplicate_query_provenance():
    cves = [
        {"id": "CVE-2026-1", "cvss": 9.8, "product": "Dify", "type": "认证绕过"},
        {"id": "CVE-2026-2", "cvss": 8.1, "product": "Dify platform", "type": "信息泄露"},
    ]

    queries = build_queries(cves, skip_direct=True)

    assert queries
    assert all(q["advisory_ids"] == ["CVE-2026-1", "CVE-2026-2"] for q in queries)
    assert all(q["product_hints"] == ["Dify", "Dify platform"] for q in queries)


def test_priority_map_has_key_types():
    assert VULN_TYPE_PRIORITIES["API key泄露"] == 1
    assert VULN_TYPE_PRIORITIES["认证绕过"] == 1
    assert VULN_TYPE_PRIORITIES["DoS"] == 5


def test_build_queries_orders_by_priority(real_cves):
    qs = build_queries(real_cves)
    types = [q["type"] for q in qs]
    priority_values = [VULN_TYPE_PRIORITIES.get(t, 9) for t in types]
    assert priority_values == sorted(priority_values)


def test_build_queries_labels_direct_product_and_provider_lanes(sample_cves):
    queries = build_queries(sample_cves)

    lanes = {query["lane"] for query in queries}

    assert lanes == {"direct", "product", "provider"}
