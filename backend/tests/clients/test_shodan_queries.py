from __future__ import annotations

from aipocket.services.shodan_queries import (
    SHARD_COUNTRIES,
    SHARD_PRODUCTS,
    SHODAN_CREDENTIAL_QUERIES,
    SHODAN_PRODUCT_QUERIES,
    build_shodan_queries,
)


def test_build_shodan_queries_returns_non_empty():
    qs = build_shodan_queries([])
    assert len(qs) > 0
    # credential-leak queries are always emitted regardless of CVE list
    assert any(q["cve_id"] == "DIRECT-CRED-LEAK" for q in qs)
    for q in qs:
        assert "query" in q and "cve_id" in q and "product" in q


def test_build_shodan_queries_dedupes():
    qs = build_shodan_queries([])
    assert len(qs) == len({q["query"] for q in qs})


def test_build_shodan_queries_from_sample(sample_cves):
    qs = build_shodan_queries(sample_cves)
    products = {q["product"] for q in qs}
    # LibreChat (priority API key leak) is included, vLLM (DoS, priority>3) is not
    assert any("LibreChat" in p for p in products)
    assert not any("vLLM" in p for p in products)


def test_build_shodan_queries_real_file_includes_known_products(real_cves):
    qs = build_shodan_queries(real_cves)
    products = {q["product"] for q in qs}
    assert any("LiteLLM" in p for p in products)


def test_credential_queries_use_shodan_syntax():
    """Shodan queries must NOT be FOFA syntax (no body=/header=)."""
    qs = build_shodan_queries([])
    cred = [q["query"] for q in qs if q["cve_id"] == "DIRECT-CRED-LEAK"]
    assert cred == SHODAN_CREDENTIAL_QUERIES
    for q in cred:
        # Shodan filters use http.html:/http.status: or bare quoted banners,
        # never FOFA's body=/header=/banner=
        assert "body=" not in q
        assert "header=" not in q


def test_product_queries_cover_all_prober_products():
    """Every product the prober can identify must have a (non-empty) Shodan query.

    Design principle: building a Shodan query for a product the prober can't
    recognize is wasted credits — recall that the prober.identify() can't route.
    So coverage is keyed on PROBER products, not the larger FOFA catalogue
    (which lists products we may scan for via FOFA but can't actively probe).
    """
    # Prober-supported products → the SHODAN_PRODUCT_QUERIES key naming used in
    # queries._normalize_product. These are the products the prober can route.
    prober_products = {
        "Dify", "LiteLLM", "OpenWebUI", "New-API", "One-API",
        "LobeChat", "LibreChat", "FastGPT", "Flowise", "Langflow",
    }
    # Every prober-supported product must have at least one query (non-empty list).
    missing = {p for p in prober_products if not SHODAN_PRODUCT_QUERIES.get(p)}
    assert not missing, f"prober products without Shodan queries: {missing}"


def test_shard_constants_well_formed():
    """Shard config sanity: 2-letter ISO codes, no dup facets, all shard
    products are real SHODAN_PRODUCT_QUERIES keys (so they actually expand)."""
    assert SHARD_COUNTRIES
    assert all(isinstance(c, str) and len(c) == 2 for c in SHARD_COUNTRIES)
    assert len(set(SHARD_COUNTRIES)) == len(SHARD_COUNTRIES)
    assert SHARD_PRODUCTS <= set(SHODAN_PRODUCT_QUERIES)


def test_shard_products_expand_into_country_facets(real_cves):
    """A SHARD_PRODUCT fans out into one query per country facet."""
    qs = build_shodan_queries(real_cves)
    # LiteLLM is a SHARD_PRODUCT whose base query is 'http.title:"LiteLLM" port:4000'
    litellm = [q for q in qs if q["product"] and "LiteLLM" in q["product"]]
    assert len(litellm) == len(SHARD_COUNTRIES)
    for c in SHARD_COUNTRIES:
        assert any(f"country:{c}" in q["query"] for q in litellm)
    # all shards share the parent's cve_id (so hits are tagged correctly)
    base_cve = litellm[0]["cve_id"]
    assert all(q["cve_id"] == base_cve for q in litellm)


def test_non_shard_products_not_faceted():
    """Products NOT in SHARD_PRODUCTS stay a single query (no country facet).

    Built from a synthetic CVE list rather than the real file, since the real
    file may not include every non-shard product (coverage is filtered by
    priority + the prober catalogue).
    """
    synth = [
        {"id": "CVE-TEST-1", "cvss": 9.0, "product": name, "type": "API key泄露"}
        for name in ("LobeChat", "Flowise")
    ]
    qs = build_shodan_queries(synth)
    for product_name in ("LobeChat", "Flowise"):
        matched = [q for q in qs if product_name in q["product"]]
        assert matched, f"{product_name} should have a query"
        for q in matched:
            assert "country:" not in q["query"], f"{product_name} unexpectedly faceted: {q['query']}"
