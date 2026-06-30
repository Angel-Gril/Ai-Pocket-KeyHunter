from __future__ import annotations

from aipocket.shodan_queries import (
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


def test_product_queries_cover_all_catalogue_products():
    """Every product in the shared catalogue has a Shodan fingerprint."""
    from aipocket.queries import PRODUCT_QUERIES

    missing = set(PRODUCT_QUERIES) - set(SHODAN_PRODUCT_QUERIES)
    assert not missing, f"products without Shodan queries: {missing}"
