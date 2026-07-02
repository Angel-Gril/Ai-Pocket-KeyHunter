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
