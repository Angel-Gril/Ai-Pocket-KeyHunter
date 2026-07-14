"""Shodan query builder — the Shodan-syntax counterpart to ``queries.py``.

Shodan's search syntax differs from FOFA, so the two backends need separate query
builders (this is the "the two sources are different" part). This module reuses
the same CVE map and product catalogue as FOFA (:mod:`aipocket.queries`), but
emits Shodan filters:

    FOFA                                Shodan
    --------------------------------------------------
    body="LiteLLM"                      http.html:"LiteLLM"
    header="x-litellm"                  "x-litellm"   (bare banner search)
    status_code="200"                   http.status:200
    icon_hash="-1720536238"             http.favicon.hash:-1720536238

Shodan only indexes internet-facing services (great fit for exposed AI gateways).
For HTTP services Shodan has the banner (`data`, incl. response headers) AND the
crawled body (`http.html`), so credential-leak queries target both.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .queries import (
    PRODUCT_QUERIES,
    SKIP_PRODUCTS,
    VULN_TYPE_PRIORITIES,
    _normalize_product,
    _should_skip,
    load_cves,
)

log = logging.getLogger(__name__)

# Per-product Shodan fingerprints. Mirrors PRODUCT_QUERIES intent, Shodan syntax.
#
# DESIGN (validated via /shodan/host/count, Jul 2026):
#   - Shodan's http.html index is SHALLOW — it only holds a summary of the
#     crawled homepage, not endpoint responses. Stacking http.html constraints
#     like http.html:"dify" http.html:"api_key" collapses recall to ~2.
#     Single http.html:"dify" has 10k+, but most are blog/doc noise.
#   - The high-precision fingerprint is http.title + the product's DEFAULT PORT
#     (or one http.html marker that genuinely appears in the homepage bundle).
#     This mirrors the 7WaySecurity AI_SHODAN_DORKS methodology: identify the
#     service by title/port, then let the prober fetch live endpoints.
#   - Do NOT search for bare "sk-"/"api_key" here — Shodan http.html can't see
#     them. Credential discovery is the prober's job (active fetch of /.env,
#     /console/api/*, /v1/models, etc.).
#
# Each entry is a list of full Shodan queries (filters already applied).
# Recall numbers are count-endpoint estimates at rewrite time.
SHODAN_PRODUCT_QUERIES: dict[str, list[str]] = {
    # Dify: title + "console" (the /console path is baked into the SPA bundle,
    # so real deployments match; blogs/docs don't). ~1.4k, low noise.
    "Dify": [
        'http.title:"Dify" http.html:"console"',
    ],
    # LiteLLM: default proxy port 4000 is the strongest signal. ~1.7k.
    "LiteLLM": [
        'http.title:"LiteLLM" port:4000',
    ],
    # Open WebUI: default port 3000 + title. ~5.8k, the largest clean pool.
    "OpenWebUI": [
        'http.title:"Open WebUI" port:3000',
    ],
    # New-API / One-API: title is unreliable (admins rename it to "我的中转站"
    # etc.), so fingerprint on hardcoded <meta> tags in the homepage HTML instead.
    #   - New-API ships <meta name="generator" content="new-api"> → ~20k, and
    #     identify() sees "new-api" in the banner (=http.html), so it routes
    #     correctly even when the title was changed.
    #   - One-API (the upstream) lacks the generator tag but shares the Chinese
    #     description "二次分发管理 key"; subtracting generator isolates One-API
    #     from New-API → ~5k.
    # `/api/status` was rejected: 13k hits but ~all are Uptime-Kuma/status pages
    # matching the `/api/status-page/...` substring, not New-API.
    "New-API": [
        'http.html:"generator" http.html:"new-api"',
    ],
    "One-API": [
        'http.html:"二次分发管理 key" -http.html:"generator"',
    ],
    # Smaller, distinctive titles — bare title is already precise.
    "LobeChat": [
        'http.title:"LobeChat"',
    ],
    "LibreChat": [
        'http.title:"LibreChat"',
    ],
    "FastGPT": [
        'http.title:"FastGPT"',
    ],
    # Flowise: default port 3000 filters the 22k title noise down to ~680 real
    # deployments. port:8080 is a secondary Flowise port (~11) — not worth a
    # second query for the credit cost.
    "Flowise": [
        'http.title:"Flowise" port:3000',
    ],
    # Langflow: bare title is 22k but ~99% tutorial/blog noise. Langflow has no
    # hardcoded product-name <meta> (unlike New-API's generator tag), so HTML
    # markers can't tighten it cleanly. Title + a comma-separated port list
    # (Shodan's multi-value port syntax, OR without the parens that break the
    # parser) is the best precision/recall trade: ~316 hits, all title-matched
    # Langflow on common ports — 99% noise rejected vs bare title.
    "Langflow": [
        'http.title:"Langflow" port:80,443,3000,8080,7860',
    ],
    # P1 products with dedicated probers
    "ChatGPT-Next-Web": [
        'http.title:"NextChat"',
        'http.html:"chatgpt-next-web"',
    ],
    "Portkey AI Gateway": [
        'http.title:"Portkey"',
        'http.html:"portkey" http.html:"gateway"',
    ],
    "OpenRouter": [
        'http.title:"OpenRouter"',
        'http.html:"openrouter" http.html:"sk-or-"',
    ],
    "AnythingLLM": [
        'http.title:"AnythingLLM"',
        'http.html:"anythingllm"',
    ],
}

# Credential-leak queries — plaintext keys leaked in banners (HTTP headers) or
# crawled page bodies. Bare quoted phrases search the full banner (`data`), which
# for HTTP includes response headers — the highest-ROI place for `Authorization`
# / `x-api-key` leaks. `http.html:` searches the page body.
SHODAN_CREDENTIAL_QUERIES: list[str] = [
    # --- HTTP header leaks (banner `data`): Authorization / x-api-key ---
    '"authorization: bearer sk-" http.status:200',
    '"authorization: bearer sk-proj" http.status:200',
    '"x-api-key: sk-" http.status:200',
    '"x-api-key: sk-proj" http.status:200',
    '"authorization: bearer sk-ant-" http.status:200',
    # --- Anthropic / Claude key leaks ---
    'http.html:"ANTHROPIC_API_KEY" "sk-ant-"',
    '"x-api-key: sk-ant-" http.status:200',
    'http.html:"anthropic" "api_key"',
    # --- Domestic provider keys in exposed configs ---
    'http.html:"DEEPSEEK_API_KEY"',
    'http.html:"MOONSHOT_API_KEY"',
    # --- .env file exposure ---
    'http.html:"OPENAI_API_KEY" http.html:"sk-proj-"',
    'http.html:".env" http.html:"API_KEY"',
    # --- Gateway admin credential exposure ---
    'http.html:"master_key" http.html:"sk-"',
    'http.html:"token" "new-api" http.html:"sk-"',
    # --- page body leaks (.env / config snippets indexed by Shodan) ---
    'http.html:"OPENAI_API_KEY=sk-"',
    'http.html:"OPENAI_API_KEY=sk-proj"',
    'http.html:"api_key=sk-proj"',
    'http.html:"apiKey=sk-proj"',
    'http.html:"api_key=sk-"',
    'http.html:"apiKey=sk-"',
    'http.html:"ANTHROPIC_API_KEY=sk-ant-"',
    'http.html:"sk-ant-"',
]


# Country facets used to shard the largest product queries. Each facet becomes a
# separate query (its page 1 costs 1 credit), and each shard independently
# paginates up to SHODAN_MAX_PAGES — so a 20k-hit query fans out into N shards
# that each return up to SHODAN_MAX_PAGES pages of mostly-non-overlapping hosts,
# dodging the per-query 100-results/page wall.
#
# Selection: top countries for self-hosted AI gateways by deployment density.
# US/DE/FR/GB = Western cloud; CN/KR = the LLM-proxy crowd that dominates
# New-API/One-API; JP/SG = APAC. Shodan country codes are ISO-3166-1 alpha-2.
# Order is for log readability only (US first); recall is order-independent.
SHARD_COUNTRIES: list[str] = ["US", "CN", "DE", "JP", "FR", "GB", "SG", "KR"]

# Products whose Shodan count estimate exceeds the per-query page cap
# (100 * SHODAN_MAX_PAGES). Only these expand into country facets; smaller
# products stay single queries to avoid inflating credit cost for no recall
# gain. Keys MUST match SHODAN_PRODUCT_QUERIES (i.e. _normalize_product output).
SHARD_PRODUCTS: set[str] = {"New-API", "OpenWebUI", "LibreChat", "LiteLLM", "Dify"}
# Intentionally NO residual "no-country" query for sharded products: it would
# heavily overlap the country shards (most indexed hosts live in these 8
# countries), burning a page-1 credit for marginal recall. The 8 shards already
# cover the bulk; the long tail of low-deployment countries is a deliberate cut.


def build_shodan_queries(
    cves: list[dict[str, Any]] | None = None,
    *,
    skip_direct: bool = False,
    count: Callable[[str], int | None] | None = None,
    max_pages: int = 10,
    request_budget: int = 1000,
    credit_budget: int = 8,
) -> list[dict[str, Any]]:
    """Build the full list of Shodan queries to run.

    Returns a list of dicts with the same keys as FOFA's build_queries():
    ``query / cve_id / product / type / cvss`` — so the scanner can treat both
    sources uniformly while keeping the query strings source-specific.
    """
    cves = cves if cves is not None else load_cves()
    by_query: dict[str, dict[str, Any]] = {}

    # 1. Direct credential-leak queries first (highest ROI).
    for q in SHODAN_CREDENTIAL_QUERIES:
        if skip_direct:
            continue
        if q in by_query:
            continue
        by_query[q] = {
            "query": q,
            "cve_id": "DIRECT-CRED-LEAK",
            "advisory_ids": ["DIRECT-CRED-LEAK"],
            "product_hints": ["generic"],
            "product": "generic",
            "type": "API key泄露",
            "cvss": "",
            "lane": "provider"
            if any(marker in q for marker in ("ANTHROPIC", "DEEPSEEK", "MOONSHOT", "sk-ant"))
            else "direct",
        }

    # 2. Product-fingerprint queries derived from the CVE map, ordered by priority.
    sorted_cves = sorted(
        cves,
        key=lambda c: (VULN_TYPE_PRIORITIES.get(c.get("type", ""), 9), -c.get("cvss", 0)),
    )

    for cve in sorted_cves:
        product = cve.get("product", "")
        cve_type = cve.get("type", "")
        priority = VULN_TYPE_PRIORITIES.get(cve_type, 9)
        if priority > 3:
            continue
        if _should_skip(product):
            continue

        base_product = _normalize_product(product)
        templates = SHODAN_PRODUCT_QUERIES.get(base_product)
        if not templates:
            continue

        # High-volume products (SHARD_PRODUCTS) fan out into one query per
        # country facet so each shard can paginate past the 100/page wall
        # independently. Low-volume products run a single query each.
        for tmpl in templates:
            facets = [tmpl]
            if base_product in SHARD_PRODUCTS:
                if count is None:
                    facets = [f"{tmpl} country:{country}" for country in SHARD_COUNTRIES]
                else:
                    base_count = count(tmpl)
                    if base_count is not None and base_count > max_pages * 100:
                        counted = [
                            (country, count(f"{tmpl} country:{country}"))
                            for country in SHARD_COUNTRIES
                        ]
                        ranked = sorted(
                            ((country, total) for country, total in counted if total),
                            key=lambda item: (-item[1], SHARD_COUNTRIES.index(item[0])),
                        )
                        covered = 0
                        facets = []
                        for country, total in ranked[:credit_budget]:
                            facets.append(f"{tmpl} country:{country}")
                            covered += min(total, max_pages * 100)
                            if covered >= min(base_count, request_budget):
                                break
            for q in facets:
                if q in by_query:
                    entry = by_query[q]
                    if cve["id"] not in entry["advisory_ids"]:
                        entry["advisory_ids"].append(cve["id"])
                    if product not in entry["product_hints"]:
                        entry["product_hints"].append(product)
                    continue
                by_query[q] = {
                    "query": q,
                    "cve_id": cve["id"],
                    "advisory_ids": [cve["id"]],
                    "product_hints": [product],
                    "product": product,
                    "type": cve_type,
                    "cvss": str(cve.get("cvss", "")),
                    "lane": "product",
                }

    return list(by_query.values())


# Re-export for callers/tests that want the catalogue alongside the builder.
__all__ = [
    "SHODAN_PRODUCT_QUERIES",
    "SHODAN_CREDENTIAL_QUERIES",
    "SHARD_COUNTRIES",
    "SHARD_PRODUCTS",
    "build_shodan_queries",
    "PRODUCT_QUERIES",
    "SKIP_PRODUCTS",
    "VULN_TYPE_PRIORITIES",
]
