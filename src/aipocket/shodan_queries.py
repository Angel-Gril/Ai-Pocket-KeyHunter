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


def build_shodan_queries(cves: list[dict[str, Any]] | None = None, *, skip_direct: bool = False) -> list[dict[str, str]]:
    """Build the full list of Shodan queries to run.

    Returns a list of dicts with the same keys as FOFA's build_queries():
    ``query / cve_id / product / type / cvss`` — so the scanner can treat both
    sources uniformly while keeping the query strings source-specific.
    """
    cves = cves if cves is not None else load_cves()
    seen: set[str] = set()
    out: list[dict[str, str]] = []

    # 1. Direct credential-leak queries first (highest ROI).
    for q in SHODAN_CREDENTIAL_QUERIES:
        if skip_direct:
            continue
        if q in seen:
            continue
        seen.add(q)
        out.append({
            "query": q,
            "cve_id": "DIRECT-CRED-LEAK",
            "product": "generic",
            "type": "API key泄露",
            "cvss": "",
        })

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

        for tmpl in templates:
            if tmpl in seen:
                continue
            seen.add(tmpl)
            out.append({
                "query": tmpl,
                "cve_id": cve["id"],
                "product": product,
                "type": cve_type,
                "cvss": str(cve.get("cvss", "")),
            })

    return out


# Re-export for callers/tests that want the catalogue alongside the builder.
__all__ = [
    "SHODAN_PRODUCT_QUERIES",
    "SHODAN_CREDENTIAL_QUERIES",
    "build_shodan_queries",
    "PRODUCT_QUERIES",
    "SKIP_PRODUCTS",
    "VULN_TYPE_PRIORITIES",
]
