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
# Each entry is a list of full Shodan queries (filters already applied).
SHODAN_PRODUCT_QUERIES: dict[str, list[str]] = {
    "LiteLLM": [
        'http.html:"LiteLLM"',
        'http.title:"LiteLLM"',
        '"x-litellm"',
    ],
    "Flowise": [
        'http.html:"Flowise"',
        'http.title:"Flowise"',
    ],
    "Dify": [
        'http.html:"dify"',
        'http.title:"Dify"',
    ],
    "LibreChat": [
        'http.html:"LibreChat"',
        'http.title:"LibreChat"',
    ],
    "OpenWebUI": [
        'http.html:"Open WebUI"',
        'http.title:"Open WebUI"',
    ],
    "Langflow": [
        'http.html:"langflow"',
        'http.title:"langflow"',
    ],
    "MLflow": [
        'http.html:"mlflow"',
        'http.title:"MLflow"',
    ],
    "Portkey AI Gateway": [
        'http.html:"portkey"',
        '"x-portkey"',
    ],
    "LangChain": [
        'http.html:"langchain"',
    ],
    "PraisonAI": [
        'http.html:"praisonai"',
    ],
    "GitLab AI Gateway": [
        '"X-Gitlab-Duo"',
        'http.html:"ai-gateway"',
    ],
    "FastGPT": [
        'http.html:"fastgpt"',
        'http.title:"FastGPT"',
    ],
    "New-API": [
        'http.html:"new-api"',
        'http.title:"new-api"',
    ],
    "AnythingLLM": [
        'http.html:"anythingllm"',
        'http.title:"AnythingLLM"',
    ],
    "ChatGPT-Next-Web": [
        'http.html:"nextchat"',
        'http.html:"chatgpt-next-web"',
        'http.title:"ChatGPT Next Web"',
    ],
    "vLLM": [
        'http.title:"vLLM"',
        'http.html:"vllm"',
    ],
    "Ollama": [
        'http.html:"ollama"',
        'http.title:"Ollama"',
    ],
    "LocalAI": [
        'http.html:"localai"',
    ],
    "Text-Generation-WebUI": [
        'http.html:"oobabooga"',
        'http.html:"text-generation-webui"',
    ],
    "LobeChat": [
        'http.html:"lobe-chat"',
        'http.title:"LobeChat"',
    ],
    "Jan": [
        'http.html:"jan.ai"',
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
