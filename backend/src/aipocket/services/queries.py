from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default CVE map. Override with AIPOCKET_CVE_PATH (e.g. sources/cve_realtest.json)
# to run a small end-to-end real scan against a trimmed CVE subset.
_DEFAULT_CVE_PATH = Path(__file__).resolve().parents[3] / "sources" / "cve_2026_ai.json"
CVE_PATH = Path(os.environ.get("AIPOCKET_CVE_PATH", _DEFAULT_CVE_PATH))


PRODUCT_QUERIES: dict[str, list[str]] = {
    "LiteLLM": [
        'body="litellm" && body="sk-"',
        'body="litellm_proxy" && body="api_key"',
        'body="LiteLLM Proxy" && body="master_key"',
    ],
    "Flowise": [
        'body="Flowise" && body="sk-"',
        'body="flowise" && body="apiKey"',
    ],
    "Dify": [
        'body="dify" && body="sk-"',
        'body="dify" && body="OPENAI_API_KEY"',
        'body="dify" && body="ANTHROPIC_API_KEY"',
    ],
    "LibreChat": [
        'body="librechat" && body="sk-"',
        'body="librechat" && body="OPENAI_API_KEY"',
        'body="librechat" && body="ANTHROPIC_API_KEY"',
    ],
    "OpenWebUI": [
        'body="Open WebUI" && body="sk-"',
        'body="open-webui" && body="api_key"',
    ],
    "Langflow": [
        'body="langflow" && body="sk-"',
        'body="langflow" && body="OPENAI_API_KEY"',
    ],
    "MLflow": [
        'body="mlflow" && body="sk-"',
        'body="mlflow" && body="api_key"',
    ],
    "Portkey AI Gateway": [
        'body="portkey" && body="sk-"',
        'body="portkey" && body="api_key"',
    ],
    "LangChain": [
        'body="langchain" && body="OPENAI_API_KEY"',
        'body="langchain" && body="sk-"',
    ],
    "PraisonAI": [
        'body="praisonai" && body="sk-"',
    ],
    "GitLab AI Gateway": [
        'body="ai-gateway" && body="sk-"',
    ],
    "FastGPT": [
        'body="fastgpt" && body="sk-"',
        'body="fastgpt" && body="OPENAI_API_KEY"',
    ],
    "New-API": [
        'body="new-api" && body="sk-"',
        'body="new-api" && body="token"',
    ],
    "One-API": [
        'body="one-api" && body="sk-"',
        'body="one-api" && body="token"',
        'body="oneapi" && body="sk-"',
    ],
    "AnythingLLM": [
        'body="anythingllm" && body="sk-"',
        'body="anythingllm" && body="OPENAI_API_KEY"',
    ],
    "ChatGPT-Next-Web": [
        'body="nextchat" && body="sk-"',
        'body="chatgpt-next-web" && body="OPENAI_API_KEY"',
    ],
    "OpenRouter": [
        'body="openrouter" && body="sk-or-"',
        'body="openrouter" && body="sk-"',
        'body="OpenRouter" && body="api_key"',
    ],
    "vLLM": [
        'body="vllm" && body="sk-"',
        'body="vllm" && body="api_key"',
    ],
    "Ollama": [
        'body="ollama" && body="sk-"',
    ],
    "LocalAI": [
        'body="localai" && body="sk-"',
    ],
    "Text-Generation-WebUI": [
        'body="text-generation-webui" && body="sk-"',
    ],
    "LobeChat": [
        'body="lobe-chat" && body="sk-"',
        'body="lobechat" && body="OPENAI_API_KEY"',
    ],
    "Jan": [
        'body="jan.ai" && body="sk-"',
    ],
    "Claude": [
        'body="claude" && body="sk-ant-"',
        'body="ANTHROPIC_API_KEY" && body="sk-ant-"',
        'body="anthropic" && body="api_key" && body="sk-"',
    ],
    "Codex CLI": [
        'body="codex" && body="OPENAI_API_KEY"',
    ],
}

VULN_TYPE_PRIORITIES = {
    "API key泄露": 1,
    "信息泄露": 1,
    "认证绕过": 1,
    "RCE": 2,
    "权限提升": 2,
    "SSRF": 3,
    "SQL注入": 2,
    "沙箱逃逸": 3,
    "DoS": 5,
}

# Credential leak queries — not CVE-bound, hit plaintext keys in exposed headers/banners/bodies.
# FOFA proxy (fofoapi.com) does NOT return the `body` field in results, so `body=`
# queries work as *filters* (FOFA matches the body) but we can only extract keys from
# the `header`/`banner` fields we actually get back.
#
# Strategy: lead with header=/banner= queries (highest ROI — we get that content back),
# keep a smaller set of body= queries as net to catch hosts that also leak in header/banner.
CREDENTIAL_QUERIES: list[str] = [
    # --- Header queries that ACTUALLY work (full header string match) ---
    # These return few results but keys are directly extractable from header field.
    'header="authorization: bearer sk-"',
    'header="authorization: bearer sk-proj"',
    'header="authorization: bearer sk-ant-"',
    'header="x-api-key: sk-"',
    'header="x-api-key: sk-ant-"',
    'header="api-key: sk-"',
    'header="apikey: sk-"',
    'banner="authorization: bearer sk-"',
    'banner="authorization: bearer sk-proj"',
    'banner="authorization: bearer sk-ant-"',
    'banner="OPENAI_API_KEY=sk-"',
    'banner="ANTHROPIC_API_KEY=sk-ant-"',
    # --- Body queries: find hosts with keys in page → GenericPageProber extracts ---
    # These are HIGH VOLUME but GenericPageProber fetches the actual key.
    'body="sk-proj-"',
    'body="sk-ant-api"',
    'body="OPENAI_API_KEY" && body="sk-"',
    'body="ANTHROPIC_API_KEY" && body="sk-ant-"',
    'body="DEEPSEEK_API_KEY" && body="sk-"',
    'body=".env" && body="sk-"',
    'body="docker-compose" && body="sk-"',
    'body="api_key" && body="sk-proj-"',
    # --- Domestic providers ---
    'body="moonshot" && body="sk-"',
    'body="deepseek" && body="sk-"',
    # --- Exposed config / gateway leaks ---
    'body="master_key" && body="sk-"',
    'body="DANGEROUSLY_DISABLE_AUTH" && body="sk-"',
]

_PROVIDER_QUERY_MARKERS = ("ANTHROPIC", "DEEPSEEK", "MOONSHOT", "sk-ant")


def load_cves(path: Path | None = None) -> list[dict[str, Any]]:
    """Load the CVE map.

    An explicit ``path`` always reads that file (used by ``--realtest`` for a
    trimmed subset). With no path and PG enabled: return the **union** of the PG
    ``cves`` table and the file, merged by ``id`` (PG rows win on conflict). This
    keeps the full set visible even when PG only holds a few newly-synced rows —
    previously a non-empty-but-partial PG table shadowed the complete file and
    the list shrank to just the synced entries.
    """
    if path is not None:
        return _load_cves_file(path)

    from aipocket.core.config import settings

    if not settings.pg_enabled:
        return _load_cves_file(CVE_PATH)

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        rows = conn.execute("SELECT record FROM cves ORDER BY id").fetchall()
    pg_records = [r["record"] for r in rows]

    # Empty table (not yet backfilled) → fall back to the file alone.
    if not pg_records:
        return _load_cves_file(CVE_PATH)

    # Merge: file is the base, PG rows override per-id, dedup by id, sort by id.
    file_records = _load_cves_file(CVE_PATH)
    merged: dict[str, dict[str, Any]] = {c["id"]: c for c in file_records if "id" in c}
    for c in pg_records:
        if "id" in c:
            merged[c["id"]] = c
    return sorted(merged.values(), key=lambda c: c.get("id", ""))


def backfill_cves_from_file() -> int:
    """Seed the PG ``cves`` table from the file on first start.

    Idempotent: if the table already has rows, do nothing. Returns the number of
    rows upserted (0 when the table is non-empty or PG is disabled). Best-effort
    by design — callers should catch and log, never let this block startup.
    """
    from aipocket.core.config import settings

    if not settings.pg_enabled:
        return 0

    from aipocket.core.db import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        n = conn.execute("SELECT count(*) AS n FROM cves").fetchone()["n"]
    if n:
        return 0  # already populated

    records = _load_cves_file(CVE_PATH)
    if not records:
        return 0

    from aipocket.clients.tavily import _upsert_cves_pg

    _upsert_cves_pg(records)
    log.info("Backfilled %d CVEs into PG from %s", len(records), CVE_PATH)
    return len(records)


def _load_cves_file(p: Path) -> list[dict[str, Any]]:
    try:
        text = p.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []


SKIP_PRODUCTS = frozenset(
    {
        "langgraph",
        "langsmith",
    }
)


def _should_skip(product: str) -> bool:
    p = product.lower()
    return any(s in p for s in SKIP_PRODUCTS)


def build_queries(
    cves: list[dict[str, Any]] | None = None, *, skip_direct: bool = False
) -> list[dict[str, Any]]:
    cves = load_cves() if cves is None else cves
    by_query: dict[str, dict[str, Any]] = {}

    for tmpl in CREDENTIAL_QUERIES:
        if skip_direct:
            continue
        q = tmpl
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
            if any(marker in q for marker in _PROVIDER_QUERY_MARKERS)
            else "direct",
        }

    sorted_cves = sorted(
        cves, key=lambda c: (VULN_TYPE_PRIORITIES.get(c.get("type", ""), 9), -c.get("cvss", 0))
    )

    for cve in sorted_cves:
        product = cve.get("product", "")
        cve_type = cve.get("type", "")
        priority = VULN_TYPE_PRIORITIES.get(cve_type, 9)
        if priority > 4:
            continue

        if _should_skip(product):
            continue

        base_product = _normalize_product(product)
        templates = PRODUCT_QUERIES.get(base_product)
        if not templates:
            continue

        for tmpl in templates:
            q = f'{tmpl} && status_code="200"'
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


def _normalize_product(product: str) -> str:
    p = product.lower().strip()
    if not p:
        return product
    for key in PRODUCT_QUERIES:
        key_tokens = re.findall(r"[a-z0-9]+", key.lower())
        product_tokens = re.findall(r"[a-z0-9]+", p)
        if key_tokens and all(token in product_tokens for token in key_tokens):
            return key
    if "litellm" in p:
        return "LiteLLM"
    if "flowise" in p:
        return "Flowise"
    if "dify" in p:
        return "Dify"
    if "librechat" in p:
        return "LibreChat"
    if "openwebui" in p or "open webui" in p:
        return "OpenWebUI"
    if "langflow" in p:
        return "Langflow"
    if "mlflow" in p:
        return "MLflow"
    if "portkey" in p:
        return "Portkey AI Gateway"
    if "langchain" in p:
        return "LangChain"
    if "praison" in p:
        return "PraisonAI"
    if "gitlab" in p:
        return "GitLab AI Gateway"
    if "new-api" in p or "newapi" in p:
        return "New-API"
    if "one-api" in p or "oneapi" in p:
        return "One-API"
    if "fastgpt" in p:
        return "FastGPT"
    if "anythingllm" in p:
        return "AnythingLLM"
    if "next-web" in p or "nextchat" in p:
        return "ChatGPT-Next-Web"
    if "openrouter" in p or "open router" in p:
        return "OpenRouter"
    if "vllm" in p:
        return "vLLM"
    if "ollama" in p:
        return "Ollama"
    if "localai" in p:
        return "LocalAI"
    if "text-generation" in p or "oobabooga" in p:
        return "Text-Generation-WebUI"
    if "lobe" in p:
        return "LobeChat"
    if "jan.ai" in p:
        return "Jan"
    if "wandb" in p or "weight & bias" in p:
        return "OpenWebUI"
    return product
