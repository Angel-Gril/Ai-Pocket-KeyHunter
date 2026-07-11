"""Shodan filter hit-count probe (count endpoint — does NOT consume query credits).

Reads SHODAN_KEYS from .env, tests how many hosts each candidate filter
matches. Output feeds the decision of which filters to use in the scan query
builder. Prints a ranked table; nothing is written to disk.

Usage:
    python scripts/shodan_filter_probe.py
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

# Candidate filters grouped by intent.
# Goal: recall Dify *instances* (and other LLM gateway products), NOT to
# search for bare "sk-" keys (Shodan http.html is too shallow for that).
FILTERS: dict[str, list[str]] = {
    "dify_html (current strategy)": [
        'http.html:"dify"',
        'http.html:"dify" http.html:"api_key"',
    ],
    "dify_title_component (fingerprint)": [
        'http.title:"Dify"',
        'http.title:"dify"',
        'http.component:"dify"',
        'http.component:"Dify"',
    ],
    "dify_favicon_ssl (strongest fingerprint)": [
        # Dify favicon hashes are empirical — test a few known candidates.
        "http.favicon.hash:-890583488",
        "http.favicon.hash:2042235418",
        'ssl.cert.subject.cn:"dify"',
        'hostname:"dify"',
    ],
    "other_llm_gateways (broader recall)": [
        'http.title:"New API"',
        'http.title:"One API"',
        'http.component:"new-api"',
        'http.title:"LiteLLM"',
        'http.title:"LobeChat"',
        'http.title:"Open WebUI"',
        'http.title:"FastGPT"',
        'http.title:"Flowise"',
        'http.title:"Langflow"',
        'http.title:"LibreChat"',
    ],
}


def load_keys() -> list[str]:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        print(f"[!] .env not found at {env_path}", file=sys.stderr)
        sys.exit(1)
    for line in env_path.read_text().splitlines():
        if line.strip().startswith("SHODAN_KEYS="):
            raw = line.split("=", 1)[1].strip()
            return [k.strip() for k in raw.split(",") if k.strip()]
    print("[!] SHODAN_KEYS not found in .env", file=sys.stderr)
    sys.exit(1)


def count(key: str, query: str) -> int | str:
    """Return total count for a query (count endpoint, no credit cost)."""
    qs = urllib.parse.urlencode({"key": key, "query": query})
    url = f"https://api.shodan.io/shodan/host/count?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "aipocket-filter-probe"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return int(data.get("total", 0))
    except Exception as e:  # noqa: BLE001
        return f"ERR:{type(e).__name__}"


def main() -> None:
    keys = load_keys()
    if not keys:
        print("[!] no keys", file=sys.stderr)
        sys.exit(1)
    key = keys[0]
    print(f"Using first Shodan key ({key[:6]}…). count endpoint = no credit cost.\n")

    rows: list[tuple[str, str, int | str]] = []
    for group, queries in FILTERS.items():
        print(f"=== {group} ===")
        for q in queries:
            total = count(key, q)
            if isinstance(total, int):
                print(f"  {total:>10,}  {q}")
            else:
                print(f"  {total:>10}  {q}")
            rows.append((group, q, total))
            time.sleep(1.1)  # Shodan rate-limits ~1 req/sec
        print()

    # Ranked summary of integer hits, descending.
    print("=== RANKED (non-error, descending) ===")
    ranked = [r for r in rows if isinstance(r[2], int)]
    for group, q, total in sorted(ranked, key=lambda x: x[2], reverse=True):
        print(f"  {total:>10,}  [{group}]  {q}")


if __name__ == "__main__":
    main()
