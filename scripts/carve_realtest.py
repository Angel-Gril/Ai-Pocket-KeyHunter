"""Dynamically carve a small real-test CVE subset from the full CVE map.

The full map ``sources/cve_2026_ai.json`` is synced from Tavily and grows over
time. ``cve_realtest.json`` is a *static* hand-picked snapshot that does NOT
track those updates. This script regenerates it from the current full map so
the real-test coverage stays fresh — re-run it after ``aipocket cve-sync``.

Selection goal: cover **every prober product type** (the 10 classes in
``aipocket.prober.probers``), then fill by severity. Two passes:

1. **Coverage pass** — for each of the 10 probers, pick the highest-CVSS CVE
   whose ``product`` matches that prober's ``identify()`` keywords AND passes
   ``build_queries``'s priority filter (so it actually generates a query).
2. **Fill pass** — top up to ``--limit`` by (priority asc, CVSS desc) across
   all remaining carvable CVEs.

Usage::

    uv run python scripts/carve_realtest.py            # default: 10 → sources/cve_realtest.json
    uv run python scripts/carve_realtest.py --limit 20  # bigger subset
    uv run python scripts/carve_realtest.py --dry-run   # print, don't write
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Make `aipocket.*` importable when run as a standalone script via uv.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from aipocket.prober.runner import _all_probers  # noqa: E402
from aipocket.queries import (  # noqa: E402  — path patched above
    VULN_TYPE_PRIORITIES,
    _should_skip,
    load_cves,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("carve_realtest")


def _carvable(cve: dict) -> bool:
    """build_queries gate: priority<=3, not skipped. (template match is checked
    indirectly — a product no prober recognises is filtered out in carve().)"""
    if VULN_TYPE_PRIORITIES.get(cve.get("type", ""), 9) > 3:
        return False
    return not _should_skip(cve.get("product", ""))


def _prober_for_product(product: str) -> str | None:
    """Return the prober product_name that recognises this CVE product, else None.

    Uses each prober's own ``identify()`` against a synthetic hit built from the
    product name — the exact same matching the live prober runner performs.
    """
    hit = {"title": product, "header": "", "banner": ""}
    for cls in _all_probers():
        try:
            if cls.identify(hit):
                return cls.product_name
        except Exception:  # noqa: BLE001 — identify must never crash
            continue
    return None


def carve(cves: list[dict], limit: int = 10) -> list[dict]:
    """Pick up to ``limit`` CVEs: cover all prober types first, then fill by severity."""
    pool = [c for c in cves if _carvable(c)]
    # Pre-compute which prober (if any) each CVE maps to.
    tagged = [(_prober_for_product(c.get("product", "")), c) for c in pool]
    # Severity rank within the pool: priority asc, CVSS desc.
    tagged.sort(key=lambda tc: (VULN_TYPE_PRIORITIES.get(tc[1].get("type", ""), 9), -float(tc[1].get("cvss") or 0)))

    picked: list[dict] = []
    have_ids: set[str] = set()
    covered_probers: set[str] = set()

    # Pass 1: best (highest-severity) CVE per prober type → full product coverage.
    for prober, cve in tagged:
        if prober is None or prober in covered_probers:
            continue
        picked.append(cve)
        have_ids.add(cve["id"])
        covered_probers.add(prober)
        if len(picked) >= limit:
            break

    # Pass 2: fill remaining slots by severity across everything else carvable.
    if len(picked) < limit:
        for _, cve in tagged:
            if len(picked) >= limit:
                break
            if cve["id"] in have_ids:
                continue
            picked.append(cve)
            have_ids.add(cve["id"])

    return picked


def main() -> None:
    ap = argparse.ArgumentParser(description="Carve a small real-test CVE subset covering all prober types.")
    ap.add_argument("--input", type=Path, default=_REPO_ROOT / "sources" / "cve_2026_ai.json")
    ap.add_argument("--output", type=Path, default=_REPO_ROOT / "sources" / "cve_realtest.json")
    ap.add_argument("--limit", type=int, default=10, help="Max CVEs to carve (default: 10)")
    ap.add_argument("--dry-run", action="store_true", help="Print selection, don't write")
    args = ap.parse_args()

    cves = load_cves(args.input)
    log.info("Loaded %d CVEs from %s", len(cves), args.input)

    all_probers = {cls.product_name for cls in _all_probers()}
    picked = carve(cves, limit=args.limit)
    if not picked:
        log.error("No carvable CVEs found — check the source map or priority filters.")
        sys.exit(1)

    covered = {_prober_for_product(c.get("product", "")) for c in picked} - {None}
    missing = all_probers - covered
    log.info(
        "Carved %d CVEs covering %d/%d prober types%s",
        len(picked), len(covered), len(all_probers),
        f" (missing: {', '.join(sorted(missing))})" if missing else "",
    )

    print("\n  CVE ID            Product             Type           CVSS  Prober")
    print("  " + "-" * 72)
    for c in picked:
        prober = _prober_for_product(c.get("product", "")) or "-"
        print(f"  {c['id']:18} {c.get('product','')[:18]:18} {c.get('type','')[:12]:12} {str(c.get('cvss','')):5} {prober}")

    if missing:
        print(f"\n  ⚠️  {len(missing)} prober type(s) have NO matching CVE in the source map:")
        print("     " + ", ".join(sorted(missing)))
        print("     → these products won't be exercised by --realtest until added to the full map.")

    if args.dry_run:
        log.info("Dry-run: not writing.")
        return

    args.output.write_text(json.dumps(picked, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log.info("Wrote %d CVEs to %s", len(picked), args.output)


if __name__ == "__main__":
    main()
