"""One-shot: backfill leak_host/routed_to_official on existing valid_*.jsonl.

Historical valid_*.jsonl files were written BEFORE the routing-override
persistence fix in validator._probe. So for keys that were routed to an
official provider endpoint (sk-proj- → api.openai.com, sk-ant-api →
api.anthropic.com, …), the persisted apiurl/host still show the *leaking*
blog/banner host, not the endpoint the key was actually validated against.

This script replays the SAME routing logic (KEY_PREFIX_ROUTING + the
is-known-gateway check against DOMAIN_ROUTING fingerprints) onto each existing
record and, where an override applies:

  - apiurl/host → official endpoint
  - leak_host   ← original apiurl (preserves the leak source incl. port)
  - routed_to_official = True
  - ip/port cleared (they described the leak host, not the gateway)

It backs up the original file to <path>.bak before writing, then regenerates
preview/data.js via scripts/gen_balance_html.py.

Usage:
    python scripts/backfill_routing_fields.py [valid_*.jsonl]

If no path is given, the most recent results/run_*/valid_*.jsonl is used.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

# Must mirror src/aipocket/validator.py exactly.
KEY_PREFIX_ROUTING: list[tuple[str, str, str]] = [
    ("sk-proj", "https://api.openai.com/v1", "openai"),
    ("sk-admin", "https://api.openai.com/v1", "openai"),
    ("sk-svcacct", "https://api.openai.com/v1", "openai"),
    ("sk-ant-api", "https://api.anthropic.com/v1", "anthropic"),
    ("sk-ant-oat", "https://api.anthropic.com/v1", "anthropic"),
    ("sk-ant-sid", "https://api.anthropic.com/v1", "anthropic"),
    ("AIza", "https://generativelanguage.googleapis.com/v1beta", "google"),
]

DOMAIN_FINGERPRINTS: list[str] = [
    "openai.com", "oaiusercontent", "anthropic.com", "deepseek.com",
    "moonshot.cn", "bigmodel.cn", "zhipuai", "siliconflow.cn",
    "dashscope.aliyuncs.com", "baidu.com", "googleapis.com",
]


def _routing_override(apikey: str, apiurl: str) -> str | None:
    """Return the official URL if this key should be routed, else None.

    Mirrors validator._probe: route only when the key prefix matches AND the
    apiurl host is NOT itself a known provider gateway.
    """
    for prefix, official_url, _name in KEY_PREFIX_ROUTING:
        if apikey.startswith(prefix):
            host = (urlparse(apiurl).hostname or "").lower()
            is_known_gateway = any(fp in host for fp in DOMAIN_FINGERPRINTS)
            return None if is_known_gateway else official_url
    return None


def backfill_file(path: Path) -> tuple[int, int]:
    """Patch one valid_*.jsonl in place. Returns (total_records, routed_count)."""
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"  backup → {backup}")

    total = 0
    routed = 0
    out_lines: list[str] = []
    for line in path.read_text("utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        record = json.loads(stripped)
        if not isinstance(record, dict) or "credential" not in record:
            # Keep non-record lines (e.g. stray metadata) unchanged.
            out_lines.append(line)
            continue
        total += 1
        cred = record["credential"]
        apikey = cred.get("apikey", "")
        apiurl = cred.get("apiurl", "")

        official = _routing_override(apikey, apiurl)
        if official:
            routed += 1
            cred["leak_host"] = cred.get("leak_host") or apiurl or cred.get("host", "")
            cred["routed_to_official"] = True
            cred["apiurl"] = official
            parsed = urlparse(official)
            cred["host"] = parsed.hostname or cred.get("host", "")
            cred["ip"] = ""
            cred["port"] = str(parsed.port) if parsed.port else ""
        else:
            # Ensure the new fields exist with sane defaults for unrouted records.
            cred.setdefault("leak_host", "")
            cred.setdefault("routed_to_official", False)
        record.setdefault("suspicious", False)
        record.setdefault("suspicious_reason", "")
        out_lines.append(json.dumps(record, ensure_ascii=False))

    path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return total, routed


def main() -> None:
    results_dir = Path(__file__).resolve().parent.parent / "results"
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        candidates = sorted(
            results_dir.glob("run_*/valid_*.jsonl"),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        target = candidates[0] if candidates else None

    if not target or not target.exists():
        print("No valid_*.jsonl found.")
        sys.exit(1)

    print(f"Backfilling: {target}")
    total, routed = backfill_file(target)
    print(f"  records={total}, routed_to_official={routed}, unchanged={total - routed}")

    # Regenerate preview/data.js from the patched file.
    print("\nRegenerating preview/data.js …")
    import subprocess
    repo = Path(__file__).resolve().parent.parent
    subprocess.run(
        [sys.executable, str(repo / "scripts" / "gen_balance_html.py"), str(target)],
        check=True,
    )


if __name__ == "__main__":
    main()
