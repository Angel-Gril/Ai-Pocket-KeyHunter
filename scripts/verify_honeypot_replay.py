"""Replay a valid_*.jsonl through verify_no_auth to confirm no-auth honeypots.

Reads a valid results file, rebuilds ValidationResult objects, runs the
forged-key probe against each distinct host, and reports which hosts accept a
forged key (= no-auth honeypots that should be voided).

Usage:
    python scripts/verify_honeypot_replay.py results/run_XXX/valid_YYY.jsonl
"""
import asyncio, json, sys
from pathlib import Path
from aipocket.models import Credential, ValidationResult
from aipocket.validator import verify_no_auth


def load_results(path: str) -> list[ValidationResult]:
    results = []
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            c = r["credential"]
            cred = Credential(
                apikey=c["apikey"], apiurl=c.get("apiurl", ""),
                source=c.get("source", ""), source_type=c.get("source_type", "fingerprint"),
                host=c.get("host", ""), ip=c.get("ip", ""),
                backend=c.get("backend", ""), product=c.get("product", ""),
            )
            vr = ValidationResult(
                credential=cred, valid=r.get("valid", True),
                status_code=r.get("status_code"),
                model_available=r.get("model_available"),
            )
            results.append(vr)
    return results


async def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "results/run_2026_07_02_16-58-49/valid_20260702T171742Z.jsonl"
    results = load_results(path)
    hosts = {r.credential.host for r in results}
    print(f"Loaded {len(results)} valid result(s) across {len(hosts)} host(s).")
    print(f"Probing each with a forged key...\n")

    no_auth = await verify_no_auth(results)

    print(f"\n{'='*60}")
    if no_auth:
        print(f"❌ {len(no_auth)} host(s) confirmed NO-AUTH (accept forged key):")
        for h in no_auth:
            print(f"   {h}")
        print(f"\n→ The new logic would void all {len(results)} key(s) on these hosts.")
    else:
        print("✅ No no-auth hosts found — all keys appear to be on real gateways.")


if __name__ == "__main__":
    asyncio.run(main())
