"""Re-probe balance for entries with no balance using the latest balance probes.

Re-probes any credential whose gateway is ``unsupported`` or empty (i.e. no
balance was resolved on the first pass), then rewrites the JSONL in place.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import httpx

from aipocket.core.models import Credential
from aipocket.services.balance import query_balance


async def main():
    valid_path = Path(sys.argv[1])
    if not valid_path.exists():
        print(f"File not found: {valid_path}")
        sys.exit(1)

    entries = [
        json.loads(line)
        for line in valid_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # Find entries with no resolved balance (unsupported or empty gateway / empty balance)
    def needs_reprobe(c: dict) -> bool:
        gw = c.get("gateway")
        if gw in (None, "", "unsupported"):
            return True
        return not c.get("balance")

    unsupported_indices = [i for i, c in enumerate(entries) if needs_reprobe(c)]
    print(f"Total credentials: {len(entries)}")
    print(f"To re-probe (no balance): {len(unsupported_indices)}")

    if not unsupported_indices:
        print("Nothing to do.")
        return

    # Re-probe
    sem = asyncio.Semaphore(20)
    updated = 0

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:

        async def probe_one(idx):
            nonlocal updated
            entry = entries[idx]
            cred_data = entry["credential"]
            cred = Credential(
                apikey=cred_data["apikey"],
                apiurl=cred_data.get("apiurl", ""),
            )
            async with sem:
                result = await query_balance(client, cred)

            if result.get("gateway") != "unsupported" and result.get("balance_usd") != "":
                entry["gateway"] = result["gateway"]
                entry["balance"] = str(result.get("balance_usd", ""))
                raw = result.get("raw", {})
                entry["rate_limit_headers"]["balance_detail"] = str(
                    {
                        "gateway": result["gateway"],
                        "balance_usd": result.get("balance_usd", ""),
                        "raw": raw
                        if not isinstance(raw, dict) or len(str(raw)) < 500
                        else "...(truncated)",
                    }
                )
                if entry.get("provider_info"):
                    entry["provider_info"]["balance_provider"] = result["gateway"]
                updated += 1

        tasks = [probe_one(i) for i in unsupported_indices]
        await asyncio.gather(*tasks)

    print(f"Updated: {updated} / {len(unsupported_indices)}")

    if updated > 0:
        # Rewrite as JSONL
        _UNSAFE = str.maketrans({"\u2028": " ", "\u2029": " "})
        output_lines = []
        for entry in entries:
            output_lines.append(
                json.dumps(entry, ensure_ascii=False, default=str).translate(_UNSAFE) + "\n"
            )
        valid_path.write_text("".join(output_lines), encoding="utf-8")
        print(f"Written to {valid_path}")
    else:
        print("No updates needed.")


if __name__ == "__main__":
    asyncio.run(main())
