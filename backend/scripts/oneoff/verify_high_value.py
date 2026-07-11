#!/usr/bin/env python3
"""验证高价值key + 探测余额。

读取 results/high_value_keys/keys.jsonl 中的所有key，重新验证状态并探测余额。
因为key可能过段时间复活，所以定期运行此脚本检查。

用法:
    uv run python scripts/verify_high_value.py
    uv run python scripts/verify_high_value.py --concurrency 10
    uv run python scripts/verify_high_value.py --output results/high_value_keys/report.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import httpx
from rich.console import Console
from rich.table import Table

from aipocket.core.models import Credential
from aipocket.services.balance import query_balance
from aipocket.services.high_value_writer import (
    _output_dir,
    _output_path,
    load_all,
)

log = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------


async def verify_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    entry: dict,
) -> dict:
    """Re-verify a single key: check if alive + probe balance."""
    apikey = entry["apikey"]
    apiurl = entry.get("apiurl", "")

    # Determine official URL based on prefix
    if apikey.startswith("sk-ant-"):
        official_url = "https://api.anthropic.com/v1"
        provider = "anthropic"
    elif apikey.startswith(("sk-proj-", "sk-admin-", "sk-svcacct-")):
        official_url = "https://api.openai.com/v1"
        provider = "openai"
    else:
        official_url = apiurl or "https://api.openai.com/v1"
        provider = "unknown"

    result = {
        "apikey": apikey,
        "apiurl": official_url,
        "provider": provider,
        "previous_status": entry.get("status_code"),
        "previous_valid": entry.get("valid"),
        "checked_at": datetime.now(UTC).isoformat(),
    }

    async with sem:
        # Step 1: Quick health check — send a minimal request
        status_code, error, is_alive = await _check_alive(client, apikey, official_url, provider)
        result["status_code"] = status_code
        result["error"] = error
        result["alive"] = is_alive

        # Step 2: If alive, probe balance
        if is_alive:
            cred = Credential(apikey=apikey, apiurl=official_url)
            try:
                balance_info = await query_balance(client, cred)
                result["gateway"] = balance_info.get("gateway", "")
                result["balance"] = balance_info.get("balance_usd", "")
                result["balance_raw"] = balance_info.get("raw", {})
            except Exception as e:
                result["gateway"] = ""
                result["balance"] = ""
                result["balance_error"] = str(e)

    return result


async def _check_alive(
    client: httpx.AsyncClient,
    apikey: str,
    base_url: str,
    provider: str,
) -> tuple[int | None, str, bool]:
    """Send a minimal API call to check if the key is alive.

    Returns (status_code, error_msg, is_alive).
    Alive = 200 or 429 (rate limited but not revoked).
    """
    try:
        if provider == "anthropic":
            # Anthropic uses /v1/messages with x-api-key
            url = f"{base_url}/messages"
            headers = {
                "x-api-key": apikey,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            payload = {
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}],
            }
            r = await client.post(url, headers=headers, json=payload)
        else:
            # OpenAI-compatible: /v1/chat/completions
            url = f"{base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {apikey}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1,
            }
            r = await client.post(url, headers=headers, json=payload)

        status = r.status_code
        # 200 = valid, 429 = rate limited (alive), 401/403 = dead
        is_alive = status in (200, 429)
        error = "" if is_alive else r.text[:200]
        return status, error, is_alive

    except httpx.TimeoutException:
        return None, "timeout", False
    except httpx.HTTPError as e:
        return None, str(e)[:200], False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def run(concurrency: int = 20, output_path: Path | None = None):
    entries = load_all()

    if not entries:
        console.print("[yellow]No high-value keys found in high_value_keys/keys.jsonl[/yellow]")
        console.print(f"[dim]Looked in: {_output_path()}[/dim]")
        return

    # Deduplicate by apikey (keep latest entry per key)
    by_key: dict[str, dict] = {}
    for e in entries:
        by_key[e["apikey"]] = e
    unique_entries = list(by_key.values())

    console.print(f"[bold]Verifying {len(unique_entries)} high-value keys[/bold]")
    console.print(
        f"  OpenAI (sk-proj-*): {sum(1 for e in unique_entries if e['apikey'].startswith('sk-proj-'))}"
    )
    console.print(
        f"  Claude (sk-ant-*):  {sum(1 for e in unique_entries if e['apikey'].startswith('sk-ant-'))}"
    )
    console.print()

    sem = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(20.0)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        tasks = [verify_one(client, sem, e) for e in unique_entries]
        results = await asyncio.gather(*tasks)

    # Categorize results
    alive_keys = [r for r in results if r["alive"]]
    dead_keys = [r for r in results if not r["alive"]]

    # Print summary table
    table = Table(title=f"高价值Key验证结果 ({datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')})")
    table.add_column("Key", max_width=20)
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Alive")
    table.add_column("Balance")
    table.add_column("Error", max_width=40)

    for r in results:
        key_display = r["apikey"][:16] + "…"
        status = str(r["status_code"] or "?")
        alive = "[green]✓[/green]" if r["alive"] else "[red]✗[/red]"
        balance = str(r.get("balance", "")) or "-"
        error = r.get("error", "")[:40]
        table.add_row(key_display, r["provider"], status, alive, balance, error)

    console.print(table)
    console.print()
    console.print(
        f"[green]Alive: {len(alive_keys)}[/green] / [red]Dead: {len(dead_keys)}[/red] / Total: {len(results)}"
    )

    # Write report as JSONL (first line = metadata, then one result per line)
    report_path = output_path or (_output_dir() / "verify_report.jsonl")
    with report_path.open("w", encoding="utf-8") as rf:
        meta = {
            "verified_at": datetime.now(UTC).isoformat(),
            "total": len(results),
            "alive": len(alive_keys),
            "dead": len(dead_keys),
        }
        rf.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
        for r in results:
            rf.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
    console.print(f"\n[dim]Report written: {report_path}[/dim]")

    # Also update the keys.jsonl with latest status for alive keys
    if alive_keys:
        _update_alive_keys(alive_keys)


def _update_alive_keys(alive_results: list[dict]):
    """Rewrite keys.jsonl keeping only alive keys with updated info."""
    # Read existing, update status for alive ones, keep all (alive or dead)
    # so we can track revival history.
    existing = load_all()
    by_key: dict[str, dict] = {}
    for e in existing:
        by_key[e["apikey"]] = e

    for r in alive_results:
        key = r["apikey"]
        if key in by_key:
            by_key[key]["status_code"] = r["status_code"]
            by_key[key]["valid"] = r["alive"]
            by_key[key]["balance"] = r.get("balance", "")
            by_key[key]["gateway"] = r.get("gateway", "")
            by_key[key]["last_verified"] = r["checked_at"]

    # Rewrite the file with updated entries
    path = _output_path()
    lines = [json.dumps(e, ensure_ascii=False, default=str) + "\n" for e in by_key.values()]
    path.write_text("".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="验证高价值key + 探测余额")
    parser.add_argument(
        "--concurrency",
        "-c",
        type=int,
        default=20,
        help="Concurrent verification tasks (default: 20)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output report path (default: results/high_value_keys/verify_report.jsonl)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    asyncio.run(run(concurrency=args.concurrency, output_path=args.output))


if __name__ == "__main__":
    main()
