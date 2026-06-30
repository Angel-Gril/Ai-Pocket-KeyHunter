from __future__ import annotations

import asyncio
import logging

import typer
from rich.console import Console
from rich.table import Table

from .config import settings

app = typer.Typer(help="aipocket — scan & validate leaked AI apikey/apiurl pairs via FOFA")
console = Console()
log = logging.getLogger("aipocket")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def scan(
    max_queries: int = typer.Option(0, "--max-queries", "-n", help="Limit number of FOFA queries (0=all)"),
    fast: bool = typer.Option(False, "--fast", help="Fast GPT mode: higher concurrency + bigger batches"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run a single scan and write JSON results to the results dir."""
    _setup_logging(verbose)
    if fast:
        settings.gpt_fast = True
        log.info("Fast mode enabled")
    from .scheduler import run_once

    n = max_queries or None
    result = asyncio.run(run_once(max_queries=n))
    _print_summary(result)


@app.command()
def watch(verbose: bool = typer.Option(False, "--verbose", "-v")):
    """Run scheduler in foreground (periodic execution)."""
    _setup_logging(verbose)
    from .scheduler import Scheduler

    if not settings.scheduler_enabled:
        console.print(
            "[yellow]SCHEDULER_ENABLED=false in .env. "
            "Set it to true to enable, or run `aipocket scan` for a one-off.[/yellow]"
        )
        raise typer.Exit(1)
    asyncio.run(Scheduler().run_forever())


@app.command()
def queries(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """List the FOFA queries that would be run (dry-run)."""
    _setup_logging(verbose)
    from .queries import build_queries

    qs = build_queries()
    table = Table(title=f"FOFA queries derived from CVE map ({len(qs)})")
    table.add_column("#", style="dim")
    table.add_column("CVE")
    table.add_column("Product")
    table.add_column("Type")
    table.add_column("Query")
    for i, q in enumerate(qs, 1):
        table.add_row(str(i), q["cve_id"], q["product"], q["type"], q["query"][:70])
    console.print(table)


@app.command()
def config():
    """Show current configuration (keys are masked)."""
    keys = settings.keys
    masked = ", ".join(f"{k[:6]}…{k[-4:]}" for k in keys) or "(none)"
    console.print(f"[bold]FOFA base URL:[/bold] {settings.fofa_base_url}")
    console.print(f"[bold]FOFA keys:[/bold] {masked} ({len(keys)} keys)")
    console.print(f"[bold]Page size / max pages:[/bold] {settings.fofa_page_size} / {settings.fofa_max_pages}")
    console.print(f"[bold]Validation concurrency:[/bold] {settings.validate_concurrency}")
    console.print(f"[bold]Scheduler:[/bold] enabled={settings.scheduler_enabled} interval={settings.scheduler_interval}s")
    console.print(f"[bold]Tavily:[/bold] {settings.tavily_base_url or '(disabled)'}")
    console.print(f"[bold]GPT analyzer:[/bold] {settings.gpt_base_url or '(disabled)'} model={settings.gpt_model}")
    console.print(f"[bold]Results dir:[/bold] {settings.results_path.resolve()}")


@app.command()
def cve_sync(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Sync AI CVEs from Tavily into sources/cve_2026_ai.json."""
    _setup_logging(verbose)
    if not settings.tavily_key:
        console.print("[red]TAVILY_KEY not configured. Set it in .env[/red]")
        raise typer.Exit(1)
    from .tavily_client import sync_cves

    merged, added = asyncio.run(sync_cves())
    console.print(f"[green]CVE sync done: {len(merged)} total, {added} new[/green]")


@app.command()
def balance(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Query balance/credits for all valid credentials in latest result."""
    _setup_logging(verbose)
    from .balance import query_latest_balances

    table = query_latest_balances()
    console.print(table)


def _print_summary(result):
    table = Table(title=f"Scan summary — {result.total_valid} valid / {result.total_credentials} creds")
    table.add_column("apikey")
    table.add_column("apiurl")
    table.add_column("tier")
    table.add_column("model")
    table.add_column("status")
    for r in result.results:
        if not r.valid:
            continue
        c = r.credential
        table.add_row(
            f"{c.apikey[:12]}…",
            c.apiurl[:50],
            r.tier or "-",
            r.model_available or "-",
            str(r.status_code),
        )
    console.print(table)


if __name__ == "__main__":
    app()
