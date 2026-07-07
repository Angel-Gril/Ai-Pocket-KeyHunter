from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aipocket.core.config import settings

# Path to the trimmed CVE subset used by `scan --realtest`.
REALTEST_CVE_PATH = "sources/cve_realtest.json"

app = typer.Typer(help="aipocket — scan & validate leaked AI apikey/apiurl pairs via FOFA + Shodan")
console = Console()
log = logging.getLogger("aipocket")


def _setup_logging(verbose: bool, log_file: Path | None = None):
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(level)
    # Console handler (replace basicConfig's default so we control format).
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    # File handler — write every scan's log into its run folder.
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)


@app.command()
def scan(
    max_queries: int = typer.Option(0, "--max-queries", "-n", help="Limit number of queries per source (0=all)"),
    fast: bool = typer.Option(False, "--fast", help="Fast GPT mode: higher concurrency + bigger batches"),
    realtest: bool = typer.Option(
        False,
        "--realtest",
        help="Small-batch real test: use sources/cve_realtest.json (10 CVEs) and default -n 3, "
             "skipping generic DIRECT-CRED-LEAK queries so the prober gets product-fingerprint hits. "
             "Full end-to-end (fetch → probe → validate) with minimal quota cost.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run a single scan across all configured sources (FOFA + Shodan) and write JSONL results."""
    if fast:
        settings.gpt_fast = True

    skip_direct = False
    if realtest:
        # Override the CVE map before queries.py is imported (each `uv run` is a
        # fresh process, so setting os.environ here takes effect at import time).
        os.environ["AIPOCKET_CVE_PATH"] = REALTEST_CVE_PATH
        import importlib

        from aipocket.services import queries as _queries_mod

        importlib.reload(_queries_mod)
        _queries_mod.CVE_PATH = Path(REALTEST_CVE_PATH)
        # Skip generic DIRECT-CRED-LEAK queries so the first product-fingerprint
        # query (LobeChat/Dify/LiteLLM/…) is what gets scanned — that yields
        # gateway-shaped hits the prober can identify, instead of random sites
        # that merely leaked a key in their banner.
        skip_direct = True
        log.info("Realtest mode: CVE map = %s (%d CVEs), skipping DIRECT-CRED-LEAK queries",
                 _queries_mod.CVE_PATH, len(_queries_mod.load_cves()))
        settings.fofa_max_pages = 1
        settings.shodan_max_pages = 1
        log.info("Realtest mode: fofa_max_pages=1, shodan_max_pages=1")
        if not max_queries:
            max_queries = 3  # default: 3 product-fingerprint queries per source
            log.info("Realtest mode: defaulting to -n 3 (override with --max-queries)")

    # Create the run folder first so the log file lands inside it.
    from aipocket.services.scanner import run_scan
    from aipocket.services.writer import new_run_dir

    run_dir = new_run_dir()
    _setup_logging(verbose, log_file=run_dir / "run.log")
    if fast:
        log.info("Fast mode enabled")

    # Create PG tables if needed (no-op when DATABASE_URL is unset).
    from aipocket.core.db import ensure_schema

    ensure_schema()

    n = max_queries or None
    result = asyncio.run(run_scan(max_queries=n, run_dir=run_dir, skip_direct=skip_direct))
    _print_summary(result)
    log.info("Run folder: %s", run_dir)

    # Store the final run.log text on the PG runs row (no-op when PG disabled).
    if settings.pg_enabled:
        from aipocket.services.writer import update_run_log_pg

        log_file = run_dir / "run.log"
        if log_file.exists():
            update_run_log_pg(run_dir.name, log_file.read_text(encoding="utf-8"))

    # Refresh the preview dashboards so the web pages are current right after
    # each scan. Best-effort: a failure here must not mask a successful scan.
    _regenerate_preview(run_dir)


@app.command()
def watch(verbose: bool = typer.Option(False, "--verbose", "-v")):
    """Run scheduler in foreground (periodic execution)."""
    _setup_logging(verbose)
    from aipocket.scheduler import Scheduler

    if not settings.scheduler_enabled:
        console.print(
            "[yellow]SCHEDULER_ENABLED=false in .env. "
            "Set it to true to enable, or run `aipocket scan` for a one-off.[/yellow]"
        )
        raise typer.Exit(1)

    from aipocket.core.db import ensure_schema

    ensure_schema()
    asyncio.run(Scheduler().run_forever())


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change (dev only)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Run the FastAPI web API (serves the React frontend + JSON endpoints)."""
    _setup_logging(verbose)
    if not settings.web_password or not settings.web_jwt_secret:
        console.print(
            "[red]WEB_PASSWORD and WEB_JWT_SECRET must be set in .env before "
            "starting the web API.[/red]"
        )
        raise typer.Exit(1)

    import uvicorn

    console.print(f"[green]Starting aipocket API on http://{host}:{port} (docs at /docs)[/green]")
    uvicorn.run(
        "aipocket.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="debug" if verbose else "info",
    )


@app.command()
def queries(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """List the FOFA and Shodan queries that would be run (dry-run)."""
    _setup_logging(verbose)
    from aipocket.services.queries import build_queries
    from aipocket.services.shodan_queries import build_shodan_queries

    fofa_qs = build_queries()
    _print_query_table(fofa_qs, "FOFA queries derived from CVE map")

    shodan_qs = build_shodan_queries()
    _print_query_table(shodan_qs, "Shodan queries derived from CVE map")


def _print_query_table(qs: list[dict[str, str]], title: str):
    table = Table(title=f"{title} ({len(qs)})")
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
    console.print("[bold]== FOFA ==[/bold]")
    console.print(f"[bold]FOFA base URL:[/bold] {settings.fofa_base_url}")
    console.print(f"[bold]FOFA keys:[/bold] {masked} ({len(keys)} keys)")
    console.print(f"[bold]Page size / max pages:[/bold] {settings.fofa_page_size} / {settings.fofa_max_pages}")

    skeys = settings.shodan_key_list
    smasked = ", ".join(f"{k[:6]}…{k[-4:]}" for k in skeys) or "(none)"
    console.print("[bold]== Shodan ==[/bold]")
    console.print(f"[bold]Shodan base URL:[/bold] {settings.shodan_base_url}")
    console.print(f"[bold]Shodan keys:[/bold] {smasked} ({len(skeys)} keys)")
    console.print(f"[bold]Shodan max pages / page delay:[/bold] {settings.shodan_max_pages} / {settings.shodan_page_delay}s")

    console.print("[bold]== Common ==[/bold]")
    console.print(f"[bold]Validation concurrency:[/bold] {settings.validate_concurrency}")
    console.print(f"[bold]Scheduler:[/bold] enabled={settings.scheduler_enabled} interval={settings.scheduler_interval}s")
    console.print(f"[bold]Tavily:[/bold] {settings.tavily_base_url or '(disabled)'}")
    console.print(f"[bold]GPT analyzer:[/bold] {settings.gpt_base_url or '(disabled)'} model={settings.gpt_model}")
    console.print(f"[bold]Results dir:[/bold] {settings.results_path.resolve()}")


@app.command(name="shodan-info")
def shodan_info():
    """Check the Shodan API key status (plan & remaining query credits)."""
    _setup_logging(False)
    from aipocket.clients.shodan import ShodanClient

    if not settings.shodan_key_list:
        console.print("[red]SHODAN_KEYS not configured. Set it in .env[/red]")
        raise typer.Exit(1)
    with ShodanClient() as c:
        info = c.info()
    if not info:
        console.print("[red]Failed to reach Shodan API or all keys invalid.[/red]")
        raise typer.Exit(1)
    # info() aggregates across ALL keys (each key's quota is reported separately,
    # since accounts often mix a high-quota key with a low-quota one).
    console.print(f"[bold]Keys:[/bold] {info['n_keys']}  [bold]Dead:[/bold] {info['n_dead']}  "
                  f"[bold]Total query credits:[/bold] {info['total_query_credits']}")
    for k in info.get("keys", []):
        table = Table(title=f"Shodan API key {k.get('_key_masked', '?')}")
        table.add_column("field")
        table.add_column("value")
        for field in ("plan", "query_credits", "unlocked_left", "scan_credits", "monitored_ips", "https", "unlocked", "telnet"):
            if field in k:
                table.add_row(field, str(k[field]))
        console.print(table)


@app.command()
def cve_sync(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Sync AI CVEs from Tavily into sources/cve_2026_ai.json."""
    _setup_logging(verbose)
    if not settings.tavily_key:
        console.print("[red]TAVILY_KEY not configured. Set it in .env[/red]")
        raise typer.Exit(1)
    from aipocket.core.db import ensure_schema
    from aipocket.clients.tavily import sync_cves

    ensure_schema()
    merged, added = asyncio.run(sync_cves())
    console.print(f"[green]CVE sync done: {len(merged)} total, {added} new[/green]")


@app.command()
def balance(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Query balance/credits for all valid credentials in latest result."""
    _setup_logging(verbose)
    from aipocket.services.balance import query_latest_balances

    table = query_latest_balances()
    console.print(table)


def _regenerate_preview(run_dir: Path) -> None:
    """Regenerate preview/data.js and preview/highvalue.js after a scan.

    Loads the generator scripts from scripts/ (not a package, so dynamic import)
    and calls their ``gen()`` entry points. Best-effort: any failure is logged
    as a warning and never masks a successful scan.
    """
    import importlib.util

    # scripts/ lives at the project root; resolve it relative to this file.
    project_root = Path(__file__).resolve().parents[2]
    scripts_dir = project_root / "scripts"

    for module_name, script in (
        ("_gen_balance_html", scripts_dir / "gen_balance_html.py"),
        ("_gen_highvalue_html", scripts_dir / "gen_highvalue_html.py"),
    ):
        try:
            spec = importlib.util.spec_from_file_location(module_name, script)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.gen()  # type: ignore[attr-defined]
        except FileNotFoundError as e:
            # No input data yet (e.g. first run produced no valid_*.jsonl).
            log.info("Preview skip (%s): %s", script.name, e)
        except Exception as e:  # noqa: BLE001 - preview is non-critical
            log.warning("Preview generation failed for %s: %s", script.name, e)


def _print_summary(result):
    sources = ", ".join(result.sources) if result.sources else "?"
    by_src = " ".join(f"{k}={v}" for k, v in result.hits_by_source.items())
    console.print(f"[bold]Sources:[/bold] {sources}   [bold]Hits:[/bold] {by_src}")
    table = Table(title=f"Scan summary — {result.total_valid} valid / {result.total_credentials} creds")
    table.add_column("source")
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
            c.backend or "-",
            f"{c.apikey[:12]}…",
            c.apiurl[:50],
            r.tier or "-",
            r.model_available or "-",
            str(r.status_code),
        )
    console.print(table)


if __name__ == "__main__":
    app()
