from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from aipocket.core.config import settings

ADVISORY_LOCK_KEY = 0xA1_20260721


def parser(description: str, *, supports_run_id: bool = True) -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=description)
    result.add_argument("--database-url", default="")
    if supports_run_id:
        result.add_argument("--run-id", default="")
    result.add_argument("--limit", type=int, default=0)
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return result


def configure_database(url: str) -> None:
    if url:
        settings.database_url = url
    if not settings.pg_enabled:
        raise SystemExit("DATABASE_URL or --database-url is required")


@contextmanager
def locked_transaction(*, apply: bool):
    from aipocket.core.db import get_pool

    with get_pool().connection() as conn, conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (ADVISORY_LOCK_KEY,))
        yield conn


def main(
    description: str,
    run: Callable[[Any, argparse.Namespace], dict[str, Any]],
    *,
    supports_run_id: bool = True,
) -> int:
    args = parser(description, supports_run_id=supports_run_id).parse_args()
    configure_database(args.database_url)
    args.apply = bool(args.apply)
    args.dry_run = not args.apply
    with locked_transaction(apply=args.apply) as conn:
        summary = run(conn, args)
    print("mode=apply" if args.apply else "mode=dry-run")
    for key, value in summary.items():
        print(f"{key}={value}")
    return 0


def rows(conn: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def limit_clause(limit: int) -> str:
    return " LIMIT %s" if limit > 0 else ""
