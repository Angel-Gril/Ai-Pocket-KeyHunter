"""PostgreSQL connection pool + schema management.

PG is the persistent source of truth for scan results, high-value keys, and the
CVE list (Redis still handles cross-run dedup only). This module exposes a single
lazily-opened, thread-safe :class:`psycopg_pool.ConnectionPool` used from every
write/read path.

Why a synchronous pool: the write side (``high_value_writer.try_save``) runs
inside ``asyncio.gather`` tasks AND the FOFA/Shodan thread pool, while the read
side offloads blocking I/O via ``asyncio.to_thread``. ``ConnectionPool`` is
built for exactly this — multiple threads/tasks requesting connections from one
shared pool — so it fits both contexts without an async/thread split.

The pool is created on first use (``get_pool``) and reused process-wide. When no
``DATABASE_URL`` is configured, callers must not reach here: gate on
``settings.pg_enabled`` first.
"""

from __future__ import annotations

import logging
import threading
from contextvars import ContextVar
from importlib import resources
from typing import TYPE_CHECKING

from .config import settings

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool

log = logging.getLogger(__name__)

# The run_id of the scan currently in flight, propagated to deep write paths
# (high_value_writer.try_save) without threading it through every function
# signature. Set at the run_scan entry point; ContextVar propagates correctly
# into the asyncio.gather tasks that run per-credential validation. None when no
# scan is active (e.g. a standalone reveal/export call).
current_run_id: ContextVar[str | None] = ContextVar("current_run_id", default=None)

_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()
_schema_lock = threading.Lock()
_schema_ready = False


def get_pool() -> ConnectionPool:
    """Return the process-wide connection pool, opening it on first call.

    Raises RuntimeError if no DATABASE_URL is configured — callers should gate on
    ``settings.pg_enabled`` before reaching here.
    """
    global _pool
    if _pool is not None:
        return _pool

    with _pool_lock:
        if _pool is not None:  # another thread won the race
            return _pool
        if not settings.pg_enabled:
            raise RuntimeError("DATABASE_URL is not configured (settings.database_url is empty)")

        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        pool = ConnectionPool(
            conninfo=settings.database_url,
            min_size=settings.pg_pool_min,
            max_size=settings.pg_pool_max,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=False,
        )
        pool.open()
        log.info("PostgreSQL pool opened (min=%d max=%d)", settings.pg_pool_min, settings.pg_pool_max)
        _pool = pool
        return _pool


def _load_schema_sql() -> str:
    """Read the bundled schema.sql shipped alongside this package."""
    return resources.files("aipocket").joinpath("schema.sql").read_text(encoding="utf-8")


def ensure_schema() -> None:
    """Create all tables/indexes if missing. Idempotent; safe to call on startup.

    No-op when PG is disabled. Runs the whole schema.sql in one transaction.
    """
    global _schema_ready
    if not settings.pg_enabled:
        return

    # Acquire the pool BEFORE the schema lock — get_pool() takes _pool_lock, and
    # _schema_lock is a separate (non-reentrant) lock, so grabbing the pool first
    # avoids any lock-ordering surprise.
    pool = get_pool()
    with _schema_lock:
        if _schema_ready:
            return
        ddl = _load_schema_sql()
        with pool.connection() as conn:
            conn.execute(ddl)
            conn.commit()
        _schema_ready = True
    log.info("PostgreSQL schema ensured (runs/results/high_value_keys/cves)")


def close_pool() -> None:
    """Close the pool (for tests / graceful shutdown)."""
    global _pool, _schema_ready
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None
    with _schema_lock:
        _schema_ready = False
