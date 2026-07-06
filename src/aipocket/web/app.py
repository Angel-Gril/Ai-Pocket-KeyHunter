"""FastAPI application factory.

Assembles the aipocket web API: startup validation, error handlers, CORS, the
scan-manager singleton, all routers, and optional static hosting of the built
frontend. Entry point for ``aipocket serve`` and uvicorn.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..config import settings
from .errors import register_error_handlers
from .scan_manager import ScanManager

log = logging.getLogger(__name__)


def _validate_startup_config() -> None:
    """Refuse to start without the security-critical secrets configured."""
    missing = []
    if not settings.web_password:
        missing.append("WEB_PASSWORD")
    if not settings.web_jwt_secret:
        missing.append("WEB_JWT_SECRET")
    if missing:
        raise RuntimeError(
            "Cannot start web API — missing required config: "
            + ", ".join(missing)
            + ". Set them in .env."
        )


def create_app() -> FastAPI:
    _validate_startup_config()

    app = FastAPI(
        title="aipocket API",
        description="HTTP service layer over the aipocket scanner",
        version="0.1.0",
    )

    # Singleton scan manager shared across all requests.
    app.state.scan_manager = ScanManager()

    register_error_handlers(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.web_cors_origin_list,
        # Auth is a bearer token in the Authorization header, not cookies, so we
        # don't need credentialed CORS — and False keeps "*" origins valid.
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers.
    from .routers import (
        auth,
        cve,
        export,
        high_value,
        key,
        runs,
        scan,
        system,
    )
    from .routers import (
        settings as settings_router,
    )

    for module in (auth, runs, high_value, key, export, scan, cve, settings_router, system):
        app.include_router(module.router)

    @app.get("/api/health")
    async def health() -> dict:  # noqa: D401 — simple liveness probe (unauthenticated)
        return {"ok": True}

    _mount_static(app)
    return app


def _mount_static(app: FastAPI) -> None:
    """Serve the built React frontend if WEB_STATIC_DIR points at a real dir."""
    static_dir = settings.web_static_dir.strip()
    if not static_dir:
        return
    path = Path(static_dir)
    if not path.is_dir():
        log.warning("WEB_STATIC_DIR=%s does not exist — not mounting frontend", static_dir)
        return
    from fastapi.staticfiles import StaticFiles

    # html=True serves index.html for unknown paths (SPA client-side routing).
    app.mount("/", StaticFiles(directory=str(path), html=True), name="frontend")
    log.info("Serving frontend from %s", path)
