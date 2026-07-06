"""FastAPI HTTP service layer for aipocket.

A thin web API that reuses the existing business modules (scanner, validator,
balance, writer, high_value_writer, clients, config) to serve a Vite + React
frontend. It runs alongside — not instead of — the CLI.

Entry point: :func:`aipocket.web.app.create_app`.
"""

from __future__ import annotations
