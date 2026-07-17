# AGENTS.md

Guidelines for AI agents (Claude Code, Copilot, Cursor, etc.) working on this codebase.

## Project Overview

**AIPocket** scans for exposed AI infrastructure via FOFA + Shodan (+ GitHub artifact source), extracts and validates leaked API key/URL pairs, checks balances, and flags high-value findings.

Monorepo layout:
- `backend/` — Python 3.11+, FastAPI + Typer CLI, `uv` package manager
- `frontend/` — React 19 + Vite + Tailwind v4 + shadcn/ui, `pnpm`
- Infra: PostgreSQL 16, Redis 7 (see `docker-compose.yml`)

## Before You Start

1. Read `CLAUDE.md` for architecture, commands, and conventions.
2. Read `.env.example` to understand configuration.
3. Never commit secrets or `.env` files.

## Backend Guidelines

- Source: `backend/src/aipocket/`
- Tests: `backend/tests/` (pytest + pytest-asyncio, auto mode)
- Validate: `cd backend && uv run pytest tests/ -x -q`
- Lint: `cd backend && uv run ruff check --fix . && uv run ruff format .`
- All HTTP I/O is async (`httpx.AsyncClient`). Do not use `requests`.
- Config uses `pydantic-settings`. Add new env vars to both `core/config.py` and `.env.example`.
- New probers go in `prober/probers/` and must be registered in `probers/__init__.py`.
- New API routes go in `api/routers/` and must be included in `api/app.py`.

## Frontend Guidelines

- Source: `frontend/src/`
- Build check: `cd frontend && pnpm build`
- Lint: `cd frontend && pnpm lint`
- UI components use shadcn/ui (`components/ui/`). Don't install alternative component libraries.
- Server state: `@tanstack/react-query`. Don't use Redux or other state managers.
- Routing: `react-router-dom` v6.
- API client: `lib/api.ts`. All backend calls go through this module.

## Common Tasks

| Task | Steps |
|------|-------|
| Add a new platform prober | Create `prober/probers/<name>.py` extending `BaseProber`, register in `__init__.py`, add tests |
| Add a new API endpoint | Create or extend a router in `api/routers/`, include in `api/app.py`, add schemas to `api/schemas.py` |
| Add a new frontend page | Create page in `pages/`, add route in `App.tsx`, add sidebar link in `components/sidebar.tsx` |
| Add a new env var | Add to `core/config.py` (Settings class), document in `.env.example` |

## Do Not

- Install new Python deps without adding them to `pyproject.toml`
- Use synchronous HTTP calls in backend code
- Store runtime state, credentials, or scan results in git-tracked files
- Modify `docker-compose.override.yml` for production changes (it's dev-only)
- Skip tests — always run `uv run pytest tests/ -x -q` after backend changes
