# AIPocket

Scan for exposed AI infrastructure (FOFA + Shodan + GitHub artifact source), extract and validate leaked API key/URL pairs, check balances, and flag high-value findings.

## Architecture

Monorepo with two deployable services:

- **backend/** — Python 3.11+, FastAPI + Typer CLI, managed by `uv`. Source lives in `backend/src/aipocket/`.
- **frontend/** — React 19 + Vite + Tailwind v4 + shadcn/ui, managed by `pnpm`. Source lives in `frontend/src/`.

Infra: PostgreSQL 16 (persistent store), Redis 7 (cross-run dedup cache). Both defined in `docker-compose.yml`.

## Key Directories

```
backend/
  src/aipocket/
    api/           # FastAPI app, routers, schemas, scan manager
    clients/       # FOFA, Shodan, Tavily HTTP clients
    core/          # config, db, models, key_patterns
    prober/        # Platform-specific probers (Dify, LiteLLM, NewAPI, etc.)
    services/      # Business logic: scanner, validator, analyzer, dedup, balance, honeypot, writer
    cli.py         # Typer CLI entry point
    scheduler.py   # Periodic scan scheduler
  scripts/
    oneoff/        # Migration / backfill scripts
    reports/       # HTML report generators
  tests/           # pytest suite (mirrors src/ structure)
frontend/
  src/
    components/    # UI components + shadcn/ui primitives
    pages/         # Route pages (Login, Scan, History, HighValue, CVE, Settings, RunResults)
    lib/           # API client, auth, utils
    providers/     # Auth context provider
docs/              # FINGERPRINTS.md and other reference docs
```

## Development

```bash
# Backend
cd backend
uv sync                              # install deps
uv run aipocket --help               # CLI
uv run pytest tests/ -x -q           # tests

# Frontend
cd frontend
pnpm install
pnpm dev                             # Vite dev server on :5173
pnpm build && pnpm preview           # production build

# Docker (dev — auto-merges override for hot-reload)
docker compose up

# Docker (prod — skip override)
docker compose -f docker-compose.yml up -d
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `aipocket scan` | Run a full scan (FOFA + Shodan + optional GitHub + extract + validate + balance). Opt-in resume: `--resume-run run_YYYY_...` (requires PostgreSQL spill tables) |
| `aipocket serve` | Start FastAPI web API |
| `aipocket watch` | Periodic scanner (scheduler loop) |
| `aipocket queries` | Print current FOFA/Shodan query sets |
| `aipocket config` | Show resolved config |
| `aipocket shodan-info` | Show Shodan account info |
| `aipocket cve-sync` | Sync CVE data from Tavily |
| `aipocket balance` | Re-check balances for stored keys |

## Code Conventions

- Backend formatter/linter: `ruff`. Run `uv run ruff check --fix .` and `uv run ruff format .`.
- Frontend linter: `oxlint`. Run `pnpm lint`.
- Tests use `pytest` + `pytest-asyncio` (auto mode). HTTP mocking via `respx`, Redis via `fakeredis`.
- Pydantic v2 for config (`pydantic-settings`) and data models.
- All async I/O uses `httpx.AsyncClient`.
- Frontend uses `@tanstack/react-query` for server state, `react-router-dom` v6 for routing.

## Environment

All config via `.env` (see `.env.example`). Key variables:
- `FOFA_KEYS`, `SHODAN_KEYS` — comma-separated API key lists
- `DATABASE_URL` — PostgreSQL connection string
- `DEDUP_REDIS_URL` — Redis for dedup
- `GPT_BASE_URL`, `GPT_KEY`, `GPT_MODEL` — LLM for analysis
- `WEB_PASSWORD`, `WEB_JWT_SECRET` — web UI auth

## Rules

- Never commit `.env` or real API keys. Use `.env.example` for documentation.
- Prefer small, reviewable changes with clear verification steps.
- Run `uv run pytest tests/ -x -q` before submitting backend changes.
- Run `pnpm build` to verify frontend compiles before submitting.
