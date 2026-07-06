# --- Frontend build stage: compile the Vite + React app to static assets ---
FROM node:20-slim AS frontend

# pnpm is the frontend package manager; corepack ships with Node 20.
RUN corepack enable

WORKDIR /frontend

# Copy manifests first for dependency layer caching.
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy the rest of the frontend source and build -> /frontend/dist
COPY frontend/ ./
RUN pnpm build

# --- Python runtime stage ---
FROM python:3.11-slim AS base

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml ./
COPY uv.lock ./

# Install dependencies (no dev deps in production)
RUN uv sync --frozen --no-dev --no-install-project

# Copy source code and assets
COPY src/ src/
COPY sources/ sources/
COPY .env.example ./
COPY entrypoint.sh ./

# Install the project itself
RUN uv sync --frozen --no-dev

# Bring in the built frontend from the node stage and serve it statically.
COPY --from=frontend /frontend/dist ./frontend-dist

# Data volume mount point
VOLUME /data/aipocket

# Default environment
ENV RESULTS_DIR=/data/aipocket/results
ENV WEB_STATIC_DIR=/app/frontend-dist

ENTRYPOINT ["/app/entrypoint.sh", "uv", "run", "aipocket"]
# Serve the web UI + API by default; a bare `docker run` must NOT auto-scan.
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
