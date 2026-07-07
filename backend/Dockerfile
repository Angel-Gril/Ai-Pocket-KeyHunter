# --- Python runtime stage ---
FROM python:3.11-slim

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
COPY scripts/ scripts/
COPY entrypoint.sh ./

# Install the project itself
RUN uv sync --frozen --no-dev

# Data volume mount point
VOLUME /data/aipocket

# Default environment
ENV RESULTS_DIR=/data/aipocket/results

ENTRYPOINT ["/app/entrypoint.sh", "uv", "run", "aipocket"]
# Serve the web API by default; a bare `docker run` must NOT auto-scan.
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
