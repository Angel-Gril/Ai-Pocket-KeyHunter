#!/bin/sh
set -e

DATA_DIR="/data/aipocket"

# Ensure data directories exist
mkdir -p "$DATA_DIR/results" "$DATA_DIR/sources"

# Copy .env.example as seed if no .env exists yet
if [ ! -f "$DATA_DIR/.env" ]; then
    if [ -f /app/.env.example ]; then
        cp /app/.env.example "$DATA_DIR/.env"
        echo "[init] Copied .env.example → $DATA_DIR/.env — edit it with your keys before the first real scan."
    fi
fi

# Symlink .env so pydantic-settings picks it up from the working directory
if [ -f "$DATA_DIR/.env" ]; then
    ln -sf "$DATA_DIR/.env" /app/.env
fi

exec "$@"
