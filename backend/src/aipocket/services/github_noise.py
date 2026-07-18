"""Shared GitHub artifact path noise filters.

Used by discovery (seed/work filtering) and artifact extract (commit file skip)
so catalog / example / docs blobs never burn validation quota.
"""

from __future__ import annotations

import re

# Directory / path segments that almost never hold live secrets.
_NOISE_DIR_MARKERS: tuple[str, ...] = (
    "/examples/",
    "/example/",
    "/samples/",
    "/sample/",
    "/fixtures/",
    "/fixture/",
    "/testdata/",
    "/test-data/",
    "/test_data/",
    "/mocks/",
    "/mock/",
    "/docs/",
    "/documentation/",
    "/changelog/",
)

# High-signal full-path noise (catalog dumps, plugin manifests).
_NOISE_PATH_SUBSTRINGS: tuple[str, ...] = (
    "provider-catalog",
    "official-external-provider",
    "openclaw.plugin.json",
    "catalog.json",
    "catalog.toml",
)

# Basename markers for dotted/hyphenated names (config.example.toml, foo-catalog.json).
# Underscore is NOT a boundary — so example_service.py is kept.
_NOISE_BASENAME_RE = re.compile(
    r"(^|[.\-])(example|sample|placeholder|catalog|fixture|demo|mock)([.\-]|$)",
    re.I,
)

_DOC_BASENAMES = re.compile(r"^(readme|changelog|license|contributing)(\.|$)", re.I)

# Real secret files that often still hold live keys despite "example" names.
_KEEP_ENV_BASENAMES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.staging",
    }
)


def is_noise_artifact_path(path: str) -> bool:
    """Return True for catalog / example / docs paths that pollute validation."""
    if not path:
        return False
    p = path.replace("\\", "/").lower().strip("/")
    # Normalize so leading segment matches /examples/ style markers.
    padded = f"/{p}/"
    basename = p.rsplit("/", 1)[-1]
    if basename in _KEEP_ENV_BASENAMES or basename.startswith(".env"):
        return False
    if any(marker in padded for marker in _NOISE_DIR_MARKERS):
        return True
    if any(marker in p for marker in _NOISE_PATH_SUBSTRINGS):
        return True
    if _DOC_BASENAMES.match(basename):
        return True
    if basename.endswith((".md", ".rst", ".markdown")):
        return True
    # config.example.toml / foo-catalog.json — but not "example_service.py"
    # (underscore is not a boundary in the regex).
    stem = basename.rsplit(".", 1)[0]
    return bool(_NOISE_BASENAME_RE.search(basename) or _NOISE_BASENAME_RE.search(stem))
