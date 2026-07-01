"""Canonical API-key regex patterns and noise filtering.

Shared by both ``extractor`` and ``prober.base`` so every pattern
is defined in exactly one place.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Key patterns — expanded to cover all platforms in FINGERPRINTS.md.
# Order matters: most specific prefix first (avoids sk- generic stealing
# deepseek/openai/siliconflow classification).
# Every regex uses a capture group so ``match.group(1)`` returns the key.
# ---------------------------------------------------------------------------
KEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openrouter", re.compile(r"\b(sk-or-v1-[a-f0-9\-]{30,})\b", re.I)),
    ("anthropic", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b")),
    ("openai_proj", re.compile(r"\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_\-]{20,})\b")),
    ("google", re.compile(r"\b(AIzaSy[A-Za-z0-9_\-]{35})\b")),
    ("groq", re.compile(r"\b(gsk_[A-Za-z0-9]{20,})\b")),
    ("perplexity", re.compile(r"\b(pplx-[A-Za-z0-9]{20,})\b")),
    ("replicate", re.compile(r"\b(r8_[A-Za-z0-9]{20,})\b")),
    ("huggingface", re.compile(r"\b(hf_[A-Za-z0-9]{20,})\b")),
    ("xai", re.compile(r"\b(xai-[A-Za-z0-9]{20,})\b")),
    ("runway", re.compile(r"\b(key_[A-Za-z0-9]{20,})\b")),
    ("glm", re.compile(r"\b([a-f0-9]{32}\.[A-Za-z0-9]{16})\b")),
    # sk- is a strong signal — accept short keys (self-hosted gateways
    # like New-API let admins set custom tokens of any length).
    ("sk_key", re.compile(r"\b(sk-[A-Za-z0-9_\-]{6,})\b")),
    ("glm_jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b")),
]

# ---------------------------------------------------------------------------
# Noise substrings — values containing any of these are false positives.
# Merged from extractor and prober; kept alphabetical.
# ---------------------------------------------------------------------------
NOISE_SUBSTRINGS: tuple[str, ...] = (
    "=>",
    "changeme",
    "data-cookie",
    "data-domain",
    "data-private",
    "data-public",
    "document.",
    "dummy",
    "example",
    "eyjhbgcioijiuzi1niisinr5cci6ikpxvcj9",
    "fake",
    "function(",
    "getelementbyid",
    "getelementbyname",
    "honeypot",
    "localstorage",
    "none",
    "null",
    "placeholder",
    "process.env",
    "replace_with",
    "sample",
    "sample_key",
    "schema",
    "sk-index",
    "sk-mocha",
    "skeleton",
    "skip",
    "test_key",
    "todo",
    "undefined",
    "window.",
    "xxx",
    "your-key",
    "your_api",
    "your_key",
    "yourkey",
)


def is_noise(val: str) -> bool:
    """Return ``True`` if *val* looks like a placeholder or false positive."""
    v = val.lower()
    if len(v) < 15:
        return True
    return any(sub in v for sub in NOISE_SUBSTRINGS)
