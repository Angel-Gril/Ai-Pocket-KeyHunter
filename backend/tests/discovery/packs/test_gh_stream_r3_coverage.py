"""Ensure commit-message anchors are a **superset** of GH Stream Hunter v10 R3.

Reference: ~/Downloads/gh_stream_v10_r3(1).py — only ``/search/commits`` with
unquoted multi-term AND queries + ``committer-date:``.

We may add more terms, but must not drop any reference term (case-insensitive).
"""

from __future__ import annotations

from datetime import UTC, datetime

import aipocket.discovery.packs  # noqa: F401 — register packs
from aipocket.discovery.packs import list_packs
from aipocket.services.github_queries import (
    GitHubPackView,
    build_commit_message_shards,
)

# Exact query *terms* from gh_stream_v10_r3 Q list, without DATE_FILTER.
# Case variants listed as in the script; coverage is checked casefold.
_R3_SINGLE_TERMS: tuple[str, ...] = (
    "deepseek_api_endpoint",
    "DEEPSEEK_API_ENDPOINT",
    "DEEPSEEK_BASE_URL",
    "deepseek_base_url",
    "openai_api_base",
    "OPENAI_API_BASE",
    "azure_openai_api_key",
    "AZURE_OPENAI_API_KEY",
    "cohere_api_key",
    "COHERE_API_KEY",
    "replicate_api_key",
    "REPLICATE_API_KEY",
    "together_api_key",
    "TOGETHER_API_KEY",
    "fireworks_api_key",
    "FIREWORKS_API_KEY",
    "anthropic_base_url",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_API_KEY",
    "claude_api_key",
    "moonshot_api_key",
    "MOONSHOT_API_KEY",
    "kimi_api_key",
    "KIMI_API_KEY",
    "minimax_api_key",
    "MINIMAX_API_KEY",
    "qwen_api_key",
    "QWEN_API_KEY",
)

_R3_MULTI_TERMS: tuple[str, ...] = (
    ".env deepseek_api_endpoint",
    ".env DEEPSEEK_BASE_URL",
    ".env openai_api_base",
    ".env azure_openai_api_key",
    ".env cohere_api_key",
    ".env replicate_api_key",
    ".env together_api_key",
    ".env fireworks_api_key",
    ".env anthropic_base_url",
    ".env CLAUDE_API_KEY",
    ".env moonshot_api_key",
    ".env kimi_api_key",
    ".env minimax_api_key",
    ".env qwen_api_key",
    "sk- cohere_api_key",
    "sk- replicate_api_key",
    "sk- fireworks_api_key",
    "sk- moonshot_api_key",
    "sk- kimi_api_key",
    "sk- qwen_api_key",
)


def _all_commit_anchors_casefold() -> set[str]:
    out: set[str] = set()
    for pack in list_packs():
        for anchor in pack.commit_message_anchors:
            out.add(anchor.casefold())
    return out


def test_r3_single_terms_covered() -> None:
    ours = _all_commit_anchors_casefold()
    missing = [t for t in _R3_SINGLE_TERMS if t.casefold() not in ours]
    assert missing == [], f"missing R3 single commit terms: {missing}"


def test_r3_multi_and_terms_covered() -> None:
    ours = _all_commit_anchors_casefold()
    missing = [t for t in _R3_MULTI_TERMS if t.casefold() not in ours]
    assert missing == [], f"missing R3 multi-term AND queries: {missing}"


def test_multi_term_anchors_emit_unquoted_and_not_phrase() -> None:
    """Reference uses AND of tokens; phrase quotes would miss the same commits."""
    pack = GitHubPackView(
        pack_id="probe",
        commit_message_anchors=(
            "sk- cohere_api_key",
            ".env DEEPSEEK_BASE_URL",
        ),
    )
    start = datetime(2025, 6, 1, tzinfo=UTC)
    end = datetime(2026, 7, 3, tzinfo=UTC)
    shards = build_commit_message_shards(pack, window_start=start, window_end=end)
    qs = [s.build_q() for s in shards]
    assert any(q.startswith("sk- cohere_api_key ") for q in qs), qs
    assert any(q.startswith(".env DEEPSEEK_BASE_URL ") for q in qs), qs
    for q in qs:
        # Must not be phrase-quoted.
        assert not q.startswith('"sk- cohere_api_key"')
        assert not q.startswith('".env DEEPSEEK_BASE_URL"')
        assert "committer-date:2025-06-01..2026-07-03" in q
        assert "is:public" in q


def test_r3_terms_survive_budget_slice() -> None:
    """Reference terms are ordered first so a modest budget still runs them."""
    # Budget 8 should still include all R3 multi terms for the packs that own them.
    for pack in list_packs():
        r3_for_pack = [
            a
            for a in pack.commit_message_anchors
            if a.casefold() in {t.casefold() for t in (*_R3_SINGLE_TERMS, *_R3_MULTI_TERMS)}
        ]
        if not r3_for_pack:
            continue
        # First N anchors after casefold collapse must retain every R3 term that
        # appears in this pack when budget >= len(unique R3 for pack).
        seen_norm: set[str] = set()
        ordered_unique: list[str] = []
        for raw in pack.commit_message_anchors:
            norm = raw.casefold()
            if norm in seen_norm:
                continue
            seen_norm.add(norm)
            ordered_unique.append(raw)

        r3_norms = {t.casefold() for t in (*_R3_SINGLE_TERMS, *_R3_MULTI_TERMS)}
        pack_r3 = [a for a in ordered_unique if a.casefold() in r3_norms]
        # All R3 terms for this pack must appear before non-R3 supersets, or at
        # least within the first 12 slots (default commit budget).
        positions = [ordered_unique.index(a) for a in pack_r3]
        assert positions, pack.pack_id
        assert max(positions) < 12, (
            f"{pack.pack_id}: R3 term pushed past default budget index 12: "
            f"{pack_r3[positions.index(max(positions))]!r}"
        )
