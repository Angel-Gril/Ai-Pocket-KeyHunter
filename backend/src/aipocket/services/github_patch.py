"""Unified-diff patch parser for GitHub commit file patches.

Ignores ``---`` / ``+++`` / ``@@`` headers; never treats them as content lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

PatchSide = Literal["added", "removed", "context"]

_HUNK_HEADER = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s@@")


@dataclass(frozen=True, slots=True)
class PatchHunkLine:
    side: PatchSide
    text: str
    new_lineno: int | None
    old_lineno: int | None


def parse_unified_patch(patch: str) -> list[PatchHunkLine]:
    """Parse a unified diff string into typed hunk lines.

    - File headers (``--- a/...``, ``+++ b/...``) are ignored.
    - Hunk headers (``@@ ... @@``) update line counters but produce no content.
    - ``+`` lines → added; ``-`` lines → removed; `` `` (space) → context.
    - ``\\ No newline at end of file`` is ignored.
    """
    if not patch:
        return []

    out: list[PatchHunkLine] = []
    old_ln: int | None = None
    new_ln: int | None = None

    for raw in patch.splitlines():
        # File headers / diff metadata — never content.
        if raw.startswith("---") or raw.startswith("+++"):
            continue
        if raw.startswith("diff ") or raw.startswith("index "):
            continue
        if raw.startswith("\\"):
            # "\ No newline at end of file"
            continue

        hunk = _HUNK_HEADER.match(raw)
        if hunk:
            old_ln = int(hunk.group(1))
            new_ln = int(hunk.group(3))
            continue

        if not raw:
            # Empty line without prefix — treat as blank context when in a hunk.
            if old_ln is None and new_ln is None:
                continue
            out.append(
                PatchHunkLine(
                    side="context",
                    text="",
                    new_lineno=new_ln,
                    old_lineno=old_ln,
                )
            )
            if old_ln is not None:
                old_ln += 1
            if new_ln is not None:
                new_ln += 1
            continue

        prefix = raw[0]
        text = raw[1:] if prefix in "+- " else raw

        if prefix == "+":
            out.append(
                PatchHunkLine(
                    side="added",
                    text=text,
                    new_lineno=new_ln,
                    old_lineno=None,
                )
            )
            if new_ln is not None:
                new_ln += 1
        elif prefix == "-":
            out.append(
                PatchHunkLine(
                    side="removed",
                    text=text,
                    new_lineno=None,
                    old_lineno=old_ln,
                )
            )
            if old_ln is not None:
                old_ln += 1
        elif prefix == " ":
            out.append(
                PatchHunkLine(
                    side="context",
                    text=text,
                    new_lineno=new_ln,
                    old_lineno=old_ln,
                )
            )
            if old_ln is not None:
                old_ln += 1
            if new_ln is not None:
                new_ln += 1
        # else: unknown prefix outside hunk — ignore

    return out


def join_side(lines: list[PatchHunkLine], side: PatchSide | tuple[PatchSide, ...]) -> str:
    """Join text of lines matching *side* (or any of a tuple of sides)."""
    wanted = {side} if isinstance(side, str) else set(side)
    return "\n".join(ln.text for ln in lines if ln.side in wanted)


def line_span(lines: list[PatchHunkLine], side: PatchSide) -> tuple[int | None, int | None]:
    """Return (min, max) new_lineno for *side* lines (or old for removed)."""
    nums: list[int] = []
    for ln in lines:
        if ln.side != side:
            continue
        n = ln.new_lineno if side != "removed" else ln.old_lineno
        if n is not None:
            nums.append(n)
    if not nums:
        return None, None
    return min(nums), max(nums)
