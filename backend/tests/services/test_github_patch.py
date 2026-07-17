"""Tests for unified-diff patch parser."""

from __future__ import annotations

from pathlib import Path

from aipocket.services.github_patch import (
    join_side,
    line_span,
    parse_unified_patch,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "github"
CANARY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb"


def test_parse_ignores_file_and_hunk_headers():
    patch = (FIX / "patch_canary.diff").read_text()
    lines = parse_unified_patch(patch)
    texts = [ln.text for ln in lines]
    assert not any(t.startswith("---") for t in texts)
    assert not any(t.startswith("+++") for t in texts)
    assert not any(t.startswith("@@") for t in texts)
    assert any(CANARY in ln.text for ln in lines if ln.side == "added")


def test_sides_and_line_numbers():
    patch = """\
--- a/cfg.env
+++ b/cfg.env
@@ -10,3 +10,4 @@
 keep
-old_line
+new_line
 context2
"""
    lines = parse_unified_patch(patch)
    added = [ln for ln in lines if ln.side == "added"]
    removed = [ln for ln in lines if ln.side == "removed"]
    context = [ln for ln in lines if ln.side == "context"]
    assert len(added) == 1 and added[0].text == "new_line"
    assert added[0].new_lineno == 11
    assert added[0].old_lineno is None
    assert len(removed) == 1 and removed[0].text == "old_line"
    assert removed[0].old_lineno == 11
    assert any(ln.text == "keep" for ln in context)


def test_join_side_and_span():
    patch = (FIX / "patch_canary.diff").read_text()
    lines = parse_unified_patch(patch)
    added_text = join_side(lines, "added")
    assert CANARY in added_text
    assert "old_placeholder" not in added_text
    start, end = line_span(lines, "added")
    assert start is not None and end is not None
    assert start <= end


def test_empty_and_no_newline_marker():
    assert parse_unified_patch("") == []
    patch = "@@ -1 +1 @@\n+hello\n\\ No newline at end of file\n"
    lines = parse_unified_patch(patch)
    assert len(lines) == 1
    assert lines[0].side == "added"
    assert lines[0].text == "hello"


def test_headers_never_treated_as_content():
    patch = "--- a/x\n+++ b/x\n@@ -1,0 +1,1 @@\n+body\n"
    lines = parse_unified_patch(patch)
    assert len(lines) == 1
    assert lines[0].text == "body"
