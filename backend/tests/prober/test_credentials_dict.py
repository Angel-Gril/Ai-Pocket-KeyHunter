"""Weak-password dictionary loading tests."""

from __future__ import annotations

from pathlib import Path

from aipocket.prober.credentials_dict import (
    BUILTIN_WEAK_CREDENTIALS,
    clear_dict_cache,
    default_dict_path,
    get_weak_credentials,
)


def setup_function() -> None:
    clear_dict_cache()


def teardown_function() -> None:
    clear_dict_cache()


def test_packaged_dict_exists_and_loads() -> None:
    path = default_dict_path()
    assert path.is_file(), f"missing packaged dict: {path}"
    pairs = get_weak_credentials(dict_path=str(path), usernames="admin", max_attempts=0)
    # Builtin seed + dict passwords under admin
    assert len(pairs) > len(BUILTIN_WEAK_CREDENTIALS)
    assert pairs[0] in BUILTIN_WEAK_CREDENTIALS
    # Passwords from file appear with admin
    assert any(u == "admin" and p == "123456" for u, p in pairs)


def test_usernames_expand_passwords(tmp_path: Path) -> None:
    d = tmp_path / "pw.txt"
    d.write_text("alpha\nbeta\n", encoding="utf-8")
    pairs = get_weak_credentials(
        dict_path=str(d), usernames="admin,root", max_attempts=0
    )
    passwords = {(u, p) for u, p in pairs}
    assert ("admin", "alpha") in passwords
    assert ("root", "beta") in passwords
    # admin outer-loop: all admin pairs appear before first non-builtin root-from-dict
    admin_idx = [i for i, (u, p) in enumerate(pairs) if u == "admin" and p == "beta"][0]
    root_idx = [i for i, (u, p) in enumerate(pairs) if u == "root" and p == "alpha"][0]
    assert admin_idx < root_idx


def test_max_attempts_caps(tmp_path: Path) -> None:
    d = tmp_path / "pw.txt"
    d.write_text("\n".join(f"p{i}" for i in range(100)), encoding="utf-8")
    pairs = get_weak_credentials(dict_path=str(d), usernames="admin", max_attempts=10)
    assert len(pairs) == 10
