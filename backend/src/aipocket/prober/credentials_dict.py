"""Weak-password dictionary loader.

Password lists live next to the prober package so they ship with the wheel.
Default file: ``prober/data/weak_passwords.txt`` (one password per line).

Override path / usernames / attempt cap via settings:

- ``WEAK_PASSWORD_DICT_PATH``
- ``WEAK_PASSWORD_USERNAMES`` (comma-separated; each password is tried under each user)
- ``WEAK_PASSWORD_MAX_ATTEMPTS`` (0 = use full expanded list, still budget-limited)
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

# Built-in high-ROI defaults always tried first (username, password).
BUILTIN_WEAK_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "123456"),
    ("admin", "admin@123"),
    ("admin", "Admin123!"),
)

_PACKAGE_DICT = Path(__file__).resolve().parent / "data" / "weak_passwords.txt"


def default_dict_path() -> Path:
    return _PACKAGE_DICT


@lru_cache(maxsize=4)
def _load_passwords_from_path(path_str: str) -> tuple[str, ...]:
    path = Path(path_str)
    if not path.is_file():
        log.warning("weak-password dict not found: %s", path)
        return ()
    seen: set[str] = set()
    out: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("failed to read weak-password dict %s: %s", path, exc)
        return ()
    for line in text.splitlines():
        pwd = line.strip()
        if not pwd or pwd.startswith("#") or pwd in seen:
            continue
        seen.add(pwd)
        out.append(pwd)
    log.info("Loaded %d weak passwords from %s", len(out), path)
    return tuple(out)


def clear_dict_cache() -> None:
    _load_passwords_from_path.cache_clear()
    get_weak_credentials.cache_clear()


def _resolve_dict_path() -> Path:
    from aipocket.core.config import settings

    raw = (settings.weak_password_dict_path or "").strip()
    if raw:
        return Path(raw).expanduser()
    return default_dict_path()


def _usernames() -> tuple[str, ...]:
    from aipocket.core.config import settings

    raw = (settings.weak_password_usernames or "admin,root").strip()
    users = tuple(u.strip() for u in raw.split(",") if u.strip())
    return users or ("admin",)


@lru_cache(maxsize=8)
def get_weak_credentials(
    *,
    dict_path: str = "",
    usernames: str = "",
    max_attempts: int = -1,
) -> tuple[tuple[str, str], ...]:
    """Return ordered (username, password) pairs for L1 weak-password probes.

    Order: builtin defaults first, then dict passwords × usernames
    (username outer loop so all passwords are tried under ``admin`` before
    moving to the next user).
    """
    from aipocket.core.config import settings

    path = Path(dict_path).expanduser() if dict_path else _resolve_dict_path()
    users_raw = usernames if usernames else (settings.weak_password_usernames or "admin,root")
    users = tuple(u.strip() for u in users_raw.split(",") if u.strip()) or ("admin",)
    if max_attempts < 0:
        max_attempts = int(getattr(settings, "weak_password_max_attempts", 0) or 0)

    passwords = _load_passwords_from_path(str(path.resolve()) if path.exists() else str(path))

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(user: str, password: str) -> None:
        key = (user, password)
        if key in seen:
            return
        seen.add(key)
        pairs.append(key)

    for user, password in BUILTIN_WEAK_CREDENTIALS:
        _add(user, password)

    for user in users:
        for password in passwords:
            _add(user, password)

    if max_attempts > 0:
        pairs = pairs[:max_attempts]

    return tuple(pairs)


# Back-compat name used by older imports/tests.
def load_weak_credentials() -> list[tuple[str, str]]:
    return list(get_weak_credentials())
