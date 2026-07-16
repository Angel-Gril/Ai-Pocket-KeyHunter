"""Register and list provider discovery packs."""

from __future__ import annotations

from aipocket.discovery.packs.base import ProviderDiscoveryPack

_PACKS: dict[str, ProviderDiscoveryPack] = {}


def register_pack(pack: ProviderDiscoveryPack) -> ProviderDiscoveryPack:
    """Register *pack* under ``pack.pack_id``. Overwrites on re-register."""
    if not pack.pack_id:
        raise ValueError("pack_id must be non-empty")
    _PACKS[pack.pack_id] = pack
    return pack


def get_pack(pack_id: str) -> ProviderDiscoveryPack:
    return _PACKS[pack_id]


def list_packs() -> tuple[ProviderDiscoveryPack, ...]:
    return tuple(_PACKS[k] for k in sorted(_PACKS))


def clear_packs() -> None:
    """Test helper — wipe the global registry."""
    _PACKS.clear()
