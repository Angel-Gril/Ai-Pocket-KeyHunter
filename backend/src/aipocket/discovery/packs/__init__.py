"""Provider discovery packs — declarative hunt metadata only."""

from __future__ import annotations

# Side-effect imports register each pack into the global registry.
from aipocket.discovery.packs import (  # noqa: F401
    cohere,
    fireworks,
    glm,
    kimi,
    qwen,
    replicate,
    together,
)
from aipocket.discovery.packs.base import ProviderDiscoveryPack
from aipocket.discovery.packs.registry import get_pack, list_packs, register_pack

__all__ = [
    "ProviderDiscoveryPack",
    "get_pack",
    "list_packs",
    "register_pack",
]
