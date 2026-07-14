"""Product → ProbeSpec registry."""

from __future__ import annotations

from .spec import ProbeSpec

_SPECS: dict[str, list[ProbeSpec]] = {}


def register_specs(product: str, specs: list[ProbeSpec] | tuple[ProbeSpec, ...]) -> None:
    key = product.lower().replace("_", "-")
    _SPECS[key] = list(specs)


def specs_for(product: str) -> list[ProbeSpec]:
    key = product.lower().replace("_", "-")
    return list(_SPECS.get(key, ()))


def all_registered_products() -> frozenset[str]:
    return frozenset(_SPECS)
