from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from aipocket.core.advisory import AdvisoryRecord

RecipeAction = Literal["fingerprint", "readonly_probe", "query_only"]

# Product fingerprints already covered by existing probers / product queries.
KNOWN_PRODUCT_FINGERPRINTS: Final[frozenset[str]] = frozenset(
    {
        "dify",
        "flowise",
        "librechat",
        "open-webui",
        "openwebui",
        "litellm",
        "new-api",
        "one-api",
        "langflow",
        "fastgpt",
        "lobe-chat",
        "lobechat",
        "mlflow",
    }
)

_FORBIDDEN_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\b(exec|system|shell|command)\b", re.I),
    re.compile(r"\b(DELETE|DROP|TRUNCATE|PUT|PATCH)\b"),
    re.compile(r"\b(spray|bruteforce|password.?list|credential.?stuff)\b", re.I),
    re.compile(r"\b(169\.254\.169\.254|metadata\.google|metadata\.azure)\b", re.I),
    re.compile(r"\{\{.*\}\}|\$\{.*\}|<script", re.I),
)


@dataclass(frozen=True, slots=True)
class HuntRecipe:
    recipe_id: str
    product: str
    action: RecipeAction
    safe_check_profile: str
    advisory_ids: tuple[str, ...]
    active: bool
    reason: str


def _is_forbidden_payload(text: str) -> bool:
    return any(pattern.search(text) for pattern in _FORBIDDEN_PATTERNS)


def recipe_from_advisory(advisory: AdvisoryRecord) -> HuntRecipe | None:
    """Map an advisory to a safe hunt recipe, or reject unsafe coverage changes.

    Active coverage only expands when the advisory maps to a known product
    fingerprint or a reviewed read-only safe-check profile. Never generates
    command execution, destructive methods, credential spraying, metadata SSRF,
    or arbitrary payload templates.
    """
    product = advisory.product.lower().replace("_", "-")
    profile = advisory.safe_check_profile or ""
    blob = f"{advisory.description} {profile} {advisory.title}"

    if _is_forbidden_payload(blob):
        return HuntRecipe(
            recipe_id=f"reject:{advisory.advisory_id}",
            product=product,
            action="query_only",
            safe_check_profile=profile,
            advisory_ids=(advisory.advisory_id,),
            active=False,
            reason="forbidden-payload",
        )

    known_product = product in KNOWN_PRODUCT_FINGERPRINTS
    reviewed_readonly = profile.startswith("readonly-")
    if not known_product and not reviewed_readonly:
        return HuntRecipe(
            recipe_id=f"defer:{advisory.advisory_id}",
            product=product,
            action="query_only",
            safe_check_profile=profile,
            advisory_ids=(advisory.advisory_id,),
            active=False,
            reason="no-known-fingerprint-or-reviewed-check",
        )

    if advisory.credential_relevance == "none":
        return HuntRecipe(
            recipe_id=f"query:{advisory.advisory_id}",
            product=product,
            action="query_only",
            safe_check_profile=profile,
            advisory_ids=(advisory.advisory_id,),
            active=False,
            reason="not-credential-relevant",
        )

    action: RecipeAction = "fingerprint" if known_product else "readonly_probe"
    return HuntRecipe(
        recipe_id=f"{action}:{product}:{advisory.advisory_id}",
        product=product,
        action=action,
        safe_check_profile=profile or f"readonly-product:{product}",
        advisory_ids=(advisory.advisory_id,),
        active=True,
        reason="mapped-safe-coverage",
    )


def active_recipes(advisories: list[AdvisoryRecord]) -> tuple[HuntRecipe, ...]:
    recipes = []
    for advisory in advisories:
        recipe = recipe_from_advisory(advisory)
        if recipe is not None and recipe.active:
            recipes.append(recipe)
    return tuple(recipes)


def products_with_active_coverage(advisories: list[AdvisoryRecord]) -> frozenset[str]:
    return frozenset(recipe.product for recipe in active_recipes(advisories))
