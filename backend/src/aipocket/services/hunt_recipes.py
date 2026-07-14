from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from aipocket.core.advisory import AdvisoryRecord

RecipeAction = Literal["fingerprint", "readonly_probe", "query_only"]

# Allowed enum values mirroring core.advisory Literals — used to sanitize legacy
# CVE dicts (which may carry absent or unexpected values) before rebuilding an
# AdvisoryRecord, so gating fails closed rather than raising on dirty data.
_ATTACK_SURFACES: Final[frozenset[str]] = frozenset(
    {
        "auth_bypass",
        "credential_exposure",
        "ssrf",
        "info_disclosure",
        "rce",
        "sqli",
        "privilege_escalation",
        "unknown",
    }
)
_CREDENTIAL_RELEVANCE: Final[frozenset[str]] = frozenset({"high", "medium", "low", "none"})
_SOURCE_CONFIDENCE: Final[frozenset[str]] = frozenset({"high", "medium", "low", "unconfirmed"})

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
        "chatgpt-next-web",
        "nextchat",
        "next-chat",
        "portkey",
        "portkey-ai-gateway",
        "openrouter",
        "open-router",
        "anythingllm",
        "anything-llm",
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


def advisory_from_cve_record(record: dict) -> AdvisoryRecord:
    """Rebuild an :class:`AdvisoryRecord` from a legacy CVE/advisory dict.

    ``load_cves()`` returns the legacy shape produced by
    ``AdvisoryRecord.to_legacy_cve_dict`` (unified sync) or older file entries
    that predate the advisory fields. Missing advisory fields fall back to
    conservative defaults so gating never over-expands coverage.
    """

    def _cvss() -> float:
        raw = record.get("cvss", 0.0)
        try:
            return float(raw)
        except (TypeError, ValueError):
            return 0.0

    def _one_of(value: object, allowed: frozenset[str], default: str) -> str:
        # Legacy file entries may carry unexpected/absent enum values; coerce to a
        # safe default so a dirty record never crashes gating (fails closed).
        return value if isinstance(value, str) and value in allowed else default

    return AdvisoryRecord(
        advisory_id=str(record.get("id") or record.get("advisory_id") or ""),
        product=str(record.get("product", "")),
        affected_versions=tuple(record.get("affected_versions", []) or ()),
        attack_surface=_one_of(record.get("attack_surface"), _ATTACK_SURFACES, "unknown"),
        credential_relevance=_one_of(
            record.get("credential_relevance"), _CREDENTIAL_RELEVANCE, "medium"
        ),
        safe_check_profile=str(record.get("safe_check_profile", "")),
        source_confidence=_one_of(record.get("source_confidence"), _SOURCE_CONFIDENCE, "medium"),
        description=str(record.get("description", "")),
        cvss=_cvss(),
        title=str(record.get("title", "")),
    )


def products_with_active_coverage_from_cves(records: list[dict]) -> frozenset[str]:
    """Active-coverage product fingerprints derived from legacy CVE dicts."""
    advisories = [advisory_from_cve_record(record) for record in records if record]
    return products_with_active_coverage(advisories)
