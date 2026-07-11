from __future__ import annotations

from aipocket.core.advisory import AdvisoryRecord
from aipocket.services.hunt_recipes import (
    active_recipes,
    products_with_active_coverage,
    recipe_from_advisory,
)


def _adv(
    *,
    advisory_id: str = "CVE-2024-1",
    product: str = "dify",
    profile: str = "readonly-fingerprint:dify",
    description: str = "auth bypass",
    relevance: str = "high",
) -> AdvisoryRecord:
    return AdvisoryRecord(
        advisory_id=advisory_id,
        product=product,
        safe_check_profile=profile,
        description=description,
        credential_relevance=relevance,  # type: ignore[arg-type]
        attack_surface="auth_bypass",
    )


def test_known_product_fingerprint_enables_active_recipe() -> None:
    recipe = recipe_from_advisory(_adv())
    assert recipe is not None
    assert recipe.active is True
    assert recipe.action == "fingerprint"
    assert "dify" in products_with_active_coverage([_adv()])


def test_reviewed_readonly_profile_enables_active_recipe_for_new_product() -> None:
    recipe = recipe_from_advisory(
        _adv(product="custom-ai-gateway", profile="readonly-product:custom-ai-gateway")
    )
    assert recipe is not None
    assert recipe.active is True
    assert recipe.action == "readonly_probe"


def test_rejects_command_execution_and_destructive_methods() -> None:
    for description in (
        "run shell command to dump keys",
        "DELETE FROM users; DROP TABLE keys",
        "credential spray password list",
        "fetch http://169.254.169.254/latest/meta-data",
        "payload template {{user_input}}",
    ):
        recipe = recipe_from_advisory(_adv(description=description))
        assert recipe is not None
        assert recipe.active is False
        assert recipe.reason == "forbidden-payload"


def test_unmapped_product_without_reviewed_check_stays_inactive() -> None:
    recipe = recipe_from_advisory(
        _adv(product="unknown-widget", profile="", description="minor UI bug")
    )
    assert recipe is not None
    assert recipe.active is False
    assert not active_recipes([_adv(product="unknown-widget", profile="")])
