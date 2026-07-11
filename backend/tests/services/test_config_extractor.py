from __future__ import annotations

import base64
import hashlib

import pytest

from aipocket.services.config_extractor import extract_config_bundles

OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
SECOND_KEY = "sk-proj-zxy987wvu654tsr321qpo098nml765kji432hgf210edc"
AZURE_KEY = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    ("content", "format_hint", "endpoint"),
    [
        (
            f"OPENAI_API_KEY={OPENAI_KEY}\nOPENAI_BASE_URL=https://env.example/v1",
            ".env",
            "https://env.example/v1",
        ),
        (
            f'{{"openai": {{"api_key": "{OPENAI_KEY}", "base_url": "https://json.example/v1"}}}}',
            "json",
            "https://json.example/v1",
        ),
        (
            f"openai:\n  api_key: {OPENAI_KEY}\n  base_url: https://yaml.example/v1",
            "yaml",
            "https://yaml.example/v1",
        ),
        (
            f'[openai]\napi_key = "{OPENAI_KEY}"\nbase_url = "https://toml.example/v1"',
            "toml",
            "https://toml.example/v1",
        ),
        (
            f"services:\n  app:\n    environment:\n      OPENAI_API_KEY: {OPENAI_KEY}\n      OPENAI_BASE_URL: https://compose.example/v1",
            "docker-compose",
            "https://compose.example/v1",
        ),
    ],
)
def test_pairs_key_and_endpoint_within_structural_scope(
    content: str, format_hint: str, endpoint: str
) -> None:
    bundles = extract_config_bundles(content, format_hint=format_hint)

    assert len(bundles) == 1
    assert bundles[0].secret_value.reveal() == OPENAI_KEY
    assert bundles[0].endpoint_candidates == (endpoint,)
    assert bundles[0].secret_fingerprint == hashlib.sha256(OPENAI_KEY.encode()).hexdigest()


def test_pairs_env_variables_by_prefix_before_adjacency() -> None:
    content = "\n".join(
        (
            f"OPENAI_API_KEY={OPENAI_KEY}",
            "ANTHROPIC_BASE_URL=https://wrong.example/v1",
            "OPENAI_BASE_URL=https://right.example/v1",
        )
    )

    bundles = extract_config_bundles(content, format_hint="env")

    assert bundles[0].endpoint_candidates == ("https://right.example/v1",)


def test_pairs_unprefixed_variables_by_adjacency() -> None:
    content = f"API_KEY={OPENAI_KEY}\nBASE_URL=https://adjacent.example/v1\nAPI_KEY={SECOND_KEY}"

    bundles = extract_config_bundles(content, format_hint="env")

    assert bundles[0].endpoint_candidates == ("https://adjacent.example/v1",)


def test_uses_provider_default_when_no_endpoint_exists() -> None:
    bundles = extract_config_bundles(f"OPENAI_API_KEY={OPENAI_KEY}", format_hint="env")

    assert bundles[0].endpoint_candidates == ("https://api.openai.com/v1",)
    assert bundles[0].provider_hint == "openai"


def test_preserves_ambiguous_endpoint_candidates_in_source_order() -> None:
    content = (
        f"API_KEY={OPENAI_KEY}\nBASE_URL=https://one.example/v1\nAPI_URL=https://two.example/v1"
    )

    bundles = extract_config_bundles(content, format_hint="env")

    assert bundles[0].endpoint_candidates == (
        "https://one.example/v1",
        "https://two.example/v1",
    )
    assert bundles[0].confidence == "ambiguous"


def test_extracts_azure_context_variables() -> None:
    content = "\n".join(
        (
            "AZURE_OPENAI_API_KEY=azure-secret-value-1234567890",
            "AZURE_OPENAI_ENDPOINT=https://resource.openai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT=gpt-4o",
            "OPENAI_API_VERSION=2024-10-21",
        )
    )

    bundle = extract_config_bundles(content, format_hint="env")[0]

    assert bundle.provider_hint == "azure_openai"
    assert bundle.context.azure_resource == "resource"
    assert bundle.context.deployment == "gpt-4o"
    assert bundle.context.api_version == "2024-10-21"


def test_binds_opaque_azure_key_to_v1_endpoint_without_rewriting_path() -> None:
    content = "\n".join(
        (
            f"AZURE_OPENAI_API_KEY={AZURE_KEY}",
            "AZURE_OPENAI_ENDPOINT=https://resource.openai.azure.com/openai/v1",
        )
    )

    bundle = extract_config_bundles(content, format_hint="env")[0]

    assert bundle.secret_value.reveal() == AZURE_KEY
    assert bundle.endpoint_candidates == (
        "https://resource.openai.azure.com/openai/v1",
    )
    assert bundle.provider_hint == "azure_openai"
    assert bundle.context.azure_resource == "resource"


def test_binds_legacy_azure_deployment_and_version_variable_names() -> None:
    content = "\n".join(
        (
            f"AZURE_OPENAI_API_KEY={AZURE_KEY}",
            "AZURE_OPENAI_ENDPOINT=https://resource.openai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT_NAME=chat",
            "AZURE_OPENAI_API_VERSION=2024-10-21",
        )
    )

    bundle = extract_config_bundles(content, format_hint="env")[0]

    assert bundle.context.deployment == "chat"
    assert bundle.context.api_version == "2024-10-21"


def test_decodes_kubernetes_secret_locally() -> None:
    encoded_key = base64.b64encode(OPENAI_KEY.encode()).decode()
    encoded_url = base64.b64encode(b"https://k8s.example/v1").decode()
    content = f"""apiVersion: v1
kind: Secret
metadata:
  name: ai-config
data:
  OPENAI_API_KEY: {encoded_key}
  OPENAI_BASE_URL: {encoded_url}
"""

    bundle = extract_config_bundles(content, format_hint="kubernetes")[0]

    assert bundle.secret_value.reveal() == OPENAI_KEY
    assert bundle.endpoint_candidates == ("https://k8s.example/v1",)
    assert OPENAI_KEY not in bundle.model_dump_json()


def test_google_service_account_keeps_private_key_controlled() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\\nprivate-material\\n-----END PRIVATE KEY-----\\n"
    content = (
        '{"type":"service_account","project_id":"sample-project",'
        '"client_email":"svc@sample-project.iam.gserviceaccount.com",'
        f'"private_key":"{private_key}"}}'
    )

    bundle = extract_config_bundles(content, format_hint="json")[0]

    assert bundle.credential_kind == "google_service_account"
    assert bundle.provider_hint == "vertex"
    assert bundle.context.project == "sample-project"
    assert bundle.context.service_account_email == "svc@sample-project.iam.gserviceaccount.com"
    assert bundle.endpoint_candidates == ("https://aiplatform.googleapis.com",)
    assert "private-material" not in bundle.model_dump_json()
