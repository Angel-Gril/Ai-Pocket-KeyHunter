from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AttackSurface = Literal[
    "auth_bypass",
    "credential_exposure",
    "ssrf",
    "info_disclosure",
    "rce",
    "sqli",
    "privilege_escalation",
    "unknown",
]
CredentialRelevance = Literal["high", "medium", "low", "none"]
SourceConfidence = Literal["high", "medium", "low", "unconfirmed"]


class AdvisoryRecord(BaseModel):
    """Unified AI infrastructure advisory — CVE, GHSA, vendor, or public disclosure."""

    model_config = ConfigDict(frozen=True)

    advisory_id: str
    product: str
    affected_versions: tuple[str, ...] = ()
    attack_surface: AttackSurface = "unknown"
    credential_relevance: CredentialRelevance = "medium"
    safe_check_profile: str = ""
    source_confidence: SourceConfidence = "medium"
    published_at: str = ""
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    sources: tuple[str, ...] = ()
    description: str = ""
    cvss: float = 0.0
    title: str = ""

    def to_legacy_cve_dict(self) -> dict:
        """Compatibility shape for existing query builders and the /api/cve UI."""
        type_map = {
            "auth_bypass": "认证绕过",
            "credential_exposure": "API key泄露",
            "ssrf": "SSRF",
            "info_disclosure": "信息泄露",
            "rce": "RCE",
            "sqli": "SQL注入",
            "privilege_escalation": "权限提升",
            "unknown": "信息泄露",
        }
        huntable = (
            "高"
            if self.credential_relevance == "high"
            or self.attack_surface in {"auth_bypass", "credential_exposure", "ssrf"}
            or self.cvss >= 8.0
            else "中"
            if self.credential_relevance != "none"
            else "低"
        )
        return {
            "id": self.advisory_id,
            "cvss": self.cvss,
            "product": self.product,
            "type": type_map.get(self.attack_surface, "信息泄露"),
            "description": self.description or self.title,
            "huntable": huntable,
            "date": (self.published_at or self.updated_at)[:10],
            "source_url": self.sources[0] if self.sources else "",
            "affected_versions": list(self.affected_versions),
            "attack_surface": self.attack_surface,
            "credential_relevance": self.credential_relevance,
            "safe_check_profile": self.safe_check_profile,
            "source_confidence": self.source_confidence,
            "updated_at": self.updated_at,
            "sources": list(self.sources),
        }
