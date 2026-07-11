from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from aipocket.core.targets import DiscoveryTarget

_KEY_SIGNAL: Final = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|token|secret)\s*[:=])", re.I
)
_CONFIG_SIGNAL: Final = re.compile(
    r"(?:\.env|config(?:uration)?|OPENAI_API_KEY|ANTHROPIC_API_KEY)", re.I
)
_DOCS_SIGNAL: Final = re.compile(r"\b(?:blog|docs?|documentation|developer portal)\b", re.I)
_SPA_SIGNAL: Final = re.compile(
    r"(?:id=[\"'](?:root|app)[\"']|/assets/(?:index|app)[^\"']*\.js)", re.I
)


@dataclass(frozen=True, slots=True)
class TargetEvidence:
    score: int
    reasons: tuple[str, ...]


def score_target(target: DiscoveryTarget) -> TargetEvidence:
    blob = "\n".join(target.content_evidence)
    score = 0
    reasons: list[str] = []
    if _KEY_SIGNAL.search(blob):
        score += 80
        reasons.append("credential pattern")
    if _CONFIG_SIGNAL.search(blob):
        score += 60
        reasons.append("configuration exposure")
    if target.product_hints:
        score += 70
        reasons.append("product fingerprint")
    if _DOCS_SIGNAL.search(blob):
        score -= 40
        reasons.append("documentation/blog penalty")
    if _SPA_SIGNAL.search(blob):
        score -= 25
        reasons.append("SPA fallback penalty")
    return TargetEvidence(score=score, reasons=tuple(reasons))
