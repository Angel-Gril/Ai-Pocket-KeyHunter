"""PR #2 review: PROBE_VULN_CLASSES must fail CLOSED; safe example defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from aipocket.prober.capability.policy import _ALL_CLASSES, _parse_vuln_classes
from aipocket.prober.capability.types import VulnClass


class TestVulnClassFailClosed:
    def test_star_enables_all(self) -> None:
        assert _parse_vuln_classes("*") == _ALL_CLASSES
        assert _parse_vuln_classes("all") == _ALL_CLASSES
        assert _parse_vuln_classes("") == _ALL_CLASSES

    def test_valid_subset(self) -> None:
        assert _parse_vuln_classes("unauth_read,idor") == frozenset(
            {VulnClass.UNAUTH_READ, VulnClass.IDOR}
        )

    def test_unknown_value_raises(self) -> None:
        """A misspelled class (rcee) must fail closed, not enable everything."""
        with pytest.raises(ValueError, match="unknown vuln class"):
            _parse_vuln_classes("rcee")

    def test_unknown_mixed_with_valid_raises(self) -> None:
        with pytest.raises(ValueError, match="rcee"):
            _parse_vuln_classes("rce,rcee")

    def test_never_falls_open_to_all_on_bad_input(self) -> None:
        with pytest.raises(ValueError):
            _parse_vuln_classes("nonsense,typo")


class TestExampleEnvSafeDefaults:
    """The shipped .env.example must not enable active (L1+) probing."""

    def _env(self) -> dict[str, str]:
        # tests/prober/ -> tests/ -> backend/ -> repo root
        root = Path(__file__).resolve().parents[3]
        example = root / ".env.example"
        assert example.exists(), f"missing {example}"
        out: dict[str, str] = {}
        for line in example.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip()
        return out

    def test_intrusive_checks_off(self) -> None:
        assert self._env().get("INTRUSIVE_CHECKS", "").lower() == "false"

    def test_max_risk_l0(self) -> None:
        assert self._env().get("PROBE_MAX_RISK") == "0"

    def test_l2_l3_switches_off(self) -> None:
        env = self._env()
        assert env.get("PROBE_SSRF_ENABLED", "").lower() == "false"
        assert env.get("PROBE_SQLI_ENABLED", "").lower() == "false"
        assert env.get("PROBE_RCE_ENABLED", "").lower() == "false"
