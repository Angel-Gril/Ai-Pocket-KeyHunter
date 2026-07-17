"""Source registry isolation and failure handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from aipocket.core.credentials import CredentialBundle
from aipocket.core.models import Credential
from aipocket.core.scan_policy import policy_from_mode
from aipocket.discovery.base import (
    ArtifactProvenance,
    CredentialSourceObservation,
    SourceBudgets,
    SourceFetchResult,
)
from aipocket.discovery.registry import SourceRegistry, merge_fetch_results


@dataclass
class _FakeHostSource:
    name: str = "fofa"
    hits: tuple = ()
    fail: bool = False
    configured: bool = True

    def is_configured(self) -> bool:
        return self.configured

    async def fetch(self, **kwargs: Any) -> SourceFetchResult:
        if self.fail:
            raise RuntimeError("boom")
        return SourceFetchResult(source=self.name, host_hits=self.hits)


@dataclass
class _FakeCredSource:
    name: str = "github"
    obs: tuple = ()
    configured: bool = True

    def is_configured(self) -> bool:
        return self.configured

    async def fetch(self, **kwargs: Any) -> SourceFetchResult:
        return SourceFetchResult(source=self.name, credential_observations=self.obs)


def _cred_obs() -> CredentialSourceObservation:
    bundle = CredentialBundle.create(
        "sk-canary-test-key-not-real-0001",
        endpoint_candidates=("https://open.bigmodel.cn/api/paas/v4",),
        provider_hint="glm",
    )
    cred = Credential(
        apikey=bundle.secret_value.reveal(),
        apiurl="https://open.bigmodel.cn/api/paas/v4",
        backend="github",
        source="github",
        bundle=bundle,
    )
    return CredentialSourceObservation(
        bundle=bundle,
        credential=cred,
        provenance=ArtifactProvenance(
            repository_id="1",
            repository_full_name="org/repo",
            commit_sha="abc",
            source_kind="blob",
        ),
        query_id="q1",
        pack_id="glm",
        lane="code_snapshot",
        coverage_mode="complete",
    )


@pytest.mark.asyncio
async def test_host_and_credential_lanes_do_not_cross_contaminate():
    host = _FakeHostSource(hits=({"host": "1.2.3.4", "port": "443"},))
    cred = _FakeCredSource(obs=(_cred_obs(),))
    reg = SourceRegistry({"fofa": host, "github": cred})
    results = await reg.fetch_all(
        [host, cred],
        budgets=SourceBudgets(),
        mode="incremental",
        policy=policy_from_mode("incremental"),
    )
    hosts, obs, sources, hits_by, *_ = merge_fetch_results(results)
    assert len(hosts) == 1
    assert hosts[0]["host"] == "1.2.3.4"
    assert len(obs) == 1
    assert obs[0].pack_id == "glm"
    assert "github" in sources
    assert hits_by["github"] == 1
    # Credential payload must never look like a host hit.
    assert not any("repository_full_name" in h for h in hosts)


@pytest.mark.asyncio
async def test_one_source_failure_does_not_cancel_other():
    bad = _FakeHostSource(name="fofa", fail=True)
    good = _FakeHostSource(name="shodan", hits=({"host": "9.9.9.9", "port": "80"},))
    reg = SourceRegistry({"fofa": bad, "shodan": good})
    results = await reg.fetch_all(
        [bad, good],
        budgets=SourceBudgets(),
        mode="incremental",
    )
    hosts, _, sources, *_ = merge_fetch_results(results)
    assert any(h.get("host") == "9.9.9.9" for h in hosts)
    assert "shodan" in sources
    assert any(r.errors for r in results if r.source == "fofa")


def test_resolve_skips_unconfigured_when_all():
    fofa = _FakeHostSource(configured=False)
    shodan = _FakeHostSource(name="shodan", configured=True)
    reg = SourceRegistry({"fofa": fofa, "shodan": shodan})
    resolved = reg.resolve(requested=None)
    names = {s.name for s in resolved}
    assert names == {"shodan"}
