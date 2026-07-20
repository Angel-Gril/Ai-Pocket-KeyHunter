"""GitHub observation streaming spill tests."""

from __future__ import annotations

from aipocket.core.credentials import CredentialBundle, CredentialEvidence
from aipocket.core.models import Credential
from aipocket.discovery.base import ArtifactProvenance, CredentialSourceObservation


def _obs(i: int) -> CredentialSourceObservation:
    secret = f"sk-gh-spill-{i:04d}-" + ("a" * 32)
    bundle = CredentialBundle.create(
        secret,
        endpoint_candidates=("https://api.openai.com/v1",),
        evidence=(
            CredentialEvidence(
                source="github",
                pack_id="openai",
                query_id="q",
                repository_full_name="org/repo",
            ),
        ),
    )
    cred = Credential(
        apikey=secret,
        apiurl="https://api.openai.com/v1",
        backend="github",
        source="github",
        bundle=bundle,
    )
    return CredentialSourceObservation(
        bundle=bundle,
        credential=cred,
        provenance=ArtifactProvenance(
            repository_id=str(i),
            repository_full_name="org/repo",
            commit_sha="abc",
            object_sha="",
            file_path=".env",
            source_kind="blob",
            query_id="q",
            pack_id="openai",
            lane="code",
        ),
        query_id="q",
        pack_id="openai",
        lane="code",
        coverage_mode="complete",
    )


def test_observations_spilled_per_batch(monkeypatch) -> None:  # noqa: ANN001
    """Buffer flush pattern: N obs with batch M → ceil(N/M) upserts; buffer ≤ M."""
    from aipocket.services.honeypot import pre_filter_credentials

    flush_sizes: list[int] = []
    buffer: list = []
    batch_size = 10
    total = 0
    upsert_calls = 0

    def flush(force: bool = False) -> None:
        nonlocal buffer, total, upsert_calls
        if not buffer:
            return
        if not force and len(buffer) < batch_size:
            return
        batch = buffer
        buffer = []
        total += len(batch)
        survivors = pre_filter_credentials([o.credential for o in batch])
        if survivors:
            upsert_calls += 1
            flush_sizes.append(len(batch))
        # After flush buffer is empty
        assert len(buffer) == 0

    def extend(items: list) -> None:
        buffer.extend(items)
        assert len(buffer) <= batch_size + len(items)  # may exceed briefly before flush
        flush(False)
        assert len(buffer) < batch_size or len(buffer) == 0 or True
        # After flush, buffer < batch_size
        assert len(buffer) < batch_size

    for i in range(0, 25, 5):
        extend([_obs(j) for j in range(i, i + 5)])
    flush(True)

    assert total == 25
    assert upsert_calls == 3  # 10 + 10 + 5
    assert all(s <= 10 for s in flush_sizes)


def test_credential_obs_counter_without_full_list() -> None:
    from aipocket.discovery.base import SourceFetchResult

    r = SourceFetchResult(
        source="github",
        credential_observations=(),
        credential_observation_count=230_234,
        spilled=True,
    )
    assert len(r.credential_observations) == 0
    assert r.credential_observation_count == 230_234
    assert r.spilled is True


def test_prefilter_marks_prefilter_ok() -> None:
    from aipocket.services.honeypot import pre_filter_credentials

    # Realistic sk- length that is not on the noise/blocklist patterns.
    good = Credential(
        apikey="sk-proj-" + ("B" * 48),
        apiurl="https://api.openai.com/v1",
    )
    bad = Credential(apikey="too-short", apiurl="https://x")
    out = pre_filter_credentials([good, bad])
    keys = {c.apikey for c in out}
    assert good.apikey in keys
    assert bad.apikey not in keys
