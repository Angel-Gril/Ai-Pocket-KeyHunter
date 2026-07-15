from __future__ import annotations

from aipocket.core.models import Credential
from aipocket.core.observations import ExtractionMethod, ObservationRegistry


def test_get_finds_observation_after_official_endpoint_routing():
    """Validation rewrites apiurl/host but preserves leak_host — lookup must still hit."""
    registry = ObservationRegistry()
    cred = Credential(
        apikey="sk-proj-abc123def456ghi789jkl",
        apiurl="https://leaky.example.com/v1",
        host="leaky.example.com",
    )
    registry.observe(
        cred,
        ExtractionMethod.REGEX,
        (("fofa", 'body="sk-proj"'),),
    )

    # Simulate validator official-endpoint routing.
    cred.leak_host = "https://leaky.example.com/v1"
    cred.apiurl = "https://api.openai.com/v1"
    cred.host = "api.openai.com"
    cred.routed_to_official = True

    observation = registry.get(cred)
    assert observation is not None
    assert observation.primary_provenance == ("fofa", 'body="sk-proj"')


def test_get_returns_none_when_never_observed():
    registry = ObservationRegistry()
    cred = Credential(apikey="sk-orphan", apiurl="https://nowhere.example")
    assert registry.get(cred) is None


def test_get_falls_back_when_leak_host_has_trailing_slash_diff():
    registry = ObservationRegistry()
    cred = Credential(
        apikey="sk-proj-trailingslash",
        apiurl="https://leaky.example.com/v1/",
        host="leaky.example.com",
    )
    registry.observe(cred, ExtractionMethod.REGEX, (("shodan", "http.html:sk"),))
    # Identity normalizes trailing slash away at observe time.
    cred.leak_host = "https://leaky.example.com/v1/"
    cred.apiurl = "https://api.openai.com/v1"
    cred.host = "api.openai.com"
    assert registry.get(cred) is not None
