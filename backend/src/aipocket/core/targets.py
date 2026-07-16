from __future__ import annotations

import contextlib
import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    scheme: str
    hostname: str
    port: int

    @property
    def identity_hash(self) -> str:
        value = f"{self.scheme}://{self.hostname}:{self.port}"
        return hashlib.sha1(value.encode()).hexdigest()

    @property
    def url(self) -> str:
        hostname = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{hostname}{suffix}"


@dataclass(frozen=True, slots=True)
class DiscoveryTarget:
    identity: TargetIdentity
    sources: frozenset[str] = field(default_factory=frozenset)
    query_ids: frozenset[str] = field(default_factory=frozenset)
    provenance_pairs: tuple[tuple[str, str], ...] = ()
    advisory_ids: frozenset[str] = field(default_factory=frozenset)
    product_hints: frozenset[str] = field(default_factory=frozenset)
    aliases: frozenset[str] = field(default_factory=frozenset)
    content_evidence: tuple[str, ...] = ()
    hit: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def to_hit(self) -> dict[str, Any]:
        result = dict(self.hit)
        result["host"] = self.identity.url
        result["protocol"] = self.identity.scheme
        result["port"] = str(self.identity.port)
        result["_source"] = ",".join(sorted(self.sources))
        result["_query_ids"] = sorted(self.query_ids)
        result["_provenance_pairs"] = [list(pair) for pair in self.provenance_pairs]
        result["_cves"] = sorted(self.advisory_ids)
        result["_product_hints"] = sorted(self.product_hints)
        if self.product_hints:
            result["_product"] = sorted(self.product_hints)[0]
        return result


def _strings(hit: dict[str, Any], *keys: str) -> frozenset[str]:
    values: set[str] = set()
    for key in keys:
        value = hit.get(key)
        if isinstance(value, str) and value.strip():
            values.add(value.strip())
        elif isinstance(value, (list, tuple, set, frozenset)):
            values.update(str(item).strip() for item in value if str(item).strip())
    return frozenset(values)


def _strings_in_order(hit: dict[str, Any], *keys: str) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        value = hit.get(key)
        items = value if isinstance(value, (list, tuple)) else (value,)
        for item in items:
            text = str(item or "").strip()
            if text and text not in values:
                values.append(text)
    return tuple(values)


def _identity(hit: dict[str, Any]) -> TargetIdentity | None:
    raw = str(hit.get("host") or hit.get("link") or "").strip()
    if not raw:
        return None
    requested_scheme = str(hit.get("protocol") or "").lower()
    scheme = requested_scheme if requested_scheme in {"http", "https"} else "https"
    parsed = urlsplit(raw if "://" in raw else f"{scheme}://{raw}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        return None
    with contextlib.suppress(ValueError):
        hostname = ipaddress.ip_address(hostname).compressed
    parsed_scheme = parsed.scheme.lower()
    scheme = parsed_scheme if parsed_scheme in {"http", "https"} else scheme
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        raw_port = str(hit.get("port") or "").strip()
        port = int(raw_port) if raw_port.isdigit() else (443 if scheme == "https" else 80)
    return TargetIdentity(scheme, hostname, port)


def canonicalize_hits(hits: list[dict[str, Any]]) -> list[DiscoveryTarget]:
    merged: dict[TargetIdentity, DiscoveryTarget] = {}
    for hit in hits:
        identity = _identity(hit)
        if identity is None:
            continue
        content = tuple(
            value
            for key in ("header", "banner", "body", "cert", "title")
            if (value := str(hit.get(key) or "").strip())
        )
        current = DiscoveryTarget(
            identity=identity,
            sources=_strings(hit, "_source"),
            query_ids=_strings(hit, "_query_id", "_query_ids"),
            provenance_pairs=tuple(
                (source, query)
                for source in _strings_in_order(hit, "_source")
                for query in _strings_in_order(hit, "_query_id")
            ),
            advisory_ids=_strings(hit, "_cve", "_cves"),
            product_hints=frozenset(v.lower() for v in _strings(hit, "_product", "_product_hints")),
            aliases=_strings(hit, "host", "ip", "link"),
            content_evidence=content,
            hit=hit,
        )
        previous = merged.get(identity)
        if previous is None:
            merged[identity] = current
            continue
        merged[identity] = DiscoveryTarget(
            identity=identity,
            sources=previous.sources | current.sources,
            query_ids=previous.query_ids | current.query_ids,
            provenance_pairs=tuple(
                dict.fromkeys(previous.provenance_pairs + current.provenance_pairs)
            ),
            advisory_ids=previous.advisory_ids | current.advisory_ids,
            product_hints=previous.product_hints | current.product_hints,
            aliases=previous.aliases | current.aliases,
            content_evidence=tuple(
                dict.fromkeys(previous.content_evidence + current.content_evidence)
            ),
            hit={**current.hit, **previous.hit},
        )
    return list(merged.values())
