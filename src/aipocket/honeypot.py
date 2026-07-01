"""Post-validation honeypot / cluster detection.

After validation marks results as valid, this module detects patterns that
indicate the "valid" results are actually honeypot or botnet clusters:

1. **Cross-host key dedup** — same apikey appearing on N different hosts means
   the hosts share a single backend (or are coordinated fakes).
2. **Response fingerprint clustering** — many hosts returning the same canned
   response snippet, same balance, same model list → cluster.
3. **Key format rejection** — known non-LLM key formats (GOCSPX-*, pure hex
   session tokens) that somehow passed validation → likely honeypot accepted it.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict

from .models import ValidationResult

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. Key format blocklist — known non-LLM key prefixes/patterns.
# ---------------------------------------------------------------------------

# Keys matching these patterns are NOT valid LLM API keys regardless of what
# the remote endpoint says.
_KEY_BLOCKLIST: list[tuple[str, re.Pattern[str]]] = [
    # Google OAuth client secrets — never an LLM key
    ("google_oauth", re.compile(r"^GOCSPX-")),
    # Google OAuth client IDs
    ("google_client_id", re.compile(r"^\d+-[a-z0-9]+\.apps\.googleusercontent\.com$")),
    # AWS secret keys (40 alphanum, but starting patterns)
    ("aws_secret", re.compile(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$")),
]

# Pure hex of exactly 32 chars is very likely a session token / hash, not an
# LLM key. We flag these with lower severity (warning) but still reject.
_HEX32_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.I)

# Base64 of hex — decode to check
_BASE64_HEX_PATTERN = re.compile(
    r'^[A-Za-z0-9+/]{40,80}={0,2}$'
)


def _is_blocked_key_format(apikey: str) -> str | None:
    """Return reason string if key matches a known non-LLM format, else None."""
    for name, pat in _KEY_BLOCKLIST:
        if pat.match(apikey):
            return f"blocked-key-format:{name}"

    # Pure 32-char hex → likely session token
    if _HEX32_PATTERN.match(apikey):
        return "blocked-key-format:hex32-session-token"

    # Base64-encoded hex string detection
    if _BASE64_HEX_PATTERN.match(apikey):
        import base64
        try:
            decoded = base64.b64decode(apikey).decode("ascii", errors="ignore")
            if re.match(r'^"?[0-9a-f]{32,}"?$', decoded.strip()):
                return "blocked-key-format:base64-hex-token"
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# 2. Cross-host dedup — same key on N hosts → keep only first, reject rest.
# ---------------------------------------------------------------------------

_CLUSTER_THRESHOLD = 3  # Same key on >= 3 hosts → mark as cluster


def _dedup_cross_host(results: list[ValidationResult]) -> int:
    """Mark duplicates where the same apikey validates on many different hosts.

    Keeps the first occurrence (by index), rejects the rest.
    Returns count of rejected.
    """
    # Group valid results by apikey
    key_indices: dict[str, list[int]] = defaultdict(list)
    for i, r in enumerate(results):
        if r.valid:
            key_indices[r.credential.apikey].append(i)

    rejected = 0
    for _apikey, indices in key_indices.items():
        if len(indices) < 2:
            continue
        # Count distinct hosts for this key
        hosts = {results[i].credential.host for i in indices}
        if len(hosts) >= _CLUSTER_THRESHOLD:
            # Keep only the first, reject the rest
            for idx in indices[1:]:
                results[idx].valid = False
                results[idx].error = (
                    f"honeypot:cluster-key (same key on {len(hosts)} hosts)"
                )
                rejected += 1
        elif len(indices) > 1:
            # Same key on 2 hosts — dedup but softer label
            for idx in indices[1:]:
                results[idx].valid = False
                results[idx].error = "honeypot:duplicate-key-cross-host"
                rejected += 1

    return rejected


# ---------------------------------------------------------------------------
# 3. Response fingerprint clustering — detect many hosts with identical
#    responses, same balance, etc.
# ---------------------------------------------------------------------------

_FINGERPRINT_CLUSTER_THRESHOLD = 5


def _detect_response_clusters(results: list[ValidationResult]) -> int:
    """Flag results where many unrelated hosts share the same canned response.

    Honeypots return identical response_snippet + balance across all nodes.
    """
    # Build fingerprint: (response_snippet, balance)
    fingerprint_indices: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(results):
        if not r.valid:
            continue
        snippet = (r.response_snippet or "").strip()[:100]
        balance = r.balance or ""
        if snippet:  # Only cluster if there's a response to compare
            fp = (snippet, balance)
            fingerprint_indices[fp].append(i)

    rejected = 0
    for fp, indices in fingerprint_indices.items():
        if len(indices) < _FINGERPRINT_CLUSTER_THRESHOLD:
            continue
        # Check if these are actually distinct hosts (not same host, diff keys)
        hosts = {results[i].credential.host for i in indices}
        if len(hosts) < _FINGERPRINT_CLUSTER_THRESHOLD:
            continue
        # This is a cluster — reject all
        snippet_preview = fp[0][:40]
        for idx in indices:
            if results[idx].valid:  # May already be rejected by dedup
                results[idx].valid = False
                results[idx].error = (
                    f"honeypot:response-cluster ({len(hosts)} hosts, "
                    f"same response: {snippet_preview!r})"
                )
                rejected += 1

    return rejected


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def filter_honeypots(results: list[ValidationResult]) -> list[ValidationResult]:
    """Run all honeypot detection passes on validated results.

    Mutates results in-place (sets valid=False, error=reason).
    Returns the same list.
    """
    valid_before = sum(1 for r in results if r.valid)
    if valid_before == 0:
        return results

    # Pass 1: Response fingerprint clustering (runs first on the full valid set
    # so it sees all entries before format/dedup removes them)
    cluster_rejected = _detect_response_clusters(results)

    # Pass 2: Key format rejection
    format_rejected = 0
    for r in results:
        if not r.valid:
            continue
        reason = _is_blocked_key_format(r.credential.apikey)
        if reason:
            r.valid = False
            r.error = reason
            format_rejected += 1

    # Pass 3: Cross-host dedup
    dedup_rejected = _dedup_cross_host(results)

    valid_after = sum(1 for r in results if r.valid)
    total_rejected = valid_before - valid_after

    if total_rejected > 0:
        log.info(
            "Honeypot filter: %d/%d rejected "
            "(format=%d, cross-host-dedup=%d, response-cluster=%d) → %d valid remain",
            total_rejected, valid_before,
            format_rejected, dedup_rejected, cluster_rejected,
            valid_after,
        )
    else:
        log.info("Honeypot filter: 0 rejected, %d valid remain", valid_after)

    return results
