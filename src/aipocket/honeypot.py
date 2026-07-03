"""Post-validation honeypot / cluster detection.

After validation marks results as valid, this module detects patterns that
indicate the "valid" results are actually honeypot or botnet clusters:

1. **Cross-host key dedup** — same apikey appearing on N different hosts means
   the hosts share a single backend (or are coordinated fakes).
2. **Response fingerprint clustering** — many hosts returning the same canned
   response snippet, same balance, same model list → cluster.
3. **Key format rejection** — known non-LLM key formats (GOCSPX-*, pure hex
   session tokens) that somehow passed validation → likely honeypot accepted it.
4. **Zero-width steganography** — responses embedding invisible Unicode chars
   (U+200B/200C/200D) for per-request fingerprinting / tracking.
5. **Prompt injection in responses** — responses containing hidden system notes,
   HTML comments with instructions, or verification URLs designed to exfiltrate
   tokens from downstream AI agents.
6. **No-auth host rejection** — hosts confirmed to accept a FORGED key. A real
   gateway rejects every key but its own (even if several real keys leaked on
   one host); a no-auth endpoint accepts any string. The validator sends a
   random bogus key to each host with a valid result; if it also succeeds, the
   host is flagged and every "valid" key on it is rejected. This is NOT keyed
   on "multiple keys per host" — that would false-positive on legitimate
   gateways that leaked several real keys.
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

# Pure hex of 32-128 chars is very likely a session token / hash / opaque
# .env secret, not an LLM API key. We flag these with lower severity (warning)
# but still reject. Range covers 32-char hashes up through 64-byte (128-hex)
# session tokens seen leaked in .env files. Real vendor keys (sk-…, AIza…) have
# non-hex structure (prefix, dashes, base64 alphabet) and are matched by their
# own prefix path, so they never reach this check.
_HEX_TOKEN_PATTERN = re.compile(r"^[0-9a-fA-F]{32,128}$")

# Base64 of hex — decode to check
_BASE64_HEX_PATTERN = re.compile(
    r'^[A-Za-z0-9+/]{40,80}={0,2}$'
)


def _is_blocked_key_format(apikey: str) -> str | None:
    """Return reason string if key matches a known non-LLM format, else None."""
    for name, pat in _KEY_BLOCKLIST:
        if pat.match(apikey):
            return f"blocked-key-format:{name}"

    # Vendor-prefixed keys have real structure (sk-…, AIza…) and are validated
    # by their own routing/probing path — never let the bare-hex filter touch them.
    if not apikey.startswith(("sk-", "AIza")):
        # Pure 32-128 hex → likely session token / opaque .env secret.
        if _HEX_TOKEN_PATTERN.match(apikey):
            return "blocked-key-format:hex-token-32-128"

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


def pre_filter_credentials(creds: list) -> list:
    """Lightweight pre-validation filter — reject obviously invalid credentials.

    Runs the key-format blocklist and cross-host dedup on raw Credential objects
    BEFORE expensive HTTP validation. This catches:
    - Non-LLM key formats (Google OAuth, AWS, hex32 tokens)
    - Keys shorter than 15 chars
    - Known noise patterns
    - Same key appearing with > N different apiurls (broadcast honeypot)

    Returns filtered list (valid credentials only).
    """
    from .key_patterns import is_noise

    valid: list = []
    key_urls: dict[str, set[str]] = {}  # apikey → set of apiurls

    # First pass: count key occurrences across different URLs
    for cred in creds:
        k = cred.apikey
        url = cred.apiurl
        if k not in key_urls:
            key_urls[k] = set()
        key_urls[k].add(url)

    rejected_format = 0
    rejected_noise = 0
    rejected_dedup = 0

    for cred in creds:
        k = cred.apikey

        # 1. Format blocklist
        reason = _is_blocked_key_format(k)
        if reason:
            rejected_format += 1
            continue

        # 2. Noise check
        if is_noise(k):
            rejected_noise += 1
            continue

        # 3. Same key on too many different URLs → likely honeypot/broadcast
        if len(key_urls.get(k, set())) > 5:
            rejected_dedup += 1
            continue

        valid.append(cred)

    total_rejected = rejected_format + rejected_noise + rejected_dedup
    if total_rejected > 0:
        log.info(
            "Pre-filter rejected %d credentials (format=%d, noise=%d, broadcast=%d)",
            total_rejected, rejected_format, rejected_noise, rejected_dedup,
        )

    return valid

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
# 2b. No-auth host rejection — hosts confirmed (by validator's fake-key probe)
#     to accept ANY token. See validator.verify_no_auth: it sends a random
#     bogus key to each host that has a valid result; if the bogus key also
#     returns a valid completion, the endpoint ignores Authorization and every
#     "valid" key on it is worthless. This pass just applies that verdict.
#
#     NOTE: we deliberately do NOT use "multiple distinct keys on one host" as
#     the signal here — a legitimate gateway can leak several real keys at once
#     (multiple users / projects sharing one .env). Only a FORGED key succeeding
#     proves no-auth.
# ---------------------------------------------------------------------------

# Hosts (apiurl) flagged as no-auth by verify_no_auth. Populated by the scanner
# between validate_all and filter_honeypots. Module-level so the scanner can set
# it without threading it through every call.
no_auth_hosts: set[str] = set()


def _reject_no_auth_hosts(results: list[ValidationResult]) -> int:
    """Reject all valid results on hosts confirmed to accept forged keys.

    ``no_auth_hosts`` holds HOST values (matched against ``credential.host``),
    as returned by :func:`validator.verify_no_auth`.
    """
    if not no_auth_hosts:
        return 0
    rejected = 0
    for r in results:
        if not r.valid:
            continue
        if r.credential.host in no_auth_hosts:
            r.valid = False
            r.error = (
                "honeypot:no-auth-host (forged key also validated — endpoint "
                "ignores Authorization, all keys here are fake)"
            )
            rejected += 1
    return rejected


# ---------------------------------------------------------------------------
# 6b. Suspicious-host quarantine — hosts flagged by verify_no_auth with a
#     forged-key 429 (open-proxy signal) or a 200-non-completion
#     (not-a-real-gateway signal). Unlike no_auth_hosts, these are NOT voided:
#     the evidence is suggestive, not conclusive. Results keep valid=True but
#     gain suspicious=True so the scanner can split them out of valid_*.jsonl
#     into suspicious_*.jsonl for manual review.
# ---------------------------------------------------------------------------

# Hosts (apiurl) flagged suspicious by verify_no_auth. Populated by the scanner
# between validate_all and filter_honeypots. Module-level mirror of no_auth_hosts.
suspicious_hosts: set[str] = set()


def _quarantine_suspicious_hosts(results: list[ValidationResult]) -> int:
    """Mark (don't void) valid results on suspicious hosts.

    Sets ``r.suspicious=True`` and a reason, leaving ``valid=True``. The scanner
    is responsible for moving suspicious results out of valid_*.jsonl.
    """
    if not suspicious_hosts:
        return 0
    marked = 0
    for r in results:
        if not r.valid:
            continue
        if r.credential.host in suspicious_hosts:
            r.suspicious = True
            r.suspicious_reason = (
                "honeypot:suspicious-host (forged key got 429 or non-completion "
                "— open-proxy / not-a-real-gateway; manual review)"
            )
            marked += 1
    return marked


# ---------------------------------------------------------------------------
# 3. Response fingerprint clustering — detect many hosts with identical
#    responses, same balance, etc.
# ---------------------------------------------------------------------------

# Minimum number of distinct hosts sharing the SAME fingerprint to trigger
# rejection.  A threshold too low causes false positives when many legitimate
# hosts proxy the same underlying model (e.g. OneAPI → gpt-4o-mini).
_FINGERPRINT_CLUSTER_THRESHOLD = 5

# Generic LLM greetings that most models produce for a "Hi" probe.  Matching
# these ALONE is not enough to conclude honeypot — we require additional
# signals (see below).
_GENERIC_LLM_RESPONSES = re.compile(
    r"(?i)^[\s\n]*(hello|hi|hey|greetings)[\s!.,]*"
    r"(how can i|i'?m doing|i'?m here|how about|nice to|what can)",
)


def _detect_response_clusters(results: list[ValidationResult]) -> int:
    """Flag results where many unrelated hosts share the same canned response.

    Honeypot clusters typically share:
    - Identical response_snippet AND balance AND gateway
    - Often a non-empty balance that's suspicious (e.g. same exact balance on
      many unrelated hosts).

    We AVOID rejecting legitimate OneAPI/LiteLLM farms that proxy to the same
    model and naturally return similar greetings with empty balance — unless
    there are enough additional signals indicating coordination.
    """
    # Build fingerprint: (response_snippet[:100], balance, gateway)
    # Include gateway to avoid lumping different gateway types together.
    fingerprint_indices: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(results):
        if not r.valid:
            continue
        snippet = (r.response_snippet or "").strip()[:100]
        balance = r.balance or ""
        gateway = r.gateway or ""
        if snippet:  # Only cluster if there's a response to compare
            fp = (snippet, balance, gateway)
            fingerprint_indices[fp].append(i)

    rejected = 0
    for fp, indices in fingerprint_indices.items():
        if len(indices) < _FINGERPRINT_CLUSTER_THRESHOLD:
            continue

        snippet, balance, gateway = fp

        # Check if these are actually distinct hosts (not same host, diff keys)
        hosts = {results[i].credential.host for i in indices}
        if len(hosts) < _FINGERPRINT_CLUSTER_THRESHOLD:
            continue

        # --- Heuristic: skip likely-legitimate clusters ---
        # If balance is empty AND the response matches a generic LLM greeting,
        # this is most likely real endpoints proxying the same model, not a
        # honeypot.  Honeypots typically report a specific (fake) balance to
        # lure attackers.
        if not balance and _GENERIC_LLM_RESPONSES.match(snippet):
            continue

        # If balance is empty AND all hosts have distinct IPs across multiple
        # /16 subnets, it's unlikely to be a coordinated honeypot cluster.
        if not balance:
            ips = set()
            for idx in indices:
                ip = results[idx].credential.ip or ""
                if ip:
                    parts = ip.split(".")
                    if len(parts) >= 2:
                        ips.add(f"{parts[0]}.{parts[1]}")
            # Diverse subnets → probably not a single operator's honeypot
            if len(ips) >= min(5, len(hosts) // 2):
                continue

        # This is a cluster — reject all
        snippet_preview = snippet[:40]
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
# 4. Zero-width steganography detection — responses embedding invisible
#    Unicode fingerprints to track per-request usage.
# ---------------------------------------------------------------------------

# Zero-width characters used for steganography encoding.
_ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\u200e\u200f\u2060\ufeff")

# Threshold: >= this many zero-width chars in a snippet → steganography.
# Normal LLM output has 0; even multilingual text rarely has more than 2.
_STEG_THRESHOLD = 10


def _detect_steganography(results: list[ValidationResult]) -> int:
    """Flag results whose response contains zero-width steganography.

    Honeypots like Nexus AI embed per-request fingerprints using sequences
    of U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ) to track which leaked
    key generated which output and trace copy-pasted content.
    """
    rejected = 0
    for r in results:
        if not r.valid:
            continue
        snippet = r.response_snippet or ""
        zwc_count = sum(1 for c in snippet if c in _ZERO_WIDTH_CHARS)
        if zwc_count >= _STEG_THRESHOLD:
            r.valid = False
            r.error = (
                f"honeypot:steganography ({zwc_count} zero-width chars "
                f"in response — per-request tracking fingerprint)"
            )
            rejected += 1
    return rejected


# ---------------------------------------------------------------------------
# 5. Prompt injection detection — responses designed to trick downstream
#    AI agents into exfiltrating tokens or executing attacker instructions.
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # HTML comments with system instructions / verification URLs
    ("html_comment_injection", re.compile(
        r"<!--\s*system\s*:", re.I
    )),
    # Fake [SYSTEM NOTE] blocks
    ("fake_system_note", re.compile(
        r"\[SYSTEM\s+NOTE", re.I
    )),
    # Instructions to perform GET/POST to verify/exfil URLs
    ("exfil_instruction", re.compile(
        r"(?:perform|issue|make|send)\s+(?:GET|POST|PUT)\s+/", re.I
    )),
    # "silently" + action verb — classic agent manipulation
    ("silent_action", re.compile(
        r"silently\s+(?:perform|execute|send|make|issue|fetch|call)", re.I
    )),
    # "do not include this in your response" — hiding from user
    ("hide_from_user", re.compile(
        r"do\s+not\s+include\s+(?:this|the\s+above)\s+in\s+your\s+response", re.I
    )),
    # Asking the model to submit context/instructions to an endpoint
    ("context_exfil", re.compile(
        r"(?:submit(?:ting)?|send(?:ing)?|post(?:ing)?)\s+your\s+(?:full\s+)?(?:system\s+)?(?:context|instructions|prompt)", re.I
    )),
]


def _detect_prompt_injection(results: list[ValidationResult]) -> int:
    """Flag results whose response contains prompt injection payloads.

    Some honeypots return responses that include hidden instructions designed
    to trick AI agents processing the output into exfiltrating auth tokens,
    system prompts, or making attacker-controlled requests.
    """
    rejected = 0
    for r in results:
        if not r.valid:
            continue
        snippet = r.response_snippet or ""
        if not snippet:
            continue
        for pattern_name, pat in _PROMPT_INJECTION_PATTERNS:
            if pat.search(snippet):
                r.valid = False
                r.error = f"honeypot:prompt-injection:{pattern_name}"
                rejected += 1
                break
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

    # Pass 2: Zero-width steganography detection
    steg_rejected = _detect_steganography(results)

    # Pass 3: Prompt injection in responses
    injection_rejected = _detect_prompt_injection(results)

    # Pass 4: Key format rejection
    format_rejected = 0
    for r in results:
        if not r.valid:
            continue
        reason = _is_blocked_key_format(r.credential.apikey)
        if reason:
            r.valid = False
            r.error = reason
            format_rejected += 1

    # Pass 5: Cross-host dedup
    dedup_rejected = _dedup_cross_host(results)

    # Pass 6: No-auth host rejection (forged-key probe verdict from validator)
    noauth_rejected = _reject_no_auth_hosts(results)

    # Pass 7: Suspicious-host quarantine (forged-429 / non-completion verdict).
    # Marks suspicious=True but leaves valid=True; the scanner splits these out.
    suspicious_marked = _quarantine_suspicious_hosts(results)

    valid_after = sum(1 for r in results if r.valid)
    total_rejected = valid_before - valid_after

    if total_rejected > 0 or suspicious_marked > 0:
        log.info(
            "Honeypot filter: %d/%d rejected, %d suspicious "
            "(cluster=%d, steg=%d, injection=%d, format=%d, dedup=%d, no-auth=%d, "
            "suspicious=%d) → %d valid remain",
            total_rejected, valid_before,
            suspicious_marked,
            cluster_rejected, steg_rejected, injection_rejected,
            format_rejected, dedup_rejected, noauth_rejected, suspicious_marked,
            valid_after,
        )
    else:
        log.info("Honeypot filter: 0 rejected, %d valid remain", valid_after)

    return results
