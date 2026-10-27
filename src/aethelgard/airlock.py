"""Subsystem Layer 1: Privacy Airlock (Regex + Shannon Entropy Scrubber)."""

import math
import re
from typing import Any

# Intercepts raw payloads pre-ingestion, redacting API keys (sk-..., AKIA...) and secrets
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"),
]

TOKEN_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/_\-]{20,}={0,2}")
ENTROPY_THRESHOLD = 4.2


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_mixed_char_classes(token: str) -> bool:
    """Distinguish high-entropy secret tokens from plain identifiers or paths."""
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return (has_lower and has_upper and has_digit) or (has_digit and (has_lower or has_upper))


def scrub_text(text: str) -> str:
    """Redact regex-matched API keys and high-entropy secret tokens from a string."""
    scrubbed = text
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            def _replace_group(match: re.Match) -> str:
                full = match.group(0)
                secret = match.group(1)
                return full.replace(secret, "[REDACTED]")
            scrubbed = pattern.sub(_replace_group, scrubbed)
        else:
            scrubbed = pattern.sub("[REDACTED]", scrubbed)

    def _entropy_replacer(match: re.Match) -> str:
        token = match.group(0)
        if token == "[REDACTED]":
            return token
        if _has_mixed_char_classes(token) and shannon_entropy(token) >= ENTROPY_THRESHOLD:
            return "[REDACTED]"
        return token

    return TOKEN_CANDIDATE_RE.sub(_entropy_replacer, scrubbed)


def scrub_payload(payload: Any) -> Any:
    """Recursively scrub strings in a payload prior to RFC 8785 canonicalization."""
    if isinstance(payload, str):
        return scrub_text(payload)
    if isinstance(payload, dict):
        return {k: scrub_payload(v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [scrub_payload(item) for item in payload]
    if isinstance(payload, tuple):
        return [scrub_payload(item) for item in payload]
    return payload
