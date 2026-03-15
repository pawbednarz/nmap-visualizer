"""
PII Scrubber — redacts sensitive client data before sending to LLM APIs.

Protects customer privacy by replacing PII patterns with anonymised tokens.
Operates on raw text (HTTP requests/responses, video captions, etc.).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ScrubberConfig:
    """Controls which PII patterns are scrubbed."""

    scrub_emails: bool = True
    scrub_phones: bool = True
    scrub_ips: bool = False          # Disable by default — IPs are useful for pentest
    scrub_credit_cards: bool = True
    scrub_ssn: bool = True
    scrub_jwt: bool = True
    scrub_api_keys: bool = True
    # Custom regex patterns to redact (regex → replacement token)
    custom_patterns: list[tuple[str, str]] = field(default_factory=list)


# Built-in PII patterns
_BUILTIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # Phone numbers (E.164 and common formats)
    (re.compile(r"\b(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"), "[PHONE]"),
    # Credit card numbers (13–16 digits, various separators)
    (re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"), "[CREDIT_CARD]"),
    # US Social Security Numbers
    (re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"), "[SSN]"),
    # JWT tokens (three Base64url-encoded segments)
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        "[JWT_TOKEN]",
    ),
    # Generic API keys (long alphanumeric/hex strings, typically in headers)
    (
        re.compile(
            r"(?i)(?:api[_\-]?key|token|secret|password|Authorization)[\":\s]+([A-Za-z0-9_\-/+.=]{20,})"
        ),
        r"[API_KEY]",
    ),
]

_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


class PIIScrubber:
    """
    Scrubs PII and secrets from text before sending to external LLM APIs.

    All redaction is done locally — no data leaves the machine during scrubbing.

    Example:
        scrubber = PIIScrubber()
        clean = scrubber.scrub("User: john@example.com, CC: 4111-1111-1111-1111")
        # → "User: [EMAIL], CC: [CREDIT_CARD]"
    """

    def __init__(self, config: ScrubberConfig | None = None):
        self.config = config or ScrubberConfig()
        self._patterns = self._build_patterns()

    def scrub(self, text: str) -> str:
        """Redact PII and secrets from the input text."""
        if not text:
            return text
        for pattern, replacement in self._patterns:
            text = pattern.sub(replacement, text)
        return text

    def scrub_dict(self, data: dict) -> dict:
        """Recursively scrub string values in a dictionary."""
        return {k: self._scrub_value(v) for k, v in data.items()}

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _scrub_value(self, v: object) -> object:
        if isinstance(v, str):
            return self.scrub(v)
        if isinstance(v, dict):
            return self.scrub_dict(v)
        if isinstance(v, list):
            return [self._scrub_value(item) for item in v]
        return v

    def _build_patterns(self) -> list[tuple[re.Pattern, str]]:
        patterns: list[tuple[re.Pattern, str]] = []
        cfg = self.config

        pattern_toggles = [
            (cfg.scrub_emails, 0),
            (cfg.scrub_phones, 1),
            (cfg.scrub_credit_cards, 2),
            (cfg.scrub_ssn, 3),
            (cfg.scrub_jwt, 4),
            (cfg.scrub_api_keys, 5),
        ]
        for enabled, idx in pattern_toggles:
            if enabled:
                patterns.append(_BUILTIN_PATTERNS[idx])

        if cfg.scrub_ips:
            patterns.append((_IP_PATTERN, "[IP_ADDRESS]"))

        for raw_pattern, replacement in cfg.custom_patterns:
            patterns.append((re.compile(raw_pattern), replacement))

        return patterns
