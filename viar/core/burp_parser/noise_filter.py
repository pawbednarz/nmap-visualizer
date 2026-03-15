"""
Noise filter for Burp Suite traffic.

Removes static resources, duplicates, and irrelevant requests to leave only
semantically meaningful HTTP interactions for security analysis.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from viar.models.burp import BurpHttpItem, BurpScanData

# MIME types that are almost never relevant to pentest findings
_STATIC_MIMES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "image/x-icon",
        "font/woff",
        "font/woff2",
        "font/ttf",
        "font/eot",
        "text/css",
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
    }
)

# Path suffixes that strongly indicate static content
_STATIC_EXTENSIONS = re.compile(
    r"\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|css|js|map|pdf|zip|tar|gz)(\?.*)?$",
    re.IGNORECASE,
)

# Paths that are typically boring (health checks, metrics, etc.)
_BORING_PATHS = re.compile(
    r"^/(health|ping|metrics|favicon\.ico|robots\.txt|sitemap\.xml)",
    re.IGNORECASE,
)


@dataclass
class FilterConfig:
    """Tunable parameters for noise filtering."""

    remove_static: bool = True
    remove_boring_paths: bool = True
    remove_304_responses: bool = True
    deduplicate_identical_requests: bool = True
    # Minimum response body length to keep (filters empty responses)
    min_response_body_len: int = 0
    # If set, only keep requests to these hosts
    allowed_hosts: Optional[list[str]] = field(default=None)
    # Additional path patterns to exclude (regex strings)
    extra_exclude_patterns: list[str] = field(default_factory=list)


class NoiseFilter:
    """
    Filters and deduplicates Burp HTTP traffic.

    Strategy:
    1. Remove static resources (images, fonts, CSS, JS)
    2. Remove boring paths (health checks, robots.txt, etc.)
    3. Remove 304 Not Modified responses
    4. Deduplicate identical request fingerprints
    5. Apply caller-supplied exclusion rules
    """

    def __init__(self, config: Optional[FilterConfig] = None):
        self.config = config or FilterConfig()
        self._extra_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (self.config.extra_exclude_patterns or [])
        ]

    def filter(self, scan: BurpScanData) -> BurpScanData:
        """Return a new BurpScanData with noise removed (non-destructive)."""
        filtered = self._filter_items(scan.http_items)
        # Rebuild a shallow copy with filtered items
        return scan.model_copy(update={"http_items": filtered})

    def filter_items(self, items: list[BurpHttpItem]) -> list[BurpHttpItem]:
        return self._filter_items(items)

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _filter_items(self, items: list[BurpHttpItem]) -> list[BurpHttpItem]:
        seen_fingerprints: set[str] = set()
        kept: list[BurpHttpItem] = []

        for item in items:
            if not self._should_keep(item, seen_fingerprints):
                continue
            kept.append(item)

        return kept

    def _should_keep(
        self, item: BurpHttpItem, seen: set[str]
    ) -> bool:
        req = item.request
        resp = item.response

        # Host allowlist
        if self.config.allowed_hosts is not None:
            if req.host not in self.config.allowed_hosts:
                return False

        # Static MIME type
        if self.config.remove_static and item.mime_type:
            if item.mime_type.lower().split(";")[0].strip() in _STATIC_MIMES:
                return False

        # Static path extension
        if self.config.remove_static and _STATIC_EXTENSIONS.search(req.path):
            return False

        # Boring paths
        if self.config.remove_boring_paths and _BORING_PATHS.match(req.path):
            return False

        # 304 Not Modified
        if self.config.remove_304_responses and resp and resp.status_code == 304:
            return False

        # Minimum response body length
        if resp and self.config.min_response_body_len > 0:
            body_len = len(resp.body or "")
            if body_len < self.config.min_response_body_len:
                return False

        # Extra caller patterns
        for pattern in self._extra_patterns:
            if pattern.search(req.path) or pattern.search(req.url):
                return False

        # Deduplication by request fingerprint
        if self.config.deduplicate_identical_requests:
            fingerprint = self._fingerprint(item)
            if fingerprint in seen:
                return False
            seen.add(fingerprint)

        return True

    @staticmethod
    def _fingerprint(item: BurpHttpItem) -> str:
        """Stable hash of the request (method + url + body) for dedup."""
        req = item.request
        key = f"{req.method}|{req.url}|{(req.body or '').strip()}"
        return hashlib.sha256(key.encode()).hexdigest()
