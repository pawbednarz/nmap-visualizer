"""Parser for Burp Suite JSON export format (Bambdas / Enterprise exports)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from viar.models.burp import (
    BurpHttpItem,
    BurpRequest,
    BurpResponse,
    BurpScanData,
    BurpScanIssue,
)


def _ts(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        return datetime.utcfromtimestamp(raw / 1000 if raw > 1e10 else raw)
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


class BurpJsonParser:
    """
    Parse Burp Suite JSON exports.

    Supports multiple schema variants:
    - Burp Enterprise JSON report
    - Bambda-exported traffic JSON
    - Custom VIAR JSON format
    """

    def parse_file(self, file_path: str | Path) -> BurpScanData:
        path = Path(file_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        return self.parse_dict(data, source_file=str(path))

    def parse_dict(
        self, data: dict | list, source_file: str = "<dict>"
    ) -> BurpScanData:
        http_items: list[BurpHttpItem] = []
        issues: list[BurpScanIssue] = []

        # Detect schema variant
        if isinstance(data, list):
            # Bare list of request/response objects
            http_items = [self._dict_to_http_item(d) for d in data if isinstance(d, dict)]
        elif "issues" in data:
            issues = [self._dict_to_issue(i) for i in data.get("issues", [])]
            http_items = [self._dict_to_http_item(r) for r in data.get("traffic", [])]
        elif "requests" in data or "items" in data:
            raw_items = data.get("requests") or data.get("items") or []
            http_items = [self._dict_to_http_item(r) for r in raw_items]
        else:
            # Fallback: treat as single HTTP item
            http_items = [self._dict_to_http_item(data)]

        scan = BurpScanData(
            source_file=source_file,
            source_format="json",
            http_items=http_items,
            issues=issues,
        )
        self._compute_aggregations(scan)
        return scan

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _dict_to_http_item(self, d: dict) -> BurpHttpItem:
        req_dict = d.get("request") or d
        resp_dict = d.get("response")

        request = BurpRequest(
            method=(req_dict.get("method") or "GET").upper(),
            url=req_dict.get("url") or req_dict.get("path") or "/",
            path=req_dict.get("path") or "/",
            host=req_dict.get("host") or "",
            port=int(req_dict.get("port") or 80),
            protocol=req_dict.get("protocol") or "http",
            headers=req_dict.get("headers") or {},
            body=req_dict.get("body"),
        )

        response: BurpResponse | None = None
        if resp_dict:
            response = BurpResponse(
                status_code=int(resp_dict.get("statusCode") or resp_dict.get("status") or 200),
                status_message=resp_dict.get("statusMessage") or "",
                headers=resp_dict.get("headers") or {},
                body=resp_dict.get("body"),
                length=int(resp_dict.get("length") or len(resp_dict.get("body") or "")),
            )

        return BurpHttpItem(
            item_id=d.get("id") or str(uuid.uuid4()),
            timestamp=_ts(d.get("timestamp") or d.get("time")),
            request=request,
            response=response,
            mime_type=d.get("mimeType"),
        )

    def _dict_to_issue(self, d: dict) -> BurpScanIssue:
        from urllib.parse import urlparse
        url = d.get("url") or ""
        parsed = urlparse(url)
        return BurpScanIssue(
            issue_id=d.get("id") or str(uuid.uuid4()),
            issue_type=int(d.get("typeIndex") or 0),
            issue_name=d.get("name") or "Unknown",
            severity=d.get("severity") or "Information",
            confidence=d.get("confidence") or "Tentative",
            url=url,
            host=parsed.hostname or "",
            path=parsed.path or "/",
            detail=d.get("detail"),
            background=d.get("background"),
            remediation=d.get("remediation"),
            cwes=d.get("cwes") or [],
        )

    def _compute_aggregations(self, scan: BurpScanData) -> None:
        hosts: set[str] = set()
        endpoints: set[str] = set()
        techs: set[str] = set()
        timestamps: list[datetime] = []

        for item in scan.http_items:
            hosts.add(item.request.host)
            endpoints.add(f"{item.request.method} {item.request.url}")
            timestamps.append(item.timestamp)
            if item.response:
                for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
                    val = item.response.headers.get(h)
                    if val:
                        techs.add(val)

        for issue in scan.issues:
            hosts.add(issue.host)

        scan.unique_hosts = sorted(hosts)
        scan.unique_endpoints = sorted(endpoints)
        scan.tech_fingerprints = sorted(techs)
        if timestamps:
            scan.time_range_start = min(timestamps)
            scan.time_range_end = max(timestamps)
