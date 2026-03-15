"""Parser for Burp Suite XML export format."""
from __future__ import annotations

import base64
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from viar.models.burp import (
    BurpHttpItem,
    BurpRequest,
    BurpResponse,
    BurpScanData,
    BurpScanIssue,
)

logger = logging.getLogger(__name__)

# Burp timestamp format: "Mon Nov 13 10:30:00 GMT 2023"
_BURP_TS_FORMAT = "%a %b %d %H:%M:%S %Z %Y"


def _decode_b64(value: Optional[str]) -> Optional[str]:
    """Decode base64-encoded Burp field, returning None on failure."""
    if not value:
        return None
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except Exception:
        return value  # already plain text


def _parse_headers(raw: str) -> tuple[dict[str, str], Optional[str]]:
    """Split raw HTTP message into header dict and optional body."""
    headers: dict[str, str] = {}
    body: Optional[str] = None

    if not raw:
        return headers, body

    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    header_block = parts[0]
    if len(parts) > 1:
        body = parts[1] if parts[1] else None

    for line in header_block.splitlines()[1:]:  # skip request/status line
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return headers, body


def _parse_request(raw: str) -> BurpRequest:
    """Parse raw HTTP request string into BurpRequest."""
    lines = raw.splitlines()
    first_line = lines[0] if lines else "GET / HTTP/1.1"
    parts = first_line.split()
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    headers, body = _parse_headers(raw)
    host_header = headers.get("Host", "")
    host_parts = host_header.split(":")
    host = host_parts[0]
    try:
        port = int(host_parts[1]) if len(host_parts) > 1 else 80
    except ValueError:
        port = 80

    url = f"http://{host}{path}"

    return BurpRequest(
        method=method,
        url=url,
        path=path,
        host=host,
        port=port,
        headers=headers,
        body=body,
        raw=raw,
    )


def _parse_response(raw: str) -> Optional[BurpResponse]:
    """Parse raw HTTP response string into BurpResponse."""
    if not raw:
        return None

    lines = raw.splitlines()
    status_line = lines[0] if lines else "HTTP/1.1 200 OK"
    status_parts = status_line.split(None, 2)
    try:
        status_code = int(status_parts[1]) if len(status_parts) > 1 else 200
    except ValueError:
        status_code = 200
    status_message = status_parts[2] if len(status_parts) > 2 else ""

    headers, body = _parse_headers(raw)

    return BurpResponse(
        status_code=status_code,
        status_message=status_message,
        headers=headers,
        body=body,
        raw=raw,
        length=len(body or ""),
    )


def _parse_timestamp(ts_str: Optional[str]) -> datetime:
    """Parse Burp timestamp string; fall back to now() on failure."""
    if not ts_str:
        return datetime.utcnow()
    ts_str = ts_str.strip()
    try:
        return datetime.strptime(ts_str, _BURP_TS_FORMAT)
    except ValueError:
        pass
    try:
        # Sometimes Burp uses Unix epoch in ms
        return datetime.utcfromtimestamp(int(ts_str) / 1000)
    except (ValueError, OSError):
        return datetime.utcnow()


class BurpXmlParser:
    """
    Parse Burp Suite XML exports (both HTTP history and scanner issues).

    Handles the two main XML export types:
    - HTTP Proxy history  (<items> root with <item> children)
    - Active/Passive scan results (<issues> root with <issue> children)
    """

    def parse_file(self, file_path: str | Path) -> BurpScanData:
        path = Path(file_path)
        raw_xml = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_string(raw_xml, source_file=str(path))

    def parse_string(
        self, xml_content: str, source_file: str = "<string>"
    ) -> BurpScanData:
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid Burp XML: {exc}") from exc

        http_items: list[BurpHttpItem] = []
        issues: list[BurpScanIssue] = []

        if root.tag == "items":
            http_items = self._parse_http_items(root)
        elif root.tag == "issues":
            issues, http_items = self._parse_issues(root)
        else:
            # Try both child element types
            http_items = self._parse_http_items(root)

        scan_data = BurpScanData(
            source_file=source_file,
            source_format="xml",
            http_items=http_items,
            issues=issues,
        )
        self._compute_aggregations(scan_data)
        return scan_data

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _parse_http_items(self, root: ET.Element) -> list[BurpHttpItem]:
        items: list[BurpHttpItem] = []
        for elem in root.findall("item"):
            try:
                items.append(self._element_to_http_item(elem))
            except Exception as exc:
                logger.warning("Skipping malformed <item>: %s", exc)
        return items

    def _element_to_http_item(self, elem: ET.Element) -> BurpHttpItem:
        ts_text = elem.findtext("time")
        timestamp = _parse_timestamp(ts_text)

        req_b64 = elem.findtext("request")
        resp_b64 = elem.findtext("response")

        req_raw = _decode_b64(req_b64) or ""
        resp_raw = _decode_b64(resp_b64)

        request = _parse_request(req_raw)
        response = _parse_response(resp_raw) if resp_raw else None

        # Override URL / host from explicit XML fields when available
        if url_text := elem.findtext("url"):
            request.url = url_text
        if host_elem := elem.find("host"):
            request.host = host_elem.text or request.host
            ip = host_elem.get("ip", "")
            if ip and ":" in ip:
                try:
                    request.port = int(ip.split(":")[-1])
                except ValueError:
                    pass

        mime_type = elem.findtext("mimetype")

        return BurpHttpItem(
            item_id=str(uuid.uuid4()),
            timestamp=timestamp,
            request=request,
            response=response,
            mime_type=mime_type,
        )

    def _parse_issues(
        self, root: ET.Element
    ) -> tuple[list[BurpScanIssue], list[BurpHttpItem]]:
        issues: list[BurpScanIssue] = []
        all_http: list[BurpHttpItem] = []

        for elem in root.findall("issue"):
            try:
                issue, http_items = self._element_to_issue(elem)
                issues.append(issue)
                all_http.extend(http_items)
            except Exception as exc:
                logger.warning("Skipping malformed <issue>: %s", exc)

        return issues, all_http

    def _element_to_issue(
        self, elem: ET.Element
    ) -> tuple[BurpScanIssue, list[BurpHttpItem]]:
        http_items: list[BurpHttpItem] = []

        for req_elem in elem.findall(".//requestresponse"):
            try:
                http_items.append(self._reqresp_to_http_item(req_elem))
            except Exception as exc:
                logger.debug("Could not parse <requestresponse>: %s", exc)

        url = elem.findtext("url") or ""
        from urllib.parse import urlparse

        parsed = urlparse(url)

        issue = BurpScanIssue(
            issue_id=str(uuid.uuid4()),
            issue_type=int(elem.findtext("type") or "0"),
            issue_name=elem.findtext("name") or "Unknown",
            severity=elem.findtext("severity") or "Information",
            confidence=elem.findtext("confidence") or "Tentative",
            url=url,
            host=parsed.hostname or "",
            path=parsed.path or "/",
            detail=elem.findtext("issueDetail"),
            background=elem.findtext("issueBackground"),
            remediation=elem.findtext("remediationDetail"),
            remediation_background=elem.findtext("remediationBackground"),
            http_items=http_items,
        )
        return issue, http_items

    def _reqresp_to_http_item(self, elem: ET.Element) -> BurpHttpItem:
        req_raw = _decode_b64(elem.findtext("request")) or ""
        resp_raw = _decode_b64(elem.findtext("response"))
        request = _parse_request(req_raw)
        response = _parse_response(resp_raw) if resp_raw else None
        return BurpHttpItem(
            item_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            request=request,
            response=response,
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

            # Fingerprint tech from response headers
            if item.response:
                server = item.response.headers.get("Server", "")
                x_powered = item.response.headers.get("X-Powered-By", "")
                if server:
                    techs.add(server)
                if x_powered:
                    techs.add(x_powered)

        for issue in scan.issues:
            hosts.add(issue.host)

        scan.unique_hosts = sorted(hosts)
        scan.unique_endpoints = sorted(endpoints)
        scan.tech_fingerprints = sorted(techs)

        if timestamps:
            scan.time_range_start = min(timestamps)
            scan.time_range_end = max(timestamps)
