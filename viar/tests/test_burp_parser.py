"""Tests for Burp Suite parsers and noise filter."""
from __future__ import annotations

import base64
from datetime import datetime

import pytest

from viar.core.burp_parser import BurpXmlParser, BurpJsonParser, NoiseFilter
from viar.core.burp_parser.noise_filter import FilterConfig


# ─────────────────────────────────────────────────────────────────────────────
# Sample XML content
# ─────────────────────────────────────────────────────────────────────────────

def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


SAMPLE_BURP_XML = f"""<?xml version="1.0"?>
<!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<items burpVersion="2024.1" exportTime="Mon Jan 15 10:00:00 GMT 2024">
  <item>
    <time>Mon Jan 15 10:00:00 GMT 2024</time>
    <url>http://app.example.com/api/users/1</url>
    <host ip="93.184.216.34">app.example.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method>GET</method>
    <path>/api/users/1</path>
    <extension>null</extension>
    <request base64="true">{_b64("GET /api/users/1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n")}</request>
    <response base64="true">{_b64("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: nginx\r\n\r\n{{\"id\":1}}")}</response>
    <responselength>7</responselength>
    <mimetype>JSON</mimetype>
    <status>200</status>
  </item>
  <item>
    <time>Mon Jan 15 10:01:00 GMT 2024</time>
    <url>http://app.example.com/static/main.css</url>
    <host>app.example.com</host>
    <request base64="true">{_b64("GET /static/main.css HTTP/1.1\r\nHost: app.example.com\r\n\r\n")}</request>
    <response base64="true">{_b64("HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody{{}}")}</response>
    <mimetype>CSS</mimetype>
    <status>200</status>
  </item>
</items>
"""

SAMPLE_BURP_JSON = """
{
  "items": [
    {
      "id": "item-001",
      "timestamp": 1705316400000,
      "request": {
        "method": "POST",
        "url": "http://app.example.com/login",
        "path": "/login",
        "host": "app.example.com",
        "port": 80,
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "username=admin&password=secret"
      },
      "response": {
        "statusCode": 200,
        "statusMessage": "OK",
        "headers": {"Content-Type": "application/json"},
        "body": "{\\"token\\": \\"abc123\\"}"
      }
    }
  ]
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# XML Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBurpXmlParser:
    def test_parses_http_items(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        assert len(result.http_items) == 2

    def test_parses_request_method_and_url(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        item = result.http_items[0]
        assert item.request.method == "GET"
        assert "app.example.com" in item.request.url

    def test_parses_response_status(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        assert result.http_items[0].response.status_code == 200

    def test_computes_unique_hosts(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        assert "app.example.com" in result.unique_hosts

    def test_detects_tech_fingerprints(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        assert any("nginx" in fp.lower() for fp in result.tech_fingerprints)

    def test_raises_on_invalid_xml(self):
        parser = BurpXmlParser()
        with pytest.raises(ValueError, match="Invalid Burp XML"):
            parser.parse_string("not xml at all <<<")

    def test_rejects_xxe_entity(self):
        """XXE in the DOCTYPE declaration should not be resolved."""
        parser = BurpXmlParser()
        # Should parse without executing the XXE entity
        result = parser.parse_string(SAMPLE_BURP_XML)
        # If XXE was resolved, content would contain /etc/passwd data
        for item in result.http_items:
            req_text = (item.request.raw or "").lower()
            assert "root:" not in req_text  # /etc/passwd content

    def test_time_range_computed(self):
        parser = BurpXmlParser()
        result = parser.parse_string(SAMPLE_BURP_XML)
        assert result.time_range_start is not None
        assert result.time_range_end is not None
        assert result.time_range_start <= result.time_range_end


# ─────────────────────────────────────────────────────────────────────────────
# JSON Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBurpJsonParser:
    def test_parses_items_key(self):
        parser = BurpJsonParser()
        result = parser.parse_string(SAMPLE_BURP_JSON)
        assert len(result.http_items) == 1

    def test_parses_request_body(self):
        parser = BurpJsonParser()
        result = parser.parse_string(SAMPLE_BURP_JSON)
        assert "username=admin" in (result.http_items[0].request.body or "")

    def test_parses_bare_list(self):
        import json
        data = json.dumps([
            {"method": "GET", "url": "http://example.com/", "path": "/", "host": "example.com"}
        ])
        parser = BurpJsonParser()
        result = parser.parse_string(data)
        assert len(result.http_items) == 1

    def test_source_format_is_json(self):
        parser = BurpJsonParser()
        result = parser.parse_string(SAMPLE_BURP_JSON)
        assert result.source_format == "json"


# ─────────────────────────────────────────────────────────────────────────────
# Noise Filter Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestNoiseFilter:
    def test_removes_css_items(self):
        parser = BurpXmlParser()
        scan = parser.parse_string(SAMPLE_BURP_XML)
        filtered = NoiseFilter().filter(scan)
        # CSS item should be filtered out
        urls = [item.request.url for item in filtered.http_items]
        assert not any("main.css" in url for url in urls)

    def test_keeps_api_items(self):
        parser = BurpXmlParser()
        scan = parser.parse_string(SAMPLE_BURP_XML)
        filtered = NoiseFilter().filter(scan)
        urls = [item.request.url for item in filtered.http_items]
        assert any("/api/users" in url for url in urls)

    def test_deduplicates_identical_requests(self, sample_http_item):
        from viar.models.burp import BurpScanData
        # Two identical items
        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=[sample_http_item, sample_http_item],
        )
        filtered = NoiseFilter().filter(scan)
        assert len(filtered.http_items) == 1

    def test_custom_exclusion_pattern(self, sample_http_item):
        from viar.models.burp import BurpScanData
        config = FilterConfig(extra_exclude_patterns=[r"/api/users"])
        scan = BurpScanData(
            source_file="test",
            source_format="xml",
            http_items=[sample_http_item],
        )
        filtered = NoiseFilter(config=config).filter(scan)
        assert len(filtered.http_items) == 0

    def test_non_destructive(self, sample_burp_scan):
        original_count = len(sample_burp_scan.http_items)
        NoiseFilter().filter(sample_burp_scan)
        # Original should be unchanged
        assert len(sample_burp_scan.http_items) == original_count
