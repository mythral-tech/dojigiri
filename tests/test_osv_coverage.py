"""Tests for dojigiri/sca/osv.py — OSV parsing and scoring functions (no network)."""

import json
import pytest
from unittest.mock import patch, MagicMock

from dojigiri.sca.osv import (
    Vulnerability,
    _cvss_to_severity,
    _find_fix_version,
    _parse_cvss_score,
    _parse_vuln,
    query_osv,
)


# ─── _cvss_to_severity ──────────────────────────────────────────────


class TestCvssToSeverity:
    def test_critical(self):
        assert _cvss_to_severity(9.5) == "CRITICAL"

    def test_high(self):
        assert _cvss_to_severity(8.0) == "HIGH"

    def test_medium(self):
        assert _cvss_to_severity(5.0) == "MEDIUM"

    def test_low(self):
        assert _cvss_to_severity(2.0) == "LOW"

    def test_zero(self):
        assert _cvss_to_severity(0.0) == "UNKNOWN"


# ─── _parse_cvss_score ──────────────────────────────────────────────


class TestParseCvssScore:
    def test_high_impact_vector(self):
        # Network attack, low complexity, no privileges, high CIA impact
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score is not None
        assert score >= 8.0

    def test_low_impact_vector(self):
        score = _parse_cvss_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        assert score is not None
        assert score < 3.0

    def test_partial_vector(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L")
        assert score is not None

    def test_cvss4_vector(self):
        score = _parse_cvss_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
        assert score is not None


# ─── _find_fix_version ───────────────────────────────────────────────


class TestFindFixVersion:
    def test_found(self):
        data = {
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.25.1"}],
                }],
            }],
        }
        assert _find_fix_version(data, "requests", "PyPI") == "2.25.1"

    def test_not_found_different_package(self):
        data = {
            "affected": [{
                "package": {"name": "other-pkg", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "1.0"}]}],
            }],
        }
        assert _find_fix_version(data, "requests", "PyPI") is None

    def test_no_fix_event(self):
        data = {
            "affected": [{
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}]}],
            }],
        }
        assert _find_fix_version(data, "requests", "PyPI") is None

    def test_empty_affected(self):
        assert _find_fix_version({}, "pkg", "PyPI") is None


# ─── _parse_vuln ────────────────────────────────────────────────────


class TestParseVuln:
    def test_basic_vuln(self):
        data = {
            "id": "GHSA-1234",
            "aliases": ["CVE-2023-1234"],
            "summary": "A vulnerability",
            "database_specific": {"severity": "HIGH"},
        }
        vuln = _parse_vuln(data, "requests", "2.25.0", "PyPI")
        assert vuln is not None
        assert vuln.vuln_id == "GHSA-1234"
        assert vuln.severity == "HIGH"
        assert vuln.package == "requests"

    def test_no_id_returns_none(self):
        assert _parse_vuln({}, "pkg", "1.0", "PyPI") is None

    def test_cvss_vector_severity(self):
        data = {
            "id": "GHSA-5678",
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        vuln = _parse_vuln(data, "pkg", "1.0", "PyPI")
        assert vuln is not None
        assert vuln.severity in ("CRITICAL", "HIGH")
        assert vuln.cvss_score is not None

    def test_affected_severity_fallback(self):
        data = {
            "id": "GHSA-9999",
            "affected": [{
                "database_specific": {"severity": "moderate"},
            }],
        }
        vuln = _parse_vuln(data, "pkg", "1.0", "PyPI")
        assert vuln is not None
        assert vuln.severity == "MODERATE"

    def test_details_as_summary_fallback(self):
        data = {
            "id": "GHSA-0000",
            "details": "Long description " * 20,
        }
        vuln = _parse_vuln(data, "pkg", "1.0", "PyPI")
        assert vuln is not None
        assert len(vuln.summary) <= 200

    def test_with_fix_version(self):
        data = {
            "id": "GHSA-1111",
            "affected": [{
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "2.0.0"}]}],
            }],
        }
        vuln = _parse_vuln(data, "flask", "1.0", "PyPI")
        assert vuln.fix_version == "2.0.0"


# ─── query_osv ──────────────────────────────────────────────────────


class TestQueryOsv:
    def test_empty_packages(self):
        assert query_osv([]) == []

    def test_query_mocked(self):
        """Test query_osv with mocked HTTP calls."""
        batch_response = json.dumps({
            "results": [{"vulns": [{"id": "GHSA-test"}]}]
        }).encode("utf-8")
        vuln_response = json.dumps({
            "id": "GHSA-test",
            "summary": "Test vuln",
            "database_specific": {"severity": "HIGH"},
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = batch_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        call_count = [0]
        def fake_urlopen(req, timeout=30):
            call_count[0] += 1
            m = MagicMock()
            if call_count[0] == 1:
                m.read.return_value = batch_response
            else:
                m.read.return_value = vuln_response
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("dojigiri.sca.osv.urllib.request.urlopen", side_effect=fake_urlopen):
            vulns = query_osv([("requests", "2.25.0", "PyPI")])
            assert len(vulns) >= 1
            assert vulns[0].vuln_id == "GHSA-test"
