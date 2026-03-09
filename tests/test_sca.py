"""Tests for SCA (Software Composition Analysis) module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dojigiri.sca.parsers import (
    Dependency,
    discover_lockfiles,
    parse_lockfile,
    _parse_requirements_txt,
    _parse_poetry_lock,
    _parse_pipfile_lock,
    _parse_package_lock_json,
    _parse_yarn_lock,
    _parse_cargo_lock,
    _parse_go_sum,
    _parse_gemfile_lock,
    _parse_composer_lock,
)
from dojigiri.sca.osv import (
    Vulnerability,
    _parse_vuln,
    _cvss_to_severity,
    _parse_cvss_score,
    _find_fix_version,
)
from dojigiri.sca.scanner import scan_sca, _vuln_to_finding
from dojigiri.types import Category, Severity, Source


# ─── Parser Tests ────────────────────────────────────────────────────


class TestRequirementsTxt:
    def test_basic(self):
        content = "flask==2.0.0\nrequests==2.25.0\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert len(deps) == 2
        assert ("flask", "2.0.0", "PyPI") in deps
        assert ("requests", "2.25.0", "PyPI") in deps

    def test_comments_and_blanks(self):
        content = "# comment\nflask==2.0.0\n\n  # another\nrequests==2.25.0\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert len(deps) == 2

    def test_inline_comments(self):
        content = "flask==2.0.0  # web framework\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert deps == [("flask", "2.0.0", "PyPI")]

    def test_skips_options(self):
        content = "-r base.txt\n--index-url https://pypi.org/simple\nflask==2.0.0\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert len(deps) == 1

    def test_skips_unpinned(self):
        content = "flask>=2.0\nrequests==2.25.0\ndjango\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert len(deps) == 1
        assert deps[0][0] == "requests"

    def test_triple_equals(self):
        content = "flask===2.0.0\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert deps == [("flask", "2.0.0", "PyPI")]

    def test_case_normalization(self):
        content = "Flask==2.0.0\nDjango==3.2\n"
        deps = _parse_requirements_txt(content, "PyPI")
        assert deps[0][0] == "flask"
        assert deps[1][0] == "django"


class TestPoetryLock:
    def test_basic(self):
        content = """
[[package]]
name = "flask"
version = "2.0.0"

[[package]]
name = "requests"
version = "2.25.0"
"""
        deps = _parse_poetry_lock(content, "PyPI")
        assert len(deps) == 2
        assert ("flask", "2.0.0", "PyPI") in deps

    def test_empty(self):
        deps = _parse_poetry_lock("", "PyPI")
        assert deps == []


class TestPipfileLock:
    def test_basic(self):
        content = json.dumps({
            "default": {
                "flask": {"version": "==2.0.0"},
                "requests": {"version": "==2.25.0"},
            },
            "develop": {
                "pytest": {"version": "==7.0.0"},
            },
        })
        deps = _parse_pipfile_lock(content, "PyPI")
        assert len(deps) == 3

    def test_invalid_json(self):
        deps = _parse_pipfile_lock("not json", "PyPI")
        assert deps == []


class TestPackageLockJson:
    def test_v2(self):
        content = json.dumps({
            "packages": {
                "": {},  # root
                "node_modules/express": {"version": "4.17.1"},
                "node_modules/lodash": {"version": "4.17.21"},
            }
        })
        deps = _parse_package_lock_json(content, "npm")
        assert len(deps) == 2
        assert ("express", "4.17.1", "npm") in deps

    def test_v1(self):
        content = json.dumps({
            "dependencies": {
                "express": {"version": "4.17.1"},
                "lodash": {
                    "version": "4.17.21",
                    "dependencies": {
                        "nested-pkg": {"version": "1.0.0"}
                    }
                },
            }
        })
        deps = _parse_package_lock_json(content, "npm")
        assert len(deps) == 3


class TestYarnLock:
    def test_basic(self):
        content = """
express@^4.17.0:
  version "4.17.1"

lodash@^4.17.0:
  version "4.17.21"
"""
        deps = _parse_yarn_lock(content, "npm")
        assert len(deps) == 2
        assert ("express", "4.17.1", "npm") in deps


class TestCargoLock:
    def test_basic(self):
        content = """
[[package]]
name = "serde"
version = "1.0.130"

[[package]]
name = "tokio"
version = "1.12.0"
"""
        deps = _parse_cargo_lock(content, "crates.io")
        assert len(deps) == 2
        assert ("serde", "1.0.130", "crates.io") in deps


class TestGoSum:
    def test_basic(self):
        content = """github.com/gin-gonic/gin v1.7.0 h1:abc123=
github.com/gin-gonic/gin v1.7.0/go.mod h1:def456=
github.com/stretchr/testify v1.7.0 h1:ghi789=
"""
        deps = _parse_go_sum(content, "Go")
        assert len(deps) == 2  # deduped
        assert ("github.com/gin-gonic/gin", "1.7.0", "Go") in deps


class TestGemfileLock:
    def test_basic(self):
        content = """GEM
  remote: https://rubygems.org/
  specs:
    rails (6.1.0)
    nokogiri (1.12.0)

PLATFORMS
  ruby
"""
        deps = _parse_gemfile_lock(content, "RubyGems")
        assert len(deps) == 2
        assert ("rails", "6.1.0", "RubyGems") in deps


class TestComposerLock:
    def test_basic(self):
        content = json.dumps({
            "packages": [
                {"name": "laravel/framework", "version": "v8.0.0"},
                {"name": "guzzlehttp/guzzle", "version": "7.0.0"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "v9.5.0"},
            ],
        })
        deps = _parse_composer_lock(content, "Packagist")
        assert len(deps) == 3
        assert ("laravel/framework", "8.0.0", "Packagist") in deps


# ─── OSV Tests ───────────────────────────────────────────────────────


class TestCvssSeverity:
    def test_critical(self):
        assert _cvss_to_severity(9.8) == "CRITICAL"

    def test_high(self):
        assert _cvss_to_severity(7.5) == "HIGH"

    def test_medium(self):
        assert _cvss_to_severity(5.0) == "MEDIUM"

    def test_low(self):
        assert _cvss_to_severity(2.0) == "LOW"

    def test_zero(self):
        assert _cvss_to_severity(0.0) == "UNKNOWN"


class TestParseVuln:
    def test_with_database_specific_severity(self):
        data = {
            "id": "GHSA-test-1234",
            "summary": "Test vuln",
            "aliases": ["CVE-2024-1234"],
            "database_specific": {"severity": "HIGH"},
            "affected": [],
        }
        vuln = _parse_vuln(data, "flask", "2.0.0", "PyPI")
        assert vuln is not None
        assert vuln.vuln_id == "GHSA-test-1234"
        assert vuln.severity == "HIGH"
        assert vuln.summary == "Test vuln"

    def test_with_cvss_vector(self):
        data = {
            "id": "GHSA-test-5678",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [],
        }
        vuln = _parse_vuln(data, "django", "3.2.0", "PyPI")
        assert vuln is not None
        assert vuln.severity in ("CRITICAL", "HIGH")

    def test_with_fix_version(self):
        data = {
            "id": "GHSA-test-fix",
            "database_specific": {"severity": "MEDIUM"},
            "affected": [{
                "package": {"name": "flask", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}],
            }],
        }
        vuln = _parse_vuln(data, "flask", "2.0.0", "PyPI")
        assert vuln is not None
        assert vuln.fix_version == "2.3.0"

    def test_no_id(self):
        assert _parse_vuln({}, "flask", "2.0.0", "PyPI") is None


# ─── Scanner Tests ───────────────────────────────────────────────────


class TestVulnToFinding:
    def test_basic(self):
        vuln = Vulnerability(
            vuln_id="GHSA-test",
            package="flask",
            installed_version="2.0.0",
            ecosystem="PyPI",
            severity="CRITICAL",
            summary="Bad thing",
            fix_version="2.3.0",
        )
        finding = _vuln_to_finding(vuln, "requirements.txt")
        assert finding.severity == Severity.CRITICAL
        assert finding.source == Source.SCA
        assert finding.category == Category.SECURITY
        assert finding.rule == "vulnerable-dependency"
        assert "flask 2.0.0" in finding.message
        assert "Upgrade flask to 2.3.0" == finding.suggestion

    def test_high_maps_to_critical(self):
        vuln = Vulnerability(
            vuln_id="GHSA-high",
            package="django",
            installed_version="3.2.0",
            ecosystem="PyPI",
            severity="HIGH",
        )
        finding = _vuln_to_finding(vuln, "requirements.txt")
        assert finding.severity == Severity.CRITICAL


class TestDiscoverLockfiles:
    def test_finds_lockfiles(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "package-lock.json").write_text("{}")
        lockfiles = discover_lockfiles(tmp_path)
        assert len(lockfiles) == 2

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "foo"
        nm.mkdir(parents=True)
        (nm / "package-lock.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        lockfiles = discover_lockfiles(tmp_path)
        assert len(lockfiles) == 1

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "requirements.txt").write_text("flask==2.0.0\n")
        lockfiles = discover_lockfiles(tmp_path)
        assert len(lockfiles) == 0


class TestScanSca:
    def test_no_lockfiles(self, tmp_path):
        result = scan_sca(tmp_path, offline=True)
        assert result == []

    def test_offline_returns_no_vulns(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        result = scan_sca(tmp_path, offline=True)
        assert result == []  # no OSV query in offline mode

    def test_with_mocked_osv(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")

        mock_vulns = [
            Vulnerability(
                vuln_id="GHSA-mock",
                package="flask",
                installed_version="2.0.0",
                ecosystem="PyPI",
                severity="HIGH",
                summary="Mocked vulnerability",
                fix_version="2.3.0",
            )
        ]

        with patch("dojigiri.sca.scanner.query_osv", return_value=mock_vulns):
            result = scan_sca(tmp_path)

        assert len(result) == 1
        assert len(result[0].findings) == 1
        assert result[0].findings[0].rule == "vulnerable-dependency"
        assert result[0].findings[0].source == Source.SCA


class TestParseLockfile:
    def test_dispatch_requirements(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("flask==2.0.0\n")
        deps = parse_lockfile(f)
        assert len(deps) == 1

    def test_unknown_file(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("stuff\n")
        deps = parse_lockfile(f)
        assert deps == []
