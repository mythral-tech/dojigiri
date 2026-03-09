"""Comprehensive SARIF output tests — complementary to test_report.py.

Focuses on structural validation, CWE taxonomy, edge cases, and schema compliance
that test_report.py doesn't cover.
"""

import json
import pytest

from dojigiri.sarif import to_sarif, SARIF_SCHEMA
from dojigiri.compliance import CWE_MAP
from dojigiri.types import (
    Finding, FileAnalysis, ScanReport,
    Severity, Category, Source, Confidence,
)
from dojigiri import __version__


def _finding(rule="test-rule", line=10, severity=Severity.WARNING,
             category=Category.BUG, source=Source.STATIC,
             message="Test", suggestion=None, snippet=None,
             confidence=None):
    return Finding(
        file="app.py", line=line, severity=severity,
        category=category, source=source, rule=rule,
        message=message, suggestion=suggestion,
        snippet=snippet, confidence=confidence,
    )


def _report(findings, path="app.py", mode="quick"):
    fa = FileAnalysis(path=path, language="python", lines=50, findings=findings)
    return ScanReport(
        root="/project", mode=mode,
        files_scanned=1, files_skipped=0,
        file_analyses=[fa],
    )


# ─── Schema structure ────────────────────────────────────────────────


class TestSarifSchema:
    def test_top_level_keys(self):
        """SARIF document has version, $schema, and runs."""
        sarif = to_sarif(_report([_finding()]))
        assert set(sarif.keys()) == {"version", "$schema", "runs"}
        assert sarif["version"] == "2.1.0"

    def test_schema_url(self):
        """$schema points to the OASIS SARIF 2.1.0 schema."""
        sarif = to_sarif(_report([_finding()]))
        assert sarif["$schema"] == SARIF_SCHEMA
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_single_run(self):
        """Output always has exactly one run."""
        sarif = to_sarif(_report([_finding()]))
        assert len(sarif["runs"]) == 1

    def test_tool_driver_metadata(self):
        """Tool driver has name, version, and informationUri."""
        sarif = to_sarif(_report([_finding()]))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "dojigiri"
        assert driver["semanticVersion"] == __version__
        assert "informationUri" in driver

    def test_full_json_roundtrip(self):
        """SARIF document survives JSON serialization roundtrip."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", severity=Severity.CRITICAL,
                     category=Category.SECURITY, suggestion="Use ast.literal_eval"),
            _finding(rule="bare-except", line=20),
        ]))
        text = json.dumps(sarif)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 2


# ─── CWE taxonomy ────────────────────────────────────────────────────


class TestCWETaxonomy:
    def test_known_rule_has_cwe_tag(self):
        """Rules with CWE mappings get external/cwe tags on the rule entry."""
        sarif = to_sarif(_report([_finding(rule="eval-usage", severity=Severity.CRITICAL,
                                           category=Category.SECURITY)]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        tags = rules[0]["properties"]["tags"]
        assert any("cwe-95" in t for t in tags)

    def test_known_rule_has_taxa_on_result(self):
        """Results for CWE-mapped rules have taxa references."""
        sarif = to_sarif(_report([_finding(rule="sql-injection-execute",
                                           severity=Severity.CRITICAL,
                                           category=Category.SECURITY)]))
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert result["taxa"][0]["toolComponent"]["name"] == "cwe"
        assert result["taxa"][0]["id"] == "89"

    def test_unknown_rule_no_taxa(self):
        """Rules without CWE mappings do not have taxa references."""
        sarif = to_sarif(_report([_finding(rule="custom-rule-xyz")]))
        result = sarif["runs"][0]["results"][0]
        assert "taxa" not in result

    def test_unknown_rule_empty_tags(self):
        """Rules without CWE mappings have empty tags list."""
        sarif = to_sarif(_report([_finding(rule="custom-rule-xyz")]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["tags"] == []

    def test_multiple_cwe_rules_dedup(self):
        """Multiple findings with the same rule produce one rule entry."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", line=1, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
            _finding(rule="eval-usage", line=20, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
        ]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) == 2


# ─── Empty / edge cases ──────────────────────────────────────────────


class TestSarifEdgeCases:
    def test_empty_report_valid_structure(self):
        """Empty report produces valid SARIF with no results or rules."""
        report = ScanReport(root="/project", mode="quick",
                            files_scanned=0, files_skipped=0)
        sarif = to_sarif(report)
        run = sarif["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        # Still valid JSON
        json.dumps(sarif)

    def test_finding_without_snippet(self):
        """Finding with no snippet still produces valid location."""
        sarif = to_sarif(_report([_finding(snippet=None)]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        region = loc["region"]
        assert region["startLine"] == 10
        # snippet may or may not be present depending on to_dict behavior

    def test_finding_without_suggestion_no_fixes(self):
        """Finding with no suggestion has no fixes key."""
        sarif = to_sarif(_report([_finding(suggestion=None)]))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" not in result

    def test_finding_with_suggestion_has_fixes(self):
        """Finding with suggestion produces fixes entry."""
        sarif = to_sarif(_report([_finding(suggestion="Use X instead")]))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Use X instead"

    def test_run_properties_reflect_report(self):
        """Run properties contain mode and file counts from the report."""
        report = ScanReport(root="/p", mode="deep",
                            files_scanned=42, files_skipped=7)
        sarif = to_sarif(report)
        props = sarif["runs"][0]["properties"]
        assert props["mode"] == "deep"
        assert props["filesScanned"] == 42
        assert props["filesSkipped"] == 7

    def test_partial_fingerprint_format(self):
        """Partial fingerprint follows file:rule:line format."""
        sarif = to_sarif(_report([_finding(rule="bare-except", line=33)]))
        fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        assert fp == "app.py:bare-except:33"

    def test_artifact_location_uses_srcroot_base(self):
        """Artifact location uses %SRCROOT% as uriBaseId."""
        sarif = to_sarif(_report([_finding()]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_llm_confidence_in_properties(self):
        """LLM findings have confidence in result properties."""
        sarif = to_sarif(_report([
            _finding(source=Source.LLM, confidence=Confidence.HIGH),
        ]))
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["confidence"] == "high"

    def test_severity_mapping_complete(self):
        """All three severity levels map correctly."""
        sarif = to_sarif(_report([
            _finding(rule="r1", severity=Severity.CRITICAL, line=1),
            _finding(rule="r2", severity=Severity.WARNING, line=2),
            _finding(rule="r3", severity=Severity.INFO, line=3),
        ]))
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
        assert levels == {"r1": "error", "r2": "warning", "r3": "note"}
