"""Tests for wiz/report.py — SARIF, JSON, ANSI console output."""

import json
import sys
import pytest
from io import StringIO
from unittest.mock import patch

from wiz.config import (
    Finding, FileAnalysis, ScanReport, FixReport, Fix,
    Severity, Category, Source, Confidence, FixSource, FixStatus,
)
from wiz.report import (
    to_sarif, print_sarif, print_json, print_report,
    print_finding, print_file_analysis, print_scan_summary,
    print_fix_report, print_fix_json, _c,
)


def _make_finding(
    rule="test-rule", line=10, file="test.py",
    severity=Severity.WARNING, category=Category.BUG,
    source=Source.STATIC, message="Test message",
    suggestion=None, snippet=None, confidence=None,
):
    return Finding(
        file=file, line=line, severity=severity,
        category=category, source=source, rule=rule,
        message=message, suggestion=suggestion,
        snippet=snippet, confidence=confidence,
    )


def _make_report(findings_data=None):
    """Build a ScanReport from a list of (rule, severity, category, source, confidence) tuples."""
    if findings_data is None:
        findings_data = [
            ("rule1", Severity.CRITICAL, Category.SECURITY, Source.STATIC, None),
            ("rule2", Severity.WARNING, Category.BUG, Source.AST, None),
            ("rule3", Severity.INFO, Category.STYLE, Source.LLM, Confidence.HIGH),
        ]
    findings = []
    for i, (rule, sev, cat, src, conf) in enumerate(findings_data, 1):
        findings.append(_make_finding(
            rule=rule, line=i * 10, severity=sev,
            category=cat, source=src, confidence=conf,
            message=f"Issue from {rule}", suggestion=f"Fix {rule}",
            snippet=f"code_{rule}",
        ))
    fa = FileAnalysis(
        path="test.py", language="python", lines=100,
        findings=findings,
    )
    return ScanReport(
        root="/project", mode="quick",
        files_scanned=1, files_skipped=0,
        total_findings=len(findings),
        critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        warnings=sum(1 for f in findings if f.severity == Severity.WARNING),
        info=sum(1 for f in findings if f.severity == Severity.INFO),
        file_analyses=[fa],
    )


# ─── SARIF output tests ──────────────────────────────────────────────


class TestToSarif:
    def test_sarif_basic_structure(self):
        """SARIF output has required top-level keys."""
        report = _make_report()
        sarif = to_sarif(report)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "Wiz"

    def test_sarif_results_count(self):
        """SARIF results match the number of findings."""
        report = _make_report()
        sarif = to_sarif(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_sarif_severity_mapping(self):
        """SARIF levels correctly map from our severities."""
        report = _make_report()
        sarif = to_sarif(report)
        results = sarif["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["rule1"] == "error"
        assert levels["rule2"] == "warning"
        assert levels["rule3"] == "note"

    def test_sarif_rules_section(self):
        """SARIF rules section has entries for each unique rule."""
        report = _make_report()
        sarif = to_sarif(report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"rule1", "rule2", "rule3"}

    def test_sarif_rule_properties(self):
        """Each SARIF rule has category and source in properties."""
        report = _make_report()
        sarif = to_sarif(report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "category" in rule["properties"]
            assert "source" in rule["properties"]

    def test_sarif_location(self):
        """SARIF results have correct location info."""
        report = _make_report()
        sarif = to_sarif(report)
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "test.py"
        assert loc["region"]["startLine"] == 10

    def test_sarif_snippet(self):
        """SARIF results include snippet when available."""
        report = _make_report()
        sarif = to_sarif(report)
        result = sarif["runs"][0]["results"][0]
        snippet = result["locations"][0]["physicalLocation"]["region"].get("snippet")
        assert snippet is not None
        assert snippet["text"] == "code_rule1"

    def test_sarif_suggestion_as_fix(self):
        """SARIF results include suggestion as fix."""
        report = _make_report()
        sarif = to_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Fix rule1"

    def test_sarif_confidence_property_merge(self):
        """REGRESSION: Confidence does not overwrite existing properties."""
        report = _make_report()
        sarif = to_sarif(report)
        # rule3 has Confidence.HIGH — its result should have confidence AND NOT lose other props
        llm_result = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "rule3"][0]
        props = llm_result.get("properties", {})
        assert props.get("confidence") == "high"
        # Non-LLM results should NOT have a confidence property
        static_result = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "rule1"][0]
        assert "properties" not in static_result or "confidence" not in static_result.get("properties", {})

    def test_sarif_confidence_preserves_existing_properties(self):
        """REGRESSION: When confidence is added, it merges into existing properties dict."""
        # Create a finding with confidence that will also have fixes (which creates properties)
        report = _make_report([
            ("llm-rule", Severity.WARNING, Category.BUG, Source.LLM, Confidence.MEDIUM),
        ])
        sarif = to_sarif(report)
        result = sarif["runs"][0]["results"][0]
        # Should have confidence in properties
        assert result.get("properties", {}).get("confidence") == "medium"
        # Should also still have fixes (suggestion)
        assert "fixes" in result

    def test_sarif_partial_fingerprint(self):
        """SARIF results have partial fingerprints for dedup."""
        report = _make_report()
        sarif = to_sarif(report)
        result = sarif["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash" in result["partialFingerprints"]

    def test_sarif_json_serializable(self):
        """SARIF output is fully JSON-serializable."""
        report = _make_report()
        sarif = to_sarif(report)
        json_str = json.dumps(sarif, indent=2)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_sarif_empty_report(self):
        """SARIF output for report with no findings."""
        report = ScanReport(
            root="/project", mode="quick",
            files_scanned=0, files_skipped=0,
            total_findings=0, critical=0, warnings=0, info=0,
        )
        sarif = to_sarif(report)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_run_properties(self):
        """SARIF run properties include mode and file counts."""
        report = _make_report()
        sarif = to_sarif(report)
        run_props = sarif["runs"][0]["properties"]
        assert run_props["mode"] == "quick"
        assert run_props["filesScanned"] == 1
        assert run_props["filesSkipped"] == 0


# ─── JSON output tests ───────────────────────────────────────────────


class TestJsonOutput:
    def test_print_json_valid(self):
        """print_json outputs valid JSON."""
        report = _make_report()
        buf = StringIO()
        with patch("sys.stdout", buf):
            print_json(report)
        data = json.loads(buf.getvalue())
        assert "files" in data
        assert data["total_findings"] == 3

    def test_json_schema_keys(self):
        """JSON output contains all expected top-level keys."""
        report = _make_report()
        data = report.to_dict()
        expected_keys = {"root", "mode", "files_scanned", "files_skipped",
                         "total_findings", "critical", "warnings", "info",
                         "llm_cost_usd", "timestamp", "files"}
        assert expected_keys.issubset(set(data.keys()))

    def test_json_findings_structure(self):
        """Each finding in JSON has all required fields."""
        report = _make_report()
        data = report.to_dict()
        for file_data in data["files"]:
            for finding in file_data["findings"]:
                assert "file" in finding
                assert "line" in finding
                assert "severity" in finding
                assert "rule" in finding
                assert "message" in finding


# ─── Console output tests ────────────────────────────────────────────


class TestConsoleOutput:
    def test_c_no_color_on_pipe(self):
        """_c returns plain text when stdout is not a TTY."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            result = _c("red", "text")
        assert result == "text"
        assert "\033[" not in result

    def test_print_finding_output(self):
        """print_finding outputs the finding's message and location."""
        f = _make_finding(message="Found a bug", suggestion="Fix it", snippet="bad_code()")
        buf = StringIO()
        with patch("sys.stdout", buf):
            # Force non-TTY for clean output
            buf.isatty = lambda: False
            print_finding(f)
        output = buf.getvalue()
        assert "Found a bug" in output
        assert "test.py:10" in output
        assert "Fix it" in output

    def test_print_report_shows_all_files(self):
        """print_report shows all file analyses."""
        report = _make_report()
        buf = StringIO()
        with patch("sys.stdout", buf):
            buf.isatty = lambda: False
            print_report(report)
        output = buf.getvalue()
        assert "test.py" in output
        assert "Scan Complete" in output

    def test_print_scan_summary_counts(self):
        """print_scan_summary shows correct finding counts."""
        report = _make_report()
        buf = StringIO()
        with patch("sys.stdout", buf):
            buf.isatty = lambda: False
            print_scan_summary(report)
        output = buf.getvalue()
        assert "Critical:" in output
        assert "Warnings:" in output
        assert "Info:" in output
        assert "Files scanned:  1" in output


# ─── Fix report tests ────────────────────────────────────────────────


class TestFixReportOutput:
    def test_print_fix_report_empty(self):
        """print_fix_report handles report with no fixes."""
        report = FixReport(
            root="test.py", files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )
        buf = StringIO()
        with patch("sys.stdout", buf):
            buf.isatty = lambda: False
            print_fix_report(report, dry_run=True)
        output = buf.getvalue()
        assert "No fixable issues found" in output

    def test_print_fix_report_with_fixes(self):
        """print_fix_report renders applied/skipped/failed counts."""
        fixes = [
            Fix(file="test.py", line=1, rule="unused-import",
                original_code="import os\n", fixed_code="",
                explanation="Removed unused import",
                source=FixSource.DETERMINISTIC, status=FixStatus.APPLIED),
            Fix(file="test.py", line=5, rule="bare-except",
                original_code="except:\n", fixed_code="except Exception:\n",
                explanation="Replaced bare except",
                source=FixSource.DETERMINISTIC, status=FixStatus.SKIPPED),
        ]
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=2,
            applied=1, skipped=1, failed=0, fixes=fixes,
        )
        buf = StringIO()
        with patch("sys.stdout", buf):
            buf.isatty = lambda: False
            print_fix_report(report, dry_run=False)
        output = buf.getvalue()
        assert "1 applied" in output
        assert "1 skipped" in output
        assert "APPLIED" in output

    def test_print_fix_json(self):
        """print_fix_json outputs valid JSON."""
        report = FixReport(
            root="test.py", files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )
        buf = StringIO()
        with patch("sys.stdout", buf):
            print_fix_json(report)
        data = json.loads(buf.getvalue())
        assert "total_fixes" in data
        assert "fixes" in data
