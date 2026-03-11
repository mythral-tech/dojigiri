"""Tests for dojigiri/mcp_format.py — MCP plain-text formatting."""

import pytest
from dataclasses import dataclass, field

from dojigiri.mcp_format import (
    _finding_line,
    _cross_finding_line,
    _format_section,
    _normalize_graph_nodes,
    format_scan_report,
    format_file_findings,
    format_fix_report,
    format_explanation,
    format_project_analysis,
)
from dojigiri.types import (
    Category,
    CrossFileFinding,
    Finding,
    Fix,
    FixReport,
    FixSource,
    ProjectAnalysis,
    ScanReport,
    Severity,
    Source,
)


def _make_finding(severity=Severity.WARNING, suggestion=None, rule="test-rule"):
    return Finding(
        file="test.py", line=10, severity=severity,
        category=Category.BUG, source=Source.STATIC,
        rule=rule, message="Test issue", suggestion=suggestion,
    )


def _make_cf(suggestion=None, target_line=None):
    return CrossFileFinding(
        source_file="a.py", target_file="b.py", line=5,
        target_line=target_line, severity=Severity.WARNING,
        category=Category.BUG, rule="cross-rule",
        message="Cross issue", suggestion=suggestion,
    )


# ─── Helpers ─────────────────────────────────────────────────────────


class TestFindingLine:
    def test_basic(self):
        result = _finding_line(_make_finding())
        assert "test.py:10" in result
        assert "[test-rule]" in result

    def test_with_suggestion(self):
        result = _finding_line(_make_finding(suggestion="Fix this"))
        assert "-> Fix this" in result


class TestCrossFileLine:
    def test_with_target_line(self):
        result = _cross_finding_line(_make_cf(target_line=20))
        assert "a.py:5" in result
        assert "b.py:20" in result

    def test_without_target_line(self):
        result = _cross_finding_line(_make_cf())
        assert "-> b.py" in result

    def test_with_suggestion(self):
        result = _cross_finding_line(_make_cf(suggestion="Fix cross"))
        assert "-> Fix cross" in result


class TestFormatSection:
    def test_basic(self):
        @dataclass
        class FakeSection:
            title: str = "Imports"
            content: str = "Uses os and sys"
            code_snippet: str = ""
        result = _format_section(FakeSection())
        assert "Imports" in result

    def test_with_code_snippet(self):
        @dataclass
        class FakeSection:
            title: str = "Example"
            content: str = "Shows usage"
            code_snippet: str = "import os\nimport sys\n"
        result = _format_section(FakeSection())
        assert "| import os" in result


class TestNormalizeGraphNodes:
    def test_dict_input(self):
        nodes = {"a.py": {"language": "python", "fan_in": 3}}
        result = _normalize_graph_nodes(nodes)
        assert len(result) == 1
        assert result[0]["path"] == "a.py"
        assert result[0]["fan_in"] == 3

    def test_list_input(self):
        nodes = [{"path": "a.py", "fan_in": 2}]
        result = _normalize_graph_nodes(nodes)
        assert result == nodes


# ─── format_scan_report ──────────────────────────────────────────────


class TestFormatScanReport:
    def test_no_findings(self):
        @dataclass
        class FakeFileAnalysis:
            findings: list = field(default_factory=list)

        @dataclass
        class FakeReport:
            root: str = "/project"
            files_scanned: int = 5
            mode: str = "fast"
            critical: int = 0
            warnings: int = 0
            info: int = 0
            total_findings: int = 0
            file_analyses: list = field(default_factory=list)

        result = format_scan_report(FakeReport())
        assert "No issues found" in result

    def test_with_findings(self):
        @dataclass
        class FakeFileAnalysis:
            findings: list = field(default_factory=list)

        fa = FakeFileAnalysis(findings=[_make_finding(Severity.CRITICAL)])

        @dataclass
        class FakeReport:
            root: str = "/project"
            files_scanned: int = 1
            mode: str = "deep"
            critical: int = 1
            warnings: int = 0
            info: int = 0
            total_findings: int = 1
            file_analyses: list = field(default_factory=list)

        report = FakeReport(file_analyses=[fa])
        result = format_scan_report(report)
        assert "CRITICAL" in result
        assert "test.py:10" in result

    def test_truncation(self):
        @dataclass
        class FakeFileAnalysis:
            findings: list = field(default_factory=list)

        findings = [_make_finding(Severity.WARNING) for _ in range(60)]
        fa = FakeFileAnalysis(findings=findings)

        @dataclass
        class FakeReport:
            root: str = "/project"
            files_scanned: int = 1
            mode: str = "fast"
            critical: int = 0
            warnings: int = 60
            info: int = 0
            total_findings: int = 60
            file_analyses: list = field(default_factory=list)

        report = FakeReport(file_analyses=[fa])
        result = format_scan_report(report, max_findings=5)
        assert "more" in result


# ─── format_file_findings ────────────────────────────────────────────


class TestFormatFileFindings:
    def test_no_findings(self):
        result = format_file_findings("test.py", "python", 100, [])
        assert "No issues found" in result

    def test_with_findings(self):
        findings = [_make_finding(Severity.CRITICAL), _make_finding(Severity.INFO)]
        result = format_file_findings("test.py", "python", 100, findings)
        assert "1 critical" in result
        assert "1 info" in result


# ─── format_fix_report ──────────────────────────────────────────────


class TestFormatFixReport:
    def test_no_fixes(self):
        report = FixReport(root="/project", files_fixed=0, total_fixes=0,
                           applied=0, skipped=0, failed=0, fixes=[], verification=None)
        result = format_fix_report(report)
        assert "No fixes available" in result

    def test_with_fixes(self):
        fix = Fix(
            file="test.py", line=5, rule="test-rule",
            original_code="x == None", fixed_code="x is None",
            explanation="Use is None", source=FixSource.DETERMINISTIC,
        )
        report = FixReport(root="/project", files_fixed=1, total_fixes=1,
                           applied=1, skipped=0, failed=0, fixes=[fix], verification=None)
        result = format_fix_report(report)
        assert "- x == None" in result
        assert "+ x is None" in result
        assert "Note: Use is None" in result

    def test_with_verification(self):
        fix = Fix(
            file="test.py", line=5, rule="test-rule",
            original_code="old", fixed_code="new",
            explanation="fix", source=FixSource.DETERMINISTIC,
        )
        report = FixReport(
            root="/project", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0, fixes=[fix],
            verification={"resolved": 3, "remaining": 1, "new_issues": 0},
        )
        result = format_fix_report(report)
        assert "3 resolved" in result


# ─── format_explanation ─────────────────────────────────────────────


class TestFormatExplanation:
    def test_basic(self):
        @dataclass
        class FakeSection:
            title: str
            content: str
            code_snippet: str = ""

        @dataclass
        class FakeExplanation:
            filepath: str = "test.py"
            language: str = "python"
            summary: str = "A test file"
            structure: list = field(default_factory=list)
            patterns: list = field(default_factory=list)
            findings_explained: list = field(default_factory=list)
            learning_notes: list = field(default_factory=list)

        explanation = FakeExplanation(
            structure=[FakeSection("Imports", "Uses os")],
            learning_notes=["Use pathlib instead of os.path"],
        )
        result = format_explanation(explanation)
        assert "test.py" in result
        assert "A test file" in result
        assert "Structure:" in result
        assert "Learning notes:" in result
        assert "Use pathlib" in result


# ─── format_project_analysis ─────────────────────────────────────────


class TestFormatProjectAnalysis:
    def test_minimal(self):
        @dataclass
        class FakeAnalysis:
            root: str = "/project"
            files_analyzed: int = 10
            graph_metrics: dict = field(default_factory=dict)
            dependency_graph: dict = None
            per_file_findings: list = field(default_factory=list)
            cross_file_findings: list = field(default_factory=list)
            synthesis: dict = None

        result = format_project_analysis(FakeAnalysis())
        assert "/project" in result
        assert "10 files" in result

    def test_with_graph_metrics(self):
        @dataclass
        class FakeAnalysis:
            root: str = "/project"
            files_analyzed: int = 5
            graph_metrics: dict = field(default_factory=dict)
            dependency_graph: dict = None
            per_file_findings: list = field(default_factory=list)
            cross_file_findings: list = field(default_factory=list)
            synthesis: dict = None

        analysis = FakeAnalysis(graph_metrics={"complexity": "high"})
        result = format_project_analysis(analysis)
        assert "complexity: high" in result

    def test_with_dependency_graph(self):
        @dataclass
        class FakeAnalysis:
            root: str = "/project"
            files_analyzed: int = 5
            graph_metrics: dict = field(default_factory=dict)
            dependency_graph: dict = None
            per_file_findings: list = field(default_factory=list)
            cross_file_findings: list = field(default_factory=list)
            synthesis: dict = None

        analysis = FakeAnalysis(dependency_graph={
            "nodes": {"a.py": {"language": "python", "fan_in": 5}},
            "circular_deps": [["a.py", "b.py", "a.py"]],
        })
        result = format_project_analysis(analysis)
        assert "1 modules" in result
        assert "Circular" in result
        assert "Most depended-on" in result

    def test_with_synthesis(self):
        @dataclass
        class FakeAnalysis:
            root: str = "/project"
            files_analyzed: int = 5
            graph_metrics: dict = field(default_factory=dict)
            dependency_graph: dict = None
            per_file_findings: list = field(default_factory=list)
            cross_file_findings: list = field(default_factory=list)
            synthesis: dict = None

        analysis = FakeAnalysis(synthesis={
            "overview": "Clean codebase",
            "recommendations": ["Add tests", "Fix warnings"],
        })
        result = format_project_analysis(analysis)
        assert "Synthesis:" in result
        assert "overview: Clean codebase" in result
        assert "- Add tests" in result
