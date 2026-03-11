"""Extended tests for dojigiri/report.py — targeting uncovered rendering functions.

Covers: print_scan_summary (LLM cost, models, category breakdown, no files),
print_debug_result, print_optimize_result, print_analysis_json,
print_cost_estimate, print_setup_status, print_graph_summary,
print_cross_file_finding, print_project_analysis, print_project_json,
print_explanation, print_explain_json, print_pr_review, print_pr_review_json,
print_fix_report (verification, failed, LLM cost).
"""

import json
import sys
from dataclasses import dataclass, field
from io import StringIO
from unittest.mock import patch

import pytest

from dojigiri.types import (
    Category,
    Finding,
    FileAnalysis,
    Fix,
    FixReport,
    FixSource,
    FixStatus,
    ProjectAnalysis,
    ScanReport,
    Severity,
    Source,
)
from dojigiri.report import (
    _c,
    _print_debug_finding,
    _print_llm_analysis_result,
    print_analysis_json,
    print_cost_estimate,
    print_cross_file_finding,
    print_debug_result,
    print_explanation,
    print_explain_json,
    print_fix_report,
    print_graph_summary,
    print_optimize_result,
    print_pr_review,
    print_pr_review_json,
    print_project_analysis,
    print_project_json,
    print_report,
    print_scan_summary,
    print_setup_status,
)


def _f(rule="test-rule", line=10, severity=Severity.WARNING, category=Category.BUG,
       message="Test msg", suggestion=None, snippet=None):
    return Finding(
        file="test.py", line=line, severity=severity,
        category=category, source=Source.STATIC, rule=rule,
        message=message, suggestion=suggestion, snippet=snippet,
    )


def _capture(fn, *args, **kwargs):
    """Capture stdout from a function call."""
    buf = StringIO()
    buf.isatty = lambda: False
    with patch("sys.stdout", buf):
        fn(*args, **kwargs)
    return buf.getvalue()


# ─── print_scan_summary extended ──────────────────────────────────────


class TestScanSummaryExtended:
    def test_no_files_scanned(self):
        report = ScanReport(root="/p", mode="quick", files_scanned=0, files_skipped=0)
        out = _capture(print_scan_summary, report)
        assert "No supported files found" in out
        assert "doji init" in out

    def test_with_duration(self):
        report = ScanReport(root="/p", mode="quick", files_scanned=1, files_skipped=0)
        out = _capture(print_scan_summary, report, duration=2.5)
        assert "2.5s" in out

    def test_with_classification(self):
        report = ScanReport(root="/p", mode="quick", files_scanned=1, files_skipped=0)
        out = _capture(print_scan_summary, report, classification="CONFIDENTIAL")
        assert "CONFIDENTIAL" in out

    def test_category_breakdown(self):
        fa = FileAnalysis(
            path="x.py", language="python", lines=10,
            findings=[
                _f(category=Category.SECURITY),
                _f(category=Category.PERFORMANCE),
                _f(category=Category.SECURITY),
            ],
        )
        report = ScanReport(root="/p", mode="quick", files_scanned=1, files_skipped=0,
                            file_analyses=[fa])
        out = _capture(print_scan_summary, report)
        assert "Security: 2" in out
        assert "Performance: 1" in out

    def test_llm_cost_display(self):
        report = ScanReport(root="/p", mode="deep", files_scanned=1, files_skipped=0,
                            llm_cost_usd=0.0123)
        out = _capture(print_scan_summary, report)
        assert "$0.0123" in out
        assert "AI-generated" in out

    def test_llm_models_used_short_names(self):
        report = ScanReport(
            root="/p", mode="deep", files_scanned=1, files_skipped=0,
            llm_cost_usd=0.01,
            llm_models_used=["claude-haiku-4-20250514", "gpt-4"],
        )
        out = _capture(print_scan_summary, report)
        assert "claude-haiku-4" in out
        assert "gpt-4" in out


# ─── print_report extended ────────────────────────────────────────────


class TestPrintReportExtended:
    def test_cross_file_findings(self):
        @dataclass
        class FakeCFF:
            severity: Severity = Severity.WARNING
            def to_dict(self):
                return {"severity": "warning", "rule": "clone", "source_file": "a.py",
                        "target_file": "b.py", "line": 5, "message": "dup"}

        report = ScanReport(root="/p", mode="quick", files_scanned=1, files_skipped=0,
                            cross_file_findings=[FakeCFF()])
        out = _capture(print_report, report)
        assert "Cross-file" in out


# ─── Debug/Optimize result ───────────────────────────────────────────


class TestDebugOptimizeResult:
    def test_debug_result_no_llm(self):
        out = _capture(print_debug_result, "test.py", [_f()], None)
        assert "Debug: test.py" in out

    def test_debug_result_with_raw_markdown(self):
        out = _capture(print_debug_result, "test.py", [], {"raw_markdown": "## Analysis\nLooks good."})
        assert "Claude analysis" in out
        assert "Looks good" in out

    def test_debug_result_with_structured(self):
        llm = {
            "summary": "Found issues",
            "findings": [
                {"severity": "critical", "confidence": "high", "title": "SQL Injection",
                 "line": 5, "category": "security", "description": "Bad query",
                 "suggestion": "Use params", "code_fix": "fixed_code()"},
            ],
            "quick_wins": ["Add input validation"],
        }
        out = _capture(print_debug_result, "test.py", [], llm)
        assert "Found issues" in out
        assert "SQL Injection" in out
        assert "Add input validation" in out

    def test_debug_result_empty_llm(self):
        out = _capture(print_debug_result, "test.py", [], {"summary": "", "findings": [], "quick_wins": []})
        assert "No additional issues" in out

    def test_optimize_result_filters_categories(self):
        findings = [
            _f(category=Category.PERFORMANCE, message="slow"),
            _f(category=Category.BUG, message="bug"),
        ]
        out = _capture(print_optimize_result, "test.py", findings, None)
        assert "slow" in out
        # BUG category should be filtered out
        assert "bug" not in out

    def test_optimize_with_structured(self):
        llm = {
            "summary": "Well optimized",
            "findings": [
                {"severity": "info", "confidence": "medium", "title": "N+1 query",
                 "line": 10, "category": "performance", "description": "Loop query"},
            ],
            "quick_wins": [],
        }
        out = _capture(print_optimize_result, "test.py", [], llm)
        assert "Assessment:" in out
        assert "N+1 query" in out


# ─── Analysis JSON ───────────────────────────────────────────────────


class TestAnalysisJson:
    def test_basic(self):
        out = _capture(print_analysis_json, "test.py", [_f()], None)
        data = json.loads(out)
        assert data["filepath"] == "test.py"
        assert len(data["static_findings"]) == 1

    def test_with_cost_tracker(self):
        class FakeTracker:
            total_cost = 0.005
        out = _capture(print_analysis_json, "test.py", [], {"x": 1}, FakeTracker())
        data = json.loads(out)
        assert data["cost_usd"] == 0.005


# ─── Cost estimate ───────────────────────────────────────────────────


class TestCostEstimate:
    def test_basic(self):
        out = _capture(print_cost_estimate, 1000, 5, 50000, 0.05)
        assert "Cost Estimate" in out
        assert "1,000" in out
        assert "$0.0500" in out


# ─── Setup status ────────────────────────────────────────────────────


class TestSetupStatus:
    def test_all_ready(self):
        out = _capture(print_setup_status, True, True)
        assert "set" in out
        assert "installed" in out
        assert "ready" in out

    def test_nothing_ready(self):
        out = _capture(print_setup_status, False, False)
        assert "not set" in out
        assert "not installed" in out
        assert "not ready" in out


# ─── Graph summary ───────────────────────────────────────────────────


class TestGraphSummary:
    def test_basic_graph(self):
        graph = {"nodes": {"a.py": {"fan_in": 2, "fan_out": 1, "imports": ["b.py"], "is_hub": False}}}
        metrics = {
            "total_files": 2, "total_edges": 1, "coupling_score": 0.5,
            "avg_fan_in": 1.0, "avg_fan_out": 1.0,
            "max_fan_in": ["a.py", 2], "max_fan_out": ["a.py", 1],
        }
        out = _capture(print_graph_summary, graph, metrics)
        assert "Dependency Graph" in out
        assert "a.py" in out

    def test_with_hubs_cycles_dead(self):
        graph = {"nodes": {"hub.py": {"fan_in": 10, "fan_out": 10, "imports": ["a.py"] * 6, "is_hub": True}}}
        metrics = {
            "total_files": 5, "total_edges": 10, "coupling_score": 0.8,
            "avg_fan_in": 2.0, "avg_fan_out": 2.0,
            "max_fan_in": ["hub.py", 10], "max_fan_out": ["hub.py", 10],
            "hub_files": ["hub.py"],
            "circular_deps": [["a.py", "b.py", "a.py"]],
            "dead_modules": ["orphan.py"],
            "entry_points": ["main.py"],
        }
        out = _capture(print_graph_summary, graph, metrics)
        assert "Hub files" in out
        assert "Circular" in out
        assert "orphan.py" in out
        assert "main.py" in out
        assert "[HUB]" in out


# ─── Cross-file finding ──────────────────────────────────────────────


class TestCrossFileFinding:
    def test_basic(self):
        cf = {"severity": "warning", "rule": "clone", "source_file": "a.py",
              "target_file": "b.py", "line": 5, "target_line": 10,
              "message": "Duplicate code", "suggestion": "Extract method"}
        out = _capture(print_cross_file_finding, cf)
        assert "a.py:5" in out
        assert "b.py:10" in out
        assert "Duplicate code" in out
        assert "Extract method" in out

    def test_no_target_line(self):
        cf = {"severity": "critical", "rule": "dep", "source_file": "x.py",
              "target_file": "y.py", "line": 1, "message": "Circular"}
        out = _capture(print_cross_file_finding, cf)
        assert "x.py:1" in out
        assert "y.py" in out


# ─── Project analysis ────────────────────────────────────────────────


class TestProjectAnalysis:
    def test_full_project_analysis(self):
        analysis = ProjectAnalysis(
            root="/project",
            dependency_graph={"nodes": {}},
            graph_metrics={"total_files": 0, "total_edges": 0, "coupling_score": 0,
                           "avg_fan_in": 0, "avg_fan_out": 0, "max_fan_in": ["", 0],
                           "max_fan_out": ["", 0]},
            cross_file_findings=[],
            files_analyzed=5,
            synthesis={
                "architecture_summary": "Well structured",
                "health_score": 8,
                "architectural_issues": [
                    {"severity": "warning", "title": "God file", "description": "Too big",
                     "affected_files": ["big.py"], "suggestion": "Split it"},
                ],
                "positive_patterns": ["Good separation of concerns"],
                "recommendations": [
                    {"priority": "high", "title": "Add tests", "description": "Coverage low"},
                    {"priority": "low", "title": "Add docs"},
                ],
            },
            llm_cost_usd=0.01,
        )
        out = _capture(print_project_analysis, analysis)
        assert "Project Analysis" in out
        assert "Well structured" in out
        assert "8/10" in out
        assert "God file" in out
        assert "Good separation" in out
        assert "Add tests" in out

    def test_project_no_cross_file(self):
        analysis = ProjectAnalysis(
            root="/p", dependency_graph={"nodes": {}},
            graph_metrics={"total_files": 0, "total_edges": 0, "coupling_score": 0,
                           "avg_fan_in": 0, "avg_fan_out": 0, "max_fan_in": ["", 0],
                           "max_fan_out": ["", 0]},
            cross_file_findings=[], files_analyzed=1,
        )
        out = _capture(print_project_analysis, analysis)
        assert "No cross-file issues" in out


class TestProjectJson:
    def test_outputs_valid_json(self):
        analysis = ProjectAnalysis(
            root="/p", dependency_graph={}, graph_metrics={},
            cross_file_findings=[], files_analyzed=1,
        )
        out = _capture(print_project_json, analysis)
        data = json.loads(out)
        assert data["root"] == "/p"


# ─── Explanation output ──────────────────────────────────────────────


@dataclass
class _Section:
    title: str = "Section"
    content: str = "Content"
    code_snippet: str | None = None


@dataclass
class _FakeExplanation:
    filepath: str = "test.py"
    language: str = "python"
    summary: str = "A test file"
    structure: list = field(default_factory=list)
    patterns: list = field(default_factory=list)
    findings_explained: list = field(default_factory=list)
    learning_notes: list = field(default_factory=list)


class TestExplanation:
    def test_full_explanation(self):
        exp = _FakeExplanation(
            structure=[_Section(title="Functions", content="Two functions", code_snippet="def foo(): ...")],
            patterns=[_Section(title="Singleton", content="Uses singleton pattern")],
            findings_explained=[_Section(title="Eval usage", content="Found eval call", code_snippet="eval(x)")],
            learning_notes=["Learn about eval risks", "Use ast.literal_eval"],
        )
        out = _capture(print_explanation, exp)
        assert "test.py" in out
        assert "A test file" in out
        assert "Functions" in out
        assert "Singleton" in out
        assert "Eval usage" in out
        assert "Learn about eval" in out

    def test_explain_json(self):
        exp = _FakeExplanation(
            structure=[_Section()],
            patterns=[_Section()],
            findings_explained=[_Section()],
            learning_notes=["Note"],
        )
        out = _capture(print_explain_json, exp)
        data = json.loads(out)
        assert data["filepath"] == "test.py"
        assert data["language"] == "python"
        assert len(data["learning_notes"]) == 1


# ─── PR review output ────────────────────────────────────────────────


class TestPRReviewOutput:
    def _make_review(self, *, findings=None, llm_analysis=None):
        from dojigiri.pr_review import FileReview, PRReview
        fr_list = []
        if findings:
            fr = FileReview(path="api.py", findings=findings, llm_analysis=llm_analysis)
            fr_list = [fr]
        return PRReview(
            base_ref="main", risk_level="High",
            file_reviews=fr_list,
            summary="test",
            llm_cost_usd=0.005,
        )

    def test_pr_review_no_findings(self):
        from dojigiri.pr_review import PRReview
        review = PRReview(base_ref="main", risk_level="Low")
        out = _capture(print_pr_review, review)
        assert "No security findings" in out

    def test_pr_review_with_static_findings(self):
        review = self._make_review(findings=[
            _f(severity=Severity.CRITICAL, message="eval found"),
            _f(severity=Severity.WARNING, message="weak hash"),
        ])
        out = _capture(print_pr_review, review)
        assert "api.py" in out
        assert "eval found" in out

    def test_pr_review_with_llm_analysis(self):
        review = self._make_review(
            findings=[_f(severity=Severity.CRITICAL)],
            llm_analysis=[
                {"severity": "critical", "title": "SQL Injection", "line": 5,
                 "snippet": "query = f\"SELECT ...\"", "risk": "Full DB access",
                 "fix": "Use parameterized queries"},
            ],
        )
        out = _capture(print_pr_review, review)
        assert "SQL Injection" in out
        assert "Full DB access" in out
        assert "parameterized" in out

    def test_pr_review_json(self):
        from dojigiri.pr_review import PRReview
        review = PRReview(base_ref="main", risk_level="Low")
        out = _capture(print_pr_review_json, review)
        data = json.loads(out)
        assert data["risk_level"] == "Low"

    def test_pr_review_llm_cost(self):
        review = self._make_review(findings=[_f()])
        out = _capture(print_pr_review, review)
        assert "$0.0050" in out


# ─── Fix report extended ─────────────────────────────────────────────


class TestFixReportExtended:
    def test_fix_report_with_verification(self):
        fix = Fix(
            file="test.py", line=1, rule="bare-except",
            original_code="except:\n", fixed_code="except Exception:\n",
            explanation="Fixed", source=FixSource.DETERMINISTIC,
            status=FixStatus.APPLIED,
        )
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            fixes=[fix],
            verification={"resolved": 1, "remaining": 0, "new_issues": 0},
        )
        out = _capture(print_fix_report, report, dry_run=False)
        assert "Verification" in out
        assert "resolved" in out

    def test_fix_report_verification_with_new_issues(self):
        fix = Fix(
            file="test.py", line=1, rule="r",
            original_code="x\n", fixed_code="y\n",
            explanation="e", source=FixSource.DETERMINISTIC,
            status=FixStatus.APPLIED,
        )
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            fixes=[fix],
            verification={
                "resolved": 1, "remaining": 0, "new_issues": 2,
                "new_findings": [
                    {"line": 5, "rule": "bug", "message": "new bug"},
                    {"line": 10, "rule": "bug2", "message": "another"},
                ],
            },
        )
        out = _capture(print_fix_report, report, dry_run=False)
        assert "New issues introduced: 2" in out

    def test_fix_report_verification_error(self):
        fix = Fix(
            file="test.py", line=1, rule="r",
            original_code="x\n", fixed_code="y\n",
            explanation="e", source=FixSource.DETERMINISTIC,
            status=FixStatus.APPLIED,
        )
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            fixes=[fix],
            verification={"error": "Could not re-read file"},
        )
        out = _capture(print_fix_report, report, dry_run=False)
        assert "Could not re-read" in out

    def test_fix_report_with_llm_cost(self):
        fix = Fix(
            file="test.py", line=1, rule="r",
            original_code="x\n", fixed_code="y\n",
            explanation="e", source=FixSource.DETERMINISTIC,
            status=FixStatus.APPLIED,
        )
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            fixes=[fix],
            llm_cost_usd=0.003,
        )
        out = _capture(print_fix_report, report, dry_run=False)
        assert "$0.003" in out

    def test_fix_report_failed_fix_with_reason(self):
        fix = Fix(
            file="test.py", line=1, rule="eval-usage",
            original_code="eval(x)\n", fixed_code="ast.literal_eval(x)\n",
            explanation="Safe eval", source=FixSource.DETERMINISTIC,
            status=FixStatus.FAILED, fail_reason="syntax error after fix",
        )
        report = FixReport(
            root="test.py", files_fixed=0, total_fixes=1,
            applied=0, skipped=0, failed=1, fixes=[fix],
        )
        out = _capture(print_fix_report, report, dry_run=False)
        assert "syntax error" in out

    def test_fix_report_deletion_fix(self):
        fix = Fix(
            file="test.py", line=1, rule="unused-import",
            original_code="import os\n", fixed_code="",
            explanation="Removed", source=FixSource.DETERMINISTIC,
            status=FixStatus.APPLIED,
        )
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0, fixes=[fix],
        )
        out = _capture(print_fix_report, report, dry_run=True)
        assert "(removed)" in out


# ─── _print_debug_finding ────────────────────────────────────────────


class TestPrintDebugFinding:
    def test_end_line_range(self):
        f = {"severity": "warning", "confidence": "low", "title": "Issue",
             "line": 5, "end_line": 10, "category": "bug"}
        out = _capture(_print_debug_finding, f, 1)
        assert "line 5-10" in out

    def test_unknown_confidence(self):
        f = {"severity": "info", "confidence": "unknown", "title": "X",
             "line": 1, "category": "style"}
        out = _capture(_print_debug_finding, f, 1)
        assert "X" in out
