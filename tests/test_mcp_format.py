"""Tests for MCP output formatting — no MCP dependency needed."""

import pytest
from wiz.config import (
    Finding, FileAnalysis, ScanReport, FixReport, Fix,
    ProjectAnalysis, CrossFileFinding,
    Severity, Category, Source, FixSource, FixStatus,
)
from wiz.semantic.explain import FileExplanation, ExplainSection
from wiz.mcp_format import (
    format_scan_report,
    format_file_findings,
    format_fix_report,
    format_explanation,
    format_project_analysis,
)


# ─── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def critical_finding():
    return Finding(
        file="src/auth.py", line=42, severity=Severity.CRITICAL,
        category=Category.SECURITY, source=Source.STATIC,
        rule="taint-flow",
        message="User input `request.args[\"id\"]` flows to SQL query on line 58",
        suggestion='Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    )


@pytest.fixture
def warning_finding():
    return Finding(
        file="src/utils.py", line=23, severity=Severity.WARNING,
        category=Category.DEAD_CODE, source=Source.STATIC,
        rule="unused-variable",
        message="`temp_buffer` assigned but never read",
    )


@pytest.fixture
def info_finding():
    return Finding(
        file="src/utils.py", line=80, severity=Severity.INFO,
        category=Category.STYLE, source=Source.STATIC,
        rule="todo-marker",
        message="TODO comment found",
    )


@pytest.fixture
def sample_fix():
    return Fix(
        file="src/auth.py", line=88, rule="bare-except",
        original_code="except:",
        fixed_code="except Exception:",
        explanation="Bare except catches SystemExit and KeyboardInterrupt",
        source=FixSource.DETERMINISTIC,
    )


@pytest.fixture
def sample_explanation():
    return FileExplanation(
        filepath="src/auth.py",
        language="python",
        summary="Authentication module handling user login and session management.",
        structure=[
            ExplainSection(
                title="login()",
                content="Validates credentials and creates a session token.",
                code_snippet="def login(username, password):\n    ...",
            ),
        ],
        patterns=[
            ExplainSection(title="Singleton", content="Database connection uses singleton pattern."),
        ],
        findings_explained=[
            ExplainSection(title="taint-flow", content="User input reaches SQL without sanitization."),
        ],
        learning_notes=["Always parameterize SQL queries", "Use bcrypt for password hashing"],
    )


# ─── format_scan_report ──────────────────────────────────────────────

class TestFormatScanReport:
    def test_empty_report(self):
        report = ScanReport(
            root="/project", mode="quick", files_scanned=10,
            files_skipped=0, total_findings=0, critical=0, warnings=0, info=0,
        )
        result = format_scan_report(report)
        assert "No issues found" in result
        assert "/project" in result
        assert "10 files" in result

    def test_findings_sorted_by_severity(self, critical_finding, warning_finding, info_finding):
        report = ScanReport(
            root="/project", mode="quick", files_scanned=5,
            files_skipped=0, total_findings=3, critical=1, warnings=1, info=1,
            file_analyses=[
                FileAnalysis(
                    path="src/auth.py", language="python", lines=100,
                    findings=[critical_finding],
                ),
                FileAnalysis(
                    path="src/utils.py", language="python", lines=50,
                    findings=[warning_finding, info_finding],
                ),
            ],
        )
        result = format_scan_report(report)
        # Critical should appear before warning
        crit_pos = result.index("CRITICAL")
        warn_pos = result.index("WARNING")
        info_pos = result.index("INFO")
        assert crit_pos < warn_pos < info_pos

    def test_suggestion_shown(self, critical_finding):
        report = ScanReport(
            root="/project", mode="quick", files_scanned=1,
            files_skipped=0, total_findings=1, critical=1, warnings=0, info=0,
            file_analyses=[
                FileAnalysis(path="src/auth.py", language="python", lines=100,
                             findings=[critical_finding]),
            ],
        )
        result = format_scan_report(report)
        assert "->" in result
        assert "parameterized" in result

    def test_truncation_at_max_findings(self):
        findings = [
            Finding(
                file="big.py", line=i, severity=Severity.WARNING,
                category=Category.STYLE, source=Source.STATIC,
                rule="long-line", message=f"Line {i} too long",
            )
            for i in range(100)
        ]
        report = ScanReport(
            root="/project", mode="quick", files_scanned=1,
            files_skipped=0, total_findings=100, critical=0, warnings=100, info=0,
            file_analyses=[
                FileAnalysis(path="big.py", language="python", lines=200,
                             findings=findings),
            ],
        )
        result = format_scan_report(report, max_findings=50)
        assert "... and 50 more" in result

    def test_diff_mode_label(self):
        report = ScanReport(
            root="/project", mode="diff", files_scanned=3,
            files_skipped=0, total_findings=0, critical=0, warnings=0, info=0,
        )
        result = format_scan_report(report)
        assert "diff mode" in result


# ─── format_file_findings ────────────────────────────────────────────

class TestFormatFileFindings:
    def test_no_findings(self):
        result = format_file_findings("clean.py", "python", 50, [])
        assert "No issues found" in result
        assert "clean.py" in result

    def test_findings_present(self, warning_finding):
        result = format_file_findings("src/utils.py", "python", 100, [warning_finding])
        assert "1 warning" in result
        assert "unused-variable" in result

    def test_severity_counts(self, critical_finding, warning_finding, info_finding):
        result = format_file_findings(
            "mixed.py", "python", 200,
            [critical_finding, warning_finding, info_finding],
        )
        assert "1 critical" in result
        assert "1 warning" in result
        assert "1 info" in result


# ─── format_fix_report ───────────────────────────────────────────────

class TestFormatFixReport:
    def test_no_fixes(self):
        report = FixReport(
            root="/project", files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )
        result = format_fix_report(report)
        assert "No fixes available" in result

    def test_fix_shown(self, sample_fix):
        report = FixReport(
            root="src/auth.py", files_fixed=1, total_fixes=1,
            applied=0, skipped=0, failed=0,
            fixes=[sample_fix],
        )
        result = format_fix_report(report)
        assert "Fix 1:" in result
        assert "bare-except" in result
        assert "- except:" in result
        assert "+ except Exception:" in result
        assert "deterministic" in result
        assert "1 fixes available" in result

    def test_verification_shown(self, sample_fix):
        report = FixReport(
            root="src/auth.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            fixes=[sample_fix],
            verification={"resolved": 1, "remaining": 0, "new_issues": 0},
        )
        result = format_fix_report(report)
        assert "Verification" in result
        assert "1 resolved" in result


# ─── format_explanation ──────────────────────────────────────────────

class TestFormatExplanation:
    def test_full_explanation(self, sample_explanation):
        result = format_explanation(sample_explanation)
        assert "src/auth.py" in result
        assert "python" in result
        assert "Authentication module" in result
        assert "login()" in result
        assert "Singleton" in result
        assert "taint-flow" in result
        assert "parameterize SQL" in result

    def test_minimal_explanation(self):
        explanation = FileExplanation(
            filepath="empty.py", language="python", summary="Empty file.",
        )
        result = format_explanation(explanation)
        assert "empty.py" in result
        assert "Empty file." in result


# ─── format_project_analysis ─────────────────────────────────────────

class TestFormatProjectAnalysis:
    def test_basic_analysis(self):
        analysis = ProjectAnalysis(
            root="/project",
            files_analyzed=15,
            graph_metrics={"total_modules": 15, "total_edges": 22},
            dependency_graph={
                "nodes": {
                    "core.py": {"language": "python", "fan_in": 8, "fan_out": 2},
                    "utils.py": {"language": "python", "fan_in": 5, "fan_out": 1},
                },
                "circular_deps": [],
            },
        )
        result = format_project_analysis(analysis)
        assert "/project" in result
        assert "15 files" in result
        assert "total_modules" in result
        assert "2 modules" in result
        assert "core.py" in result
        assert "fan_in=8" in result

    def test_cross_file_findings(self):
        analysis = ProjectAnalysis(
            root="/project",
            files_analyzed=5,
            graph_metrics={},
            dependency_graph={"nodes": [], "edges": []},
            cross_file_findings=[
                CrossFileFinding(
                    source_file="a.py", target_file="b.py",
                    line=10, target_line=20,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    rule="circular-import",
                    message="Circular dependency between a.py and b.py",
                ),
            ],
        )
        result = format_project_analysis(analysis)
        assert "Cross-file findings (1)" in result
        assert "circular-import" in result
        assert "a.py:10" in result
        assert "b.py:20" in result

    def test_empty_project(self):
        analysis = ProjectAnalysis(
            root="/empty",
            files_analyzed=0,
            graph_metrics={},
            dependency_graph={},
        )
        result = format_project_analysis(analysis)
        assert "/empty" in result
        assert "0 files" in result
