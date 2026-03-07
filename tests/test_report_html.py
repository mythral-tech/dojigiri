"""Tests for report_html module — HTML/PDF rendering."""

import pytest
from unittest.mock import patch, MagicMock

from dojigiri.report_html import render_html, render_pdf
from dojigiri.types import (
    ScanReport, FileAnalysis, Finding,
    Severity, Category, Source, Confidence,
)


# ─── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def empty_report():
    return ScanReport(
        root="/project",
        mode="quick",
        files_scanned=5,
        files_skipped=0,
        file_analyses=[],
        timestamp="2026-03-05T12:00:00",
    )


@pytest.fixture
def report_with_findings():
    findings = [
        Finding(
            file="app.py",
            line=10,
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            source=Source.STATIC,
            rule="sql-injection",
            message="SQL injection via string concat",
            suggestion="Use parameterized queries",
            snippet="cursor.execute('SELECT * FROM ' + user_input)",
        ),
        Finding(
            file="app.py",
            line=25,
            severity=Severity.WARNING,
            category=Category.BUG,
            source=Source.STATIC,
            rule="eval-usage",
            message="eval() usage is dangerous",
            suggestion="Use ast.literal_eval",
        ),
    ]
    fa = FileAnalysis(
        path="app.py",
        language="python",
        lines=100,
        findings=findings,
    )
    return ScanReport(
        root="/project",
        mode="deep",
        files_scanned=10,
        files_skipped=2,
        file_analyses=[fa],
        llm_cost_usd=0.0042,
        timestamp="2026-03-05T12:00:00",
    )


# ─── render_html ──────────────────────────────────────────────────────

class TestRenderHtml:
    def test_returns_valid_html(self, empty_report):
        result = render_html(empty_report)
        assert result.startswith("<!DOCTYPE html>")
        assert "</html>" in result

    def test_contains_title(self, empty_report):
        result = render_html(empty_report, project_name="MyProject")
        assert "MyProject" in result
        assert "<title>Dojigiri Report" in result

    def test_defaults_title_to_root(self, empty_report):
        result = render_html(empty_report)
        assert "/project" in result

    def test_contains_summary_cards(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "Files Scanned" in result
        assert "Critical" in result
        assert "Warnings" in result
        assert "Total" in result

    def test_summary_counts(self, report_with_findings):
        result = render_html(report_with_findings)
        # Check the summary card numbers
        assert ">10<" in result  # files_scanned
        assert ">1<" in result   # critical
        assert ">2<" in result   # total_findings

    def test_findings_table(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "sql-injection" in result
        assert "eval-usage" in result
        assert "SQL injection via string concat" in result
        assert "Use parameterized queries" in result

    def test_cwe_in_findings(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "CWE-89" in result  # sql-injection

    def test_nist_in_findings(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "SI-10" in result  # sql-injection NIST mapping

    def test_per_file_breakdown(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "app.py" in result
        assert "python" in result
        assert "100 lines" in result

    def test_no_findings_message(self, empty_report):
        result = render_html(empty_report)
        assert "No findings" in result
        assert "No files with findings" in result

    def test_classification_banner(self, empty_report):
        result = render_html(empty_report, classification="SECRET")
        assert "SECRET" in result
        assert "classification-banner" in result

    def test_no_classification_banner_by_default(self, empty_report):
        result = render_html(empty_report)
        # CSS class exists in stylesheet, but no banner div should be rendered
        assert '<div class="classification-banner">' not in result

    def test_classification_xss_escaped(self, empty_report):
        result = render_html(empty_report, classification='<script>alert("xss")</script>')
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_project_name_xss_escaped(self, empty_report):
        result = render_html(empty_report, project_name='<img src=x onerror=alert(1)>')
        assert "<img src=" not in result
        assert "&lt;img" in result

    def test_finding_message_xss_escaped(self):
        fa = FileAnalysis(
            path="x.py",
            language="python",
            lines=10,
            findings=[Finding(
                file="x.py",
                line=1,
                severity=Severity.INFO,
                category=Category.STYLE,
                source=Source.STATIC,
                rule="test-rule",
                message='<script>evil()</script>',
            )],
        )
        report = ScanReport(
            root="/p", mode="quick", files_scanned=1, files_skipped=0,
            file_analyses=[fa], timestamp="2026-01-01T00:00:00",
        )
        result = render_html(report)
        assert "<script>evil()</script>" not in result
        assert "&lt;script&gt;" in result

    def test_snippet_xss_escaped(self):
        fa = FileAnalysis(
            path="x.py",
            language="python",
            lines=10,
            findings=[Finding(
                file="x.py",
                line=1,
                severity=Severity.WARNING,
                category=Category.BUG,
                source=Source.STATIC,
                rule="test-rule",
                message="msg",
                snippet='x = "<img onerror=alert(1)>"',
            )],
        )
        report = ScanReport(
            root="/p", mode="quick", files_scanned=1, files_skipped=0,
            file_analyses=[fa], timestamp="2026-01-01T00:00:00",
        )
        result = render_html(report)
        # The <img> tag itself must be escaped — onerror text in escaped form is fine
        assert "<img onerror=" not in result
        assert "&lt;img" in result

    def test_llm_cost_shown_when_nonzero(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "$0.0042" in result

    def test_llm_cost_hidden_when_zero(self, empty_report):
        result = render_html(empty_report)
        assert "LLM cost" not in result

    def test_timestamp_in_output(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "2026-03-05T12:00:00" in result

    def test_mode_in_output(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "deep" in result

    def test_version_footer(self, empty_report):
        result = render_html(empty_report)
        assert "Dojigiri v1.1.0" in result

    def test_print_css_included(self, empty_report):
        result = render_html(empty_report)
        assert "@media print" in result

    def test_severity_colors_applied(self, report_with_findings):
        result = render_html(report_with_findings)
        assert "#dc2626" in result  # critical color
        assert "#d97706" in result  # warning color

    def test_multiple_files(self):
        fa1 = FileAnalysis(
            path="a.py", language="python", lines=50,
            findings=[Finding(
                file="a.py", line=1, severity=Severity.INFO,
                category=Category.STYLE, source=Source.STATIC,
                rule="r1", message="m1",
            )],
        )
        fa2 = FileAnalysis(
            path="b.js", language="javascript", lines=30,
            findings=[Finding(
                file="b.js", line=5, severity=Severity.CRITICAL,
                category=Category.SECURITY, source=Source.STATIC,
                rule="r2", message="m2",
            )],
        )
        report = ScanReport(
            root="/p", mode="quick", files_scanned=2, files_skipped=0,
            file_analyses=[fa1, fa2], timestamp="2026-01-01T00:00:00",
        )
        result = render_html(report)
        assert "a.py" in result
        assert "b.js" in result
        assert "python" in result
        assert "javascript" in result


# ─── render_pdf ──────────────────────────────────────────────────────

class TestRenderPdf:
    def test_pdf_raises_without_weasyprint(self, empty_report, tmp_path):
        output = str(tmp_path / "report.pdf")
        with patch.dict("sys.modules", {"weasyprint": None}):
            with pytest.raises(ImportError, match="weasyprint"):
                render_pdf(empty_report, output)

    def test_pdf_passes_classification(self, empty_report, tmp_path):
        """Test that render_pdf forwards classification to render_html."""
        import sys
        output = str(tmp_path / "report.pdf")
        mock_weasyprint = MagicMock()
        mock_html_instance = MagicMock()
        mock_weasyprint.HTML.return_value = mock_html_instance

        with patch("dojigiri.report_html.render_html", return_value="<html></html>") as mock_render:
            sys.modules["weasyprint"] = mock_weasyprint
            try:
                render_pdf(empty_report, output, classification="CUI", project_name="Test")
                mock_render.assert_called_once_with(
                    empty_report, classification="CUI", project_name="Test"
                )
                mock_weasyprint.HTML.assert_called_once()
                mock_html_instance.write_pdf.assert_called_once_with(output)
            finally:
                del sys.modules["weasyprint"]
