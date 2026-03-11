"""Extended tests for pr_review.py — targeting uncovered pure-logic functions."""

import json
import pytest

from dojigiri.pr_review import (
    FileReview,
    PRReview,
    _assess_risk,
    _build_review_prompt,
    _build_summary,
    _parse_review_response,
    format_pr_comment,
)
from dojigiri.types import Finding, Severity, Category, Source


def _f(rule="test-rule", line=1, severity=Severity.WARNING, message="Issue",
       suggestion=None):
    return Finding(
        file="test.py", line=line, severity=severity,
        category=Category.SECURITY, source=Source.STATIC,
        rule=rule, message=message, suggestion=suggestion,
    )


# ─── PRReview data class ─────────────────────────────────────────────


class TestPRReviewDataClass:
    def test_auto_timestamp(self):
        r = PRReview(base_ref="main", risk_level="Low")
        assert r.timestamp  # Should be auto-generated

    def test_total_findings(self):
        fr = FileReview(path="a.py", findings=[_f(), _f()])
        r = PRReview(base_ref="main", risk_level="Low", file_reviews=[fr])
        assert r.total_findings == 2

    def test_severity_counts(self):
        fr = FileReview(path="a.py", findings=[
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.WARNING),
            _f(severity=Severity.INFO),
        ])
        r = PRReview(base_ref="main", risk_level="Medium", file_reviews=[fr])
        assert r.critical == 1
        assert r.warnings == 1
        assert r.info == 1

    def test_to_dict(self):
        fr = FileReview(path="a.py", findings=[_f()])
        r = PRReview(base_ref="dev", risk_level="High", file_reviews=[fr], summary="1 issue")
        d = r.to_dict()
        assert d["base_ref"] == "dev"
        assert d["risk_level"] == "High"
        assert d["total_findings"] == 1
        assert len(d["files"]) == 1


# ─── _build_summary ──────────────────────────────────────────────────


class TestBuildSummary:
    def test_no_findings(self):
        assert _build_summary([]) == "No findings"

    def test_mixed_findings(self):
        fr = FileReview(path="a.py", findings=[
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.WARNING),
            _f(severity=Severity.WARNING),
        ])
        result = _build_summary([fr])
        assert "3 finding(s)" in result
        assert "1 critical" in result
        assert "2 warning" in result


# ─── _build_review_prompt ────────────────────────────────────────────


class TestBuildReviewPrompt:
    def test_basic_prompt(self):
        prompt = _build_review_prompt("test.py", "--- a/test.py\n+++ b/test.py\n", [])
        assert "test.py" in prompt
        assert "DIFF" in prompt

    def test_with_findings(self):
        findings = [_f(message="Eval found", suggestion="Use literal_eval")]
        prompt = _build_review_prompt("app.py", "diff", findings)
        assert "Eval found" in prompt
        assert "literal_eval" in prompt
        assert "Static analysis" in prompt


# ─── _parse_review_response extended ─────────────────────────────────


class TestParseReviewResponseExtended:
    def test_whitespace_only(self):
        assert _parse_review_response("   \n  ") is None

    def test_markdown_json_fence(self):
        text = "```json\n{\"risk_level\": \"Low\", \"findings\": []}\n```"
        result = _parse_review_response(text)
        assert result["risk_level"] == "Low"

    def test_markdown_fence_no_newline(self):
        text = "```{\"a\": 1}```"
        result = _parse_review_response(text)
        assert result is not None

    def test_json_embedded_in_text(self):
        text = 'Analysis complete.\n{"risk_level": "High", "findings": [{"line": 1}]}\nDone.'
        result = _parse_review_response(text)
        assert result is not None
        assert result["risk_level"] == "High"


# ─── format_pr_comment extended ──────────────────────────────────────


class TestFormatPRCommentExtended:
    def test_with_llm_analysis(self):
        fr = FileReview(
            path="api.py",
            findings=[_f(severity=Severity.CRITICAL)],
            llm_analysis=[
                {"severity": "critical", "title": "SSRF", "line": 10,
                 "snippet": "urllib.urlopen(url)", "risk": "Server can reach internal services",
                 "fix": "Validate URL against allowlist"},
            ],
        )
        review = PRReview(base_ref="main", risk_level="High", file_reviews=[fr])
        md = format_pr_comment(review)
        assert "SSRF" in md
        assert "api.py" in md
        assert "allowlist" in md
        assert "```python" in md

    def test_with_static_only(self):
        fr = FileReview(
            path="app.py",
            findings=[_f(rule="eval-usage", severity=Severity.CRITICAL, suggestion="Use literal_eval")],
        )
        review = PRReview(base_ref="main", risk_level="High", file_reviews=[fr])
        md = format_pr_comment(review)
        assert "eval-usage" in md
        assert "literal_eval" in md

    def test_llm_analysis_without_optional_fields(self):
        fr = FileReview(
            path="x.py",
            findings=[_f()],
            llm_analysis=[{"severity": "info", "title": "Minor", "line": 1}],
        )
        review = PRReview(base_ref="main", risk_level="Low", file_reviews=[fr])
        md = format_pr_comment(review)
        assert "Minor" in md
