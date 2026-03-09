"""Tests for pr_review module — data types, risk assessment, response parsing, formatting."""

import json
import pytest

from dojigiri.pr_review import (
    FileReview,
    PRReview,
    _assess_risk,
    _parse_review_response,
    _build_review_prompt,
    format_pr_comment,
)
from dojigiri.types import Finding, Severity, Category, Source


def _f(rule="test-rule", line=1, severity=Severity.WARNING):
    """Shorthand finding factory."""
    return Finding(
        file="test.py", line=line, severity=severity,
        category=Category.SECURITY, source=Source.STATIC,
        rule=rule, message=f"Issue: {rule}",
    )


# ─── FileReview ───────────────────────────────────────────────────────


class TestFileReview:
    def test_severity_counts(self):
        """FileReview correctly counts critical/warning/info."""
        fr = FileReview(
            path="test.py",
            findings=[
                _f(severity=Severity.CRITICAL),
                _f(severity=Severity.CRITICAL),
                _f(severity=Severity.WARNING),
                _f(severity=Severity.INFO),
            ],
        )
        assert fr.critical_count == 2
        assert fr.warning_count == 1
        assert fr.info_count == 1

    def test_to_dict_includes_path(self):
        """to_dict has path and findings keys."""
        fr = FileReview(path="app.py", findings=[_f()])
        d = fr.to_dict()
        assert d["path"] == "app.py"
        assert len(d["findings"]) == 1

    def test_to_dict_includes_llm_analysis(self):
        """to_dict includes llm_analysis when present."""
        fr = FileReview(
            path="app.py", findings=[_f()],
            llm_analysis=[{"title": "SQL Injection", "severity": "critical"}],
        )
        d = fr.to_dict()
        assert "llm_analysis" in d
        assert d["llm_analysis"][0]["title"] == "SQL Injection"


# ─── Risk assessment ─────────────────────────────────────────────────


class TestRiskAssessment:
    def test_no_findings_is_low(self):
        assert _assess_risk([]) == "Low"

    def test_one_critical_is_high(self):
        fr = FileReview(path="x.py", findings=[_f(severity=Severity.CRITICAL)])
        assert _assess_risk([fr]) == "High"

    def test_three_criticals_is_critical(self):
        fr = FileReview(path="x.py", findings=[
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.CRITICAL),
            _f(severity=Severity.CRITICAL),
        ])
        assert _assess_risk([fr]) == "Critical"

    def test_warnings_only_is_medium(self):
        fr = FileReview(path="x.py", findings=[_f(severity=Severity.WARNING)])
        assert _assess_risk([fr]) == "Medium"

    def test_info_only_is_low(self):
        fr = FileReview(path="x.py", findings=[_f(severity=Severity.INFO)])
        assert _assess_risk([fr]) == "Low"


# ─── Response parsing ────────────────────────────────────────────────


class TestParseReviewResponse:
    def test_valid_json(self):
        """Direct JSON is parsed correctly."""
        payload = {"risk_level": "High", "findings": []}
        result = _parse_review_response(json.dumps(payload))
        assert result == payload

    def test_markdown_fenced_json(self):
        """JSON inside markdown fences is extracted."""
        text = "```json\n{\"risk_level\": \"Low\", \"findings\": []}\n```"
        result = _parse_review_response(text)
        assert result is not None
        assert result["risk_level"] == "Low"

    def test_json_with_surrounding_text(self):
        """JSON embedded in prose is extracted."""
        text = 'Here is my analysis:\n{"risk_level": "Medium", "findings": []}\nEnd.'
        result = _parse_review_response(text)
        assert result is not None
        assert result["risk_level"] == "Medium"

    def test_empty_string_returns_none(self):
        assert _parse_review_response("") is None

    def test_none_returns_none(self):
        assert _parse_review_response(None) is None

    def test_invalid_json_returns_none(self):
        assert _parse_review_response("not json at all") is None


# ─── Format PR comment ───────────────────────────────────────────────


class TestFormatPRComment:
    def test_clean_review_output(self):
        """Review with no findings produces clean message."""
        review = PRReview(base_ref="main", risk_level="Low")
        output = format_pr_comment(review)
        assert "Dojigiri Security Review" in output
        assert "No security findings" in output

    def test_review_with_findings(self):
        """Review with findings shows file sections."""
        fr = FileReview(path="api.py", findings=[
            _f(rule="eval-usage", severity=Severity.CRITICAL),
        ])
        review = PRReview(
            base_ref="main", risk_level="High",
            file_reviews=[fr],
            summary="1 finding(s) (1 critical)",
        )
        output = format_pr_comment(review)
        assert "`api.py`" in output
        assert "eval-usage" in output
        assert "High" in output
