"""Tests for dojigiri/llm_parsers.py — LLM response parsing and recovery."""

import json
import pytest

from dojigiri.llm_parsers import (
    _strip_markdown_fences,
    _recover_truncated_json,
    _parse_debug_response,
    _parse_scan_response,
    _raw_to_findings,
    _format_static_findings_for_llm,
    _parse_python_traceback,
)
from dojigiri.types import Category, Confidence, Finding, Severity, Source


# ─── _strip_markdown_fences ─────────────────────────────────────────


class TestStripMarkdownFences:
    def test_no_fences(self):
        assert _strip_markdown_fences("hello") == "hello"

    def test_json_fences(self):
        text = '```json\n{"key": "val"}\n```'
        assert _strip_markdown_fences(text) == '{"key": "val"}'

    def test_fences_no_newline(self):
        text = "```content```"
        assert _strip_markdown_fences(text) == "content"

    def test_fences_without_closing(self):
        text = "```json\n{}\n"
        result = _strip_markdown_fences(text)
        assert "```" not in result


# ─── _recover_truncated_json ────────────────────────────────────────


class TestRecoverTruncatedJson:
    def test_valid_complete_array(self):
        text = '[{"a": 1}, {"b": 2}]'
        result = _recover_truncated_json(text)
        assert result == [{"a": 1}, {"b": 2}]

    def test_truncated_array(self):
        text = '[{"a": 1}, {"b": 2}, {"c": 3'
        result = _recover_truncated_json(text)
        assert result is not None
        assert len(result) == 2

    def test_not_array(self):
        assert _recover_truncated_json('{"a": 1}') is None

    def test_no_braces(self):
        assert _recover_truncated_json("[1, 2, 3") is None

    def test_empty(self):
        assert _recover_truncated_json("") is None

    def test_all_invalid(self):
        assert _recover_truncated_json("[{bad{bad{") is None


# ─── _parse_debug_response ──────────────────────────────────────────


class TestParseDebugResponse:
    def test_valid_json(self):
        text = '{"key": "value"}'
        result = _parse_debug_response(text)
        assert result == {"key": "value"}

    def test_empty(self):
        assert _parse_debug_response("") is None
        assert _parse_debug_response("   ") is None
        assert _parse_debug_response(None) is None

    def test_markdown_fenced(self):
        text = '```json\n{"key": "val"}\n```'
        result = _parse_debug_response(text)
        assert result == {"key": "val"}

    def test_brace_extraction(self):
        text = 'Here is the result: {"answer": 42} hope that helps!'
        result = _parse_debug_response(text)
        assert result == {"answer": 42}

    def test_returns_none_on_non_dict(self):
        text = "[1, 2, 3]"
        result = _parse_debug_response(text)
        assert result is None

    def test_total_failure(self):
        assert _parse_debug_response("not json at all") is None


# ─── _parse_scan_response ───────────────────────────────────────────


class TestParseScanResponse:
    def test_valid_array(self):
        text = '[{"a": 1}]'
        result = _parse_scan_response(text)
        assert result == [{"a": 1}]

    def test_empty(self):
        assert _parse_scan_response("") is None
        assert _parse_scan_response(None) is None

    def test_dict_wrapper_findings(self):
        text = json.dumps({"findings": [{"a": 1}]})
        result = _parse_scan_response(text)
        assert result == [{"a": 1}]

    def test_dict_wrapper_results(self):
        text = json.dumps({"results": [{"b": 2}]})
        result = _parse_scan_response(text)
        assert result == [{"b": 2}]

    def test_dict_wrapper_issues(self):
        text = json.dumps({"issues": [{"c": 3}]})
        result = _parse_scan_response(text)
        assert result == [{"c": 3}]

    def test_markdown_fenced(self):
        text = '```json\n[{"x": 1}]\n```'
        result = _parse_scan_response(text)
        assert result == [{"x": 1}]

    def test_bracket_extraction(self):
        text = 'Here are the findings: [{"rule": "test"}] done.'
        result = _parse_scan_response(text)
        assert result == [{"rule": "test"}]

    def test_truncated_recovery(self):
        text = '[{"a": 1}, {"b": 2}, {"c": '
        result = _parse_scan_response(text)
        assert result is not None
        assert len(result) >= 1

    def test_total_failure(self):
        assert _parse_scan_response("garbage text") is None


# ─── _raw_to_findings ───────────────────────────────────────────────


class TestRawToFindings:
    def test_from_text(self):
        data = [{"line": 5, "severity": "warning", "category": "bug",
                 "rule": "test-rule", "message": "Test msg"}]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert len(findings) == 1
        assert findings[0].line == 5
        assert findings[0].rule == "test-rule"

    def test_tool_use_dict(self):
        data = {"findings": [{"line": 1, "severity": "info", "category": "style",
                              "rule": "r1", "message": "m1"}]}
        findings = _raw_to_findings("", "test.py", tool_use_data=data)
        assert len(findings) == 1

    def test_tool_use_list(self):
        data = [{"line": 1, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1"}]
        findings = _raw_to_findings("", "test.py", tool_use_data=data)
        assert len(findings) == 1

    def test_tool_use_invalid(self):
        findings = _raw_to_findings("", "test.py", tool_use_data="bad")
        assert findings == []

    def test_chunk_offset(self):
        data = [{"line": 5, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1"}]
        findings = _raw_to_findings(json.dumps(data), "test.py",
                                     chunk_index=1, chunk_start_line=100)
        assert findings[0].line == 104  # 5 + 100 - 1

    def test_invalid_line(self):
        data = [{"line": -1, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1"}]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert findings[0].line == 1

    def test_invalid_confidence(self):
        data = [{"line": 1, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1", "confidence": "super-high"}]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert findings[0].confidence == Confidence.MEDIUM

    def test_non_dict_item_skipped(self):
        data = [{"line": 1, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1"}, "not a dict", 42]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert len(findings) == 1

    def test_bad_severity_skipped(self):
        data = [{"line": 1, "severity": "mega", "category": "bug",
                 "rule": "r1", "message": "m1"}]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert len(findings) == 0

    def test_suggestion_included(self):
        data = [{"line": 1, "severity": "info", "category": "bug",
                 "rule": "r1", "message": "m1", "suggestion": "fix it"}]
        findings = _raw_to_findings(json.dumps(data), "test.py")
        assert findings[0].suggestion == "fix it"

    def test_empty_response(self):
        findings = _raw_to_findings("", "test.py")
        assert findings == []


# ─── _format_static_findings_for_llm ────────────────────────────────


class TestFormatStaticFindings:
    def test_empty(self):
        assert _format_static_findings_for_llm([]) == ""

    def test_basic_finding(self):
        f = Finding(file="test.py", line=5, severity=Severity.WARNING,
                    category=Category.BUG, source=Source.STATIC,
                    rule="test-rule", message="Test issue")
        result = _format_static_findings_for_llm([f])
        assert "WARNING" in result
        assert "test-rule" not in result  # rule is not in the formatted output
        assert "Test issue" in result

    def test_with_suggestion(self):
        f = Finding(file="test.py", line=5, severity=Severity.WARNING,
                    category=Category.BUG, source=Source.STATIC,
                    rule="test-rule", message="msg", suggestion="fix this")
        result = _format_static_findings_for_llm([f])
        assert "suggestion:" in result

    def test_redacted_finding(self):
        f = Finding(file="test.py", line=5, severity=Severity.WARNING,
                    category=Category.SECURITY, source=Source.STATIC,
                    rule="hardcoded-secret", message="secret found")
        result = _format_static_findings_for_llm([f])
        assert "REDACTED" in result


# ─── _parse_python_traceback ────────────────────────────────────────


class TestParsePythonTraceback:
    def test_none_input(self):
        assert _parse_python_traceback("") is None
        assert _parse_python_traceback(None) is None

    def test_no_traceback(self):
        assert _parse_python_traceback("just an error message") is None

    def test_valid_traceback(self):
        tb = (
            'Traceback (most recent call last):\n'
            '  File "test.py", line 10, in main\n'
            '    result = foo()\n'
            '  File "test.py", line 5, in foo\n'
            '    return 1 / 0\n'
            'ZeroDivisionError: division by zero\n'
        )
        result = _parse_python_traceback(tb)
        assert result is not None
        assert len(result["frames"]) == 2
        assert result["exception_type"] == "ZeroDivisionError"
        assert result["exception_message"] == "division by zero"
        assert 10 in result["relevant_lines"]
        assert 5 in result["relevant_lines"]

    def test_traceback_no_function(self):
        tb = (
            'Traceback (most recent call last):\n'
            '  File "test.py", line 1\n'
            '    x = bad\n'
            'NameError: name bad is not defined\n'
        )
        result = _parse_python_traceback(tb)
        assert result is not None
        assert result["frames"][0]["function"] == "<module>"

    def test_exception_without_message(self):
        tb = (
            'Traceback (most recent call last):\n'
            '  File "test.py", line 1, in main\n'
            '    raise StopIteration\n'
            'StopIteration\n'
        )
        result = _parse_python_traceback(tb)
        assert result is not None
        assert result["exception_type"] == "StopIteration"
        assert result["exception_message"] == ""
