"""Tests for dojigiri/fixer/engine.py — targeting uncovered engine functions."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from dojigiri.types import (
    Finding, Fix, FixReport, FixSource, FixStatus,
    Severity, Category, Source, FixContext,
)
from dojigiri.fixer.engine import (
    _apply_single_fix,
    _resolve_fix_conflicts,
    _strip_template_literals,
    _validate_syntax,
    _empty_fix_report,
    _write_fixed_content,
    apply_fixes,
    fix_file,
)


def _f(rule="test-rule", line=1, message="test"):
    return Finding(
        file="test.py", line=line, severity=Severity.WARNING,
        category=Category.STYLE, source=Source.STATIC,
        rule=rule, message=message,
    )


# ─── _apply_single_fix ──────────────────────────────────────────────


class TestApplySingleFix:
    def test_overlap_skip(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="x\n", fixed_code="y\n",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x\n", "y\n"]
        occupied = {1}
        deleted = set()
        _apply_single_fix(fix, lines, occupied, deleted, dry_run=True)
        assert fix.status == FixStatus.SKIPPED

    def test_out_of_range(self):
        fix = Fix(file="t.py", line=100, rule="r", original_code="x\n", fixed_code="y\n",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=True)
        assert fix.status == FixStatus.FAILED
        assert "out of range" in fix.fail_reason

    def test_deletion_mismatch(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="expected\n", fixed_code="",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["different\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=True)
        assert fix.status == FixStatus.FAILED
        assert "not found" in fix.fail_reason

    def test_deletion_applies(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="x = 1\n", fixed_code="",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x = 1\n", "y = 2\n"]
        deleted = set()
        _apply_single_fix(fix, lines, set(), deleted, dry_run=False)
        assert fix.status == FixStatus.APPLIED
        assert lines[0] == ""
        assert 0 in deleted

    def test_replacement_applies(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="x = 1\n",
                  fixed_code="x = 2\n", explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x = 1\n", "y = 2\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=False)
        assert fix.status == FixStatus.APPLIED
        assert lines[0] == "x = 2\n"

    def test_replacement_adds_newline(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="x = 1\n",
                  fixed_code="x = 2", explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x = 1\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=False)
        assert lines[0] == "x = 2\n"

    def test_missing_both_codes(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="", fixed_code="",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=True)
        assert fix.status == FixStatus.FAILED
        assert "missing" in fix.fail_reason

    def test_replacement_mismatch(self):
        fix = Fix(file="t.py", line=1, rule="r", original_code="expected\n",
                  fixed_code="new\n", explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["different\n"]
        _apply_single_fix(fix, lines, set(), set(), dry_run=True)
        assert fix.status == FixStatus.FAILED

    def test_multiline_deletion(self):
        fix = Fix(file="t.py", line=1, end_line=2, rule="r",
                  original_code="x = 1\n", fixed_code="",
                  explanation="e", source=FixSource.DETERMINISTIC)
        lines = ["x = 1\n", "y = 2\n", "z = 3\n"]
        deleted = set()
        _apply_single_fix(fix, lines, set(), deleted, dry_run=False)
        assert fix.status == FixStatus.APPLIED
        assert lines[0] == ""
        assert lines[1] == ""


# ─── _resolve_fix_conflicts ──────────────────────────────────────────


class TestResolveFixConflicts:
    def test_unused_var_wins_over_secret(self):
        fixes = [
            Fix(file="t.py", line=5, rule="unused-variable", original_code="x\n",
                fixed_code="", explanation="e", source=FixSource.DETERMINISTIC),
            Fix(file="t.py", line=5, rule="hardcoded-secret", original_code="x\n",
                fixed_code="os.environ['X']", explanation="e", source=FixSource.DETERMINISTIC),
        ]
        result = _resolve_fix_conflicts(fixes)
        rules = [f.rule for f in result]
        assert "hardcoded-secret" not in rules
        assert "unused-variable" in rules

    def test_preserves_needed_imports(self):
        fixes = [
            Fix(file="t.py", line=1, rule="unused-import", original_code="import os\n",
                fixed_code="", explanation="e", source=FixSource.DETERMINISTIC),
            Fix(file="t.py", line=5, rule="hardcoded-secret", original_code="x = 'secret'\n",
                fixed_code="x = os.environ['X']", explanation="e", source=FixSource.DETERMINISTIC),
        ]
        result = _resolve_fix_conflicts(fixes)
        rules = [f.rule for f in result]
        assert "unused-import" not in rules  # os import is needed

    def test_no_conflicts(self):
        fixes = [
            Fix(file="t.py", line=1, rule="bare-except", original_code="except:\n",
                fixed_code="except Exception:\n", explanation="e", source=FixSource.DETERMINISTIC),
        ]
        result = _resolve_fix_conflicts(fixes)
        assert len(result) == 1


# ─── _strip_template_literals ────────────────────────────────────────


class TestStripTemplateLiterals:
    def test_simple_template(self):
        result = _strip_template_literals("let x = `hello ${name}`")
        assert "{" not in result.split("`")[-1] if "`" in result else True
        assert len(result) == len("let x = `hello ${name}`")

    def test_nested_template(self):
        result = _strip_template_literals("let x = `${`inner`}`")
        assert len(result) == len("let x = `${`inner`}`")

    def test_no_templates(self):
        code = "let x = 'hello'"
        assert _strip_template_literals(code) == code

    def test_escaped_backtick(self):
        result = _strip_template_literals("let x = `hello \\` world`")
        assert len(result) == len("let x = `hello \\` world`")

    def test_nested_object_in_expression(self):
        result = _strip_template_literals("let x = `${({a: 1})}`")
        assert len(result) == len("let x = `${({a: 1})}`")


# ─── _validate_syntax ────────────────────────────────────────────────


class TestValidateSyntax:
    def test_valid_python(self):
        assert _validate_syntax("test.py", "x = 1\n", "python") is None

    def test_invalid_python(self):
        result = _validate_syntax("test.py", "def bad(\n", "python")
        assert result is not None
        assert "syntax error" in result.lower()

    def test_valid_javascript(self):
        assert _validate_syntax("test.js", "function foo() { return 1; }\n", "javascript") is None

    def test_unbalanced_braces_js(self):
        result = _validate_syntax("test.js", "function foo() {\n", "javascript")
        assert result is not None
        assert "Unbalanced" in result

    def test_unknown_language(self):
        assert _validate_syntax("test.rs", "fn main() {}", "rust") is None


# ─── _empty_fix_report ──────────────────────────────────────────────


class TestEmptyFixReport:
    def test_returns_zero_counts(self):
        report = _empty_fix_report("test.py")
        assert report.root == "test.py"
        assert report.applied == 0
        assert report.total_fixes == 0


# ─── apply_fixes ─────────────────────────────────────────────────────


class TestApplyFixes:
    def test_empty_fixes(self):
        result = apply_fixes("test.py", [], dry_run=True)
        assert result == []

    def test_dry_run_does_not_write(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("x = 1\n", encoding="utf-8")
        fix = Fix(file=str(p), line=1, rule="r", original_code="x = 1\n",
                  fixed_code="x = 2\n", explanation="e", source=FixSource.DETERMINISTIC)
        apply_fixes(str(p), [fix], dry_run=True)
        assert p.read_text() == "x = 1\n"
        assert fix.status == FixStatus.APPLIED

    def test_actual_write(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("x = 1\ny = 2\n", encoding="utf-8")
        fix = Fix(file=str(p), line=1, rule="r", original_code="x = 1\n",
                  fixed_code="x = 99\n", explanation="e", source=FixSource.DETERMINISTIC)
        apply_fixes(str(p), [fix], dry_run=False, create_backup=False)
        assert "x = 99" in p.read_text()

    def test_unreadable_file(self):
        fix = Fix(file="/nonexistent/file.py", line=1, rule="r",
                  original_code="x\n", fixed_code="y\n",
                  explanation="e", source=FixSource.DETERMINISTIC)
        result = apply_fixes("/nonexistent/file.py", [fix], dry_run=True)
        assert result[0].status == FixStatus.FAILED

    def test_backup_created(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("x = 1\n", encoding="utf-8")
        fix = Fix(file=str(p), line=1, rule="r", original_code="x = 1\n",
                  fixed_code="x = 2\n", explanation="e", source=FixSource.DETERMINISTIC)
        apply_fixes(str(p), [fix], dry_run=False, create_backup=True)
        backup = tmp_path / "test.py.doji.bak"
        assert backup.exists()
        assert backup.read_text() == "x = 1\n"


# ─── fix_file ────────────────────────────────────────────────────────


class TestFixFile:
    def test_no_findings(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("x = 1\n", encoding="utf-8")
        report = fix_file(str(p), "x = 1\n", "python", [])
        assert report.total_fixes == 0

    def test_filtered_by_rules(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("except:\n    pass\n", encoding="utf-8")
        finding = _f(rule="bare-except", line=1, message="bare except")
        report = fix_file(str(p), "except:\n    pass\n", "python", [finding],
                          rules=["nonexistent-rule"], dry_run=True)
        assert report.total_fixes == 0

    def test_deterministic_fix_dry_run(self, tmp_path):
        code = "    except:\n        pass\n"
        p = tmp_path / "test.py"
        p.write_text(code, encoding="utf-8")
        finding = Finding(
            file=str(p), line=1, severity=Severity.WARNING,
            category=Category.BUG, source=Source.STATIC,
            rule="bare-except", message="Bare except",
        )
        report = fix_file(str(p), code, "python", [finding], dry_run=True, verify=False)
        assert report.total_fixes >= 1
        assert report.applied >= 1
