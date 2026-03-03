"""Tests for wiz/fixer.py — deterministic fixers, fix application, integration."""

import json
import os
import subprocess
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from wiz.config import (
    Finding, Fix, FixReport, FixSource, FixStatus,
    Severity, Category, Source,
)
from wiz.fixer import (
    DETERMINISTIC_FIXERS,
    _fix_unused_import, _fix_bare_except, _fix_loose_equality,
    _fix_var_usage, _fix_none_comparison, _fix_type_comparison,
    _fix_console_log, _fix_insecure_http, _fix_fstring_no_expr,
    _fix_hardcoded_secret, _fix_open_without_with,
    _fix_yaml_unsafe, _fix_weak_hash, _fix_unreachable_code,
    _fix_mutable_default, _fix_exception_swallowed,
    _in_multiline_string, _pattern_outside_strings,
    apply_fixes, fix_file, generate_llm_fixes,
)


def _make_finding(rule: str, line: int = 1, file: str = "test.py",
                  message: str = "test") -> Finding:
    """Helper to create a Finding for testing."""
    return Finding(
        file=file, line=line, severity=Severity.WARNING,
        category=Category.STYLE, source=Source.STATIC,
        rule=rule, message=message,
    )


# ─── Deterministic fixer tests ───────────────────────────────────────


class TestFixUnusedImport:
    def test_removes_import(self):
        fix = _fix_unused_import("import os\n", _make_finding("unused-import"), "")
        assert fix is not None
        assert fix.fixed_code == ""
        assert fix.source == FixSource.DETERMINISTIC

    def test_removes_from_import(self):
        fix = _fix_unused_import("from os import path\n", _make_finding("unused-import"), "")
        assert fix is not None
        assert fix.fixed_code == ""

    def test_ignores_non_import(self):
        fix = _fix_unused_import("x = 1\n", _make_finding("unused-import"), "")
        assert fix is None

    def test_skips_multiline_import(self):
        """Multiline import (opening paren, no closing) should be skipped."""
        fix = _fix_unused_import(
            "from .config import (\n", _make_finding("unused-import"), ""
        )
        assert fix is None

    def test_handles_single_line_parens(self):
        """Single-line import with parens should still be fixed."""
        fix = _fix_unused_import(
            "from os import (path)\n", _make_finding("unused-import"), ""
        )
        assert fix is not None
        assert fix.fixed_code == ""


class TestFixBareExcept:
    def test_replaces_bare_except(self):
        fix = _fix_bare_except("    except:\n", _make_finding("bare-except"), "")
        assert fix is not None
        assert fix.fixed_code == "    except Exception:\n"

    def test_preserves_indentation(self):
        fix = _fix_bare_except("        except:\n", _make_finding("bare-except"), "")
        assert fix is not None
        assert fix.fixed_code == "        except Exception:\n"

    def test_ignores_except_with_type(self):
        fix = _fix_bare_except("    except ValueError:\n", _make_finding("bare-except"), "")
        assert fix is None


class TestFixLooseEquality:
    def test_double_equals_to_triple(self):
        fix = _fix_loose_equality("    if (x == 5) {\n", _make_finding("loose-equality"), "")
        assert fix is not None
        assert "===" in fix.fixed_code
        assert "!==" not in fix.fixed_code

    def test_not_equals(self):
        fix = _fix_loose_equality("    if (x != y) {\n", _make_finding("loose-equality"), "")
        assert fix is not None
        assert "!==" in fix.fixed_code

    def test_ignores_already_strict(self):
        fix = _fix_loose_equality("    if (x === 5) {\n", _make_finding("loose-equality"), "")
        assert fix is None


class TestFixVarUsage:
    def test_var_to_let(self):
        fix = _fix_var_usage("var x = 1;\n", _make_finding("var-usage"), "")
        assert fix is not None
        assert fix.fixed_code.startswith("let x")

    def test_preserves_indentation(self):
        fix = _fix_var_usage("  var y = 2;\n", _make_finding("var-usage"), "")
        assert fix is not None
        assert fix.fixed_code.startswith("  let")

    def test_ignores_non_var(self):
        fix = _fix_var_usage("let z = 3;\n", _make_finding("var-usage"), "")
        assert fix is None


class TestFixNoneComparison:
    def test_eq_none_to_is_none(self):
        fix = _fix_none_comparison("    if x == None:\n", _make_finding("none-comparison"), "")
        assert fix is not None
        assert "is None" in fix.fixed_code

    def test_neq_none_to_is_not_none(self):
        fix = _fix_none_comparison("    if x != None:\n", _make_finding("none-comparison"), "")
        assert fix is not None
        assert "is not None" in fix.fixed_code

    def test_ignores_correct(self):
        fix = _fix_none_comparison("    if x is None:\n", _make_finding("none-comparison"), "")
        assert fix is None

    def test_skips_inside_double_quoted_string(self):
        """Pattern inside a double-quoted string should be skipped."""
        fix = _fix_none_comparison(
            'msg = "Use == None to check"\n',
            _make_finding("none-comparison"), "",
        )
        assert fix is None

    def test_skips_inside_single_quoted_string(self):
        """Pattern inside a single-quoted string should be skipped."""
        fix = _fix_none_comparison(
            "msg = 'x != None is bad'\n",
            _make_finding("none-comparison"), "",
        )
        assert fix is None

    def test_skips_inside_docstring_body(self):
        """Pattern inside a multiline docstring body should be skipped."""
        content = 'def foo():\n    """\n    Check if x == None\n    """\n    pass\n'
        fix = _fix_none_comparison(
            "    Check if x == None\n",
            _make_finding("none-comparison", line=3), content,
        )
        assert fix is None


class TestFixTypeComparison:
    def test_type_eq_to_isinstance(self):
        fix = _fix_type_comparison("    if type(x) == str:\n", _make_finding("type-comparison"), "")
        assert fix is not None
        assert "isinstance(x, str)" in fix.fixed_code

    def test_ignores_no_match(self):
        fix = _fix_type_comparison("    if isinstance(x, str):\n", _make_finding("type-comparison"), "")
        assert fix is None


class TestFixConsoleLog:
    def test_removes_console_log(self):
        fix = _fix_console_log('console.log("debug");\n', _make_finding("console-log"), "")
        assert fix is not None
        assert fix.fixed_code == ""

    def test_ignores_non_console(self):
        fix = _fix_console_log('print("debug");\n', _make_finding("console-log"), "")
        assert fix is None


class TestFixInsecureHttp:
    def test_http_to_https(self):
        fix = _fix_insecure_http('url = "http://example.com"\n', _make_finding("insecure-http"), "")
        assert fix is not None
        assert "https://example.com" in fix.fixed_code

    def test_ignores_already_https(self):
        fix = _fix_insecure_http('url = "https://example.com"\n', _make_finding("insecure-http"), "")
        assert fix is None

    def test_skips_inside_docstring_body(self):
        """http:// inside a multiline docstring body should be skipped."""
        content = 'def foo():\n    """\n    See http://example.com\n    """\n    pass\n'
        fix = _fix_insecure_http(
            "    See http://example.com\n",
            _make_finding("insecure-http", line=3), content,
        )
        assert fix is None

    def test_skips_single_line_docstring(self):
        """http:// inside a single-line docstring should be skipped."""
        fix = _fix_insecure_http(
            '    """See http://example.com for docs."""\n',
            _make_finding("insecure-http"), "",
        )
        assert fix is None

    def test_fixes_code_string_assignment(self):
        """http:// in a regular string assignment should still be fixed."""
        fix = _fix_insecure_http(
            'url = "http://example.com"\n',
            _make_finding("insecure-http"), "",
        )
        assert fix is not None
        assert "https://" in fix.fixed_code


class TestFixFstringNoExpr:
    def test_removes_f_prefix(self):
        fix = _fix_fstring_no_expr('x = f"hello"\n', _make_finding("fstring-no-expr"), "")
        assert fix is not None
        assert 'f"' not in fix.fixed_code
        assert '"hello"' in fix.fixed_code

    def test_keeps_f_with_expr(self):
        fix = _fix_fstring_no_expr('x = f"hello {name}"\n', _make_finding("fstring-no-expr"), "")
        assert fix is None


# ─── Fix application tests ───────────────────────────────────────────


class TestApplyFixes:
    def test_single_fix(self, temp_dir):
        """Apply a single replacement fix."""
        fp = temp_dir / "test.py"
        fp.write_text("import os\nx = 1\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="Remove unused import",
            source=FixSource.DETERMINISTIC,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        assert fp.read_text(encoding="utf-8") == "x = 1\n"

    def test_bottom_to_top_ordering(self, temp_dir):
        """Fixes applied bottom-to-top to preserve line numbers."""
        fp = temp_dir / "test.py"
        fp.write_text("import os\nimport sys\nx = 1\n", encoding="utf-8")
        fixes = [
            Fix(file=str(fp), line=1, rule="unused-import",
                original_code="import os", fixed_code="",
                explanation="rm", source=FixSource.DETERMINISTIC),
            Fix(file=str(fp), line=2, rule="unused-import",
                original_code="import sys", fixed_code="",
                explanation="rm", source=FixSource.DETERMINISTIC),
        ]
        result = apply_fixes(str(fp), fixes, dry_run=False, create_backup=False)
        assert all(f.status == FixStatus.APPLIED for f in result)
        assert fp.read_text(encoding="utf-8") == "x = 1\n"

    def test_overlapping_fixes_skip(self, temp_dir):
        """When two fixes target the same line, first wins, second skipped."""
        fp = temp_dir / "test.py"
        fp.write_text("    except:\n        pass\n", encoding="utf-8")
        fixes = [
            Fix(file=str(fp), line=1, rule="bare-except",
                original_code="    except:", fixed_code="    except Exception:\n",
                explanation="fix1", source=FixSource.DETERMINISTIC),
            Fix(file=str(fp), line=1, rule="another-rule",
                original_code="    except:", fixed_code="    except BaseException:\n",
                explanation="fix2", source=FixSource.LLM),
        ]
        result = apply_fixes(str(fp), fixes, dry_run=False, create_backup=False)
        applied = [f for f in result if f.status == FixStatus.APPLIED]
        skipped = [f for f in result if f.status == FixStatus.SKIPPED]
        assert len(applied) == 1
        assert len(skipped) == 1

    def test_dry_run_no_modification(self, temp_dir):
        """Dry-run mode doesn't modify the file."""
        fp = temp_dir / "test.py"
        original = "import os\nx = 1\n"
        fp.write_text(original, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        result = apply_fixes(str(fp), [fix], dry_run=True)
        assert result[0].status == FixStatus.APPLIED
        assert fp.read_text(encoding="utf-8") == original  # unchanged

    def test_creates_backup(self, temp_dir):
        """Apply mode creates .wiz.bak backup."""
        fp = temp_dir / "test.py"
        fp.write_text("import os\nx = 1\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        apply_fixes(str(fp), [fix], dry_run=False, create_backup=True)
        backup = Path(str(fp) + ".wiz.bak")
        assert backup.exists()
        assert backup.read_text(encoding="utf-8") == "import os\nx = 1\n"

    def test_empty_fixes_noop(self, temp_dir):
        """Empty fixes list returns immediately."""
        fp = temp_dir / "test.py"
        fp.write_text("x = 1\n", encoding="utf-8")
        result = apply_fixes(str(fp), [], dry_run=False)
        assert result == []

    def test_replacement_fix(self, temp_dir):
        """Replacement fix correctly swaps content."""
        fp = temp_dir / "test.py"
        fp.write_text("    except:\n        pass\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="bare-except",
            original_code="    except:", fixed_code="    except Exception:\n",
            explanation="fix", source=FixSource.DETERMINISTIC,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        content = fp.read_text(encoding="utf-8")
        assert "except Exception:" in content

    def test_mismatched_original_fails(self, temp_dir):
        """Fix fails when original_code doesn't match file content."""
        fp = temp_dir / "test.py"
        fp.write_text("x = 1\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="test",
            original_code="y = 2", fixed_code="y = 3",
            explanation="fix", source=FixSource.DETERMINISTIC,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.FAILED


# ─── Integration tests ───────────────────────────────────────────────


class TestFixFile:
    def test_scan_and_fix_pipeline(self, temp_dir):
        """Scan a file, fix findings, verify fixes generated."""
        fp = temp_dir / "test.py"
        fp.write_text('import os\n\ntry:\n    x = 1\nexcept:\n    pass\n', encoding="utf-8")

        from wiz.detector import analyze_file_static
        content = fp.read_text(encoding="utf-8")
        findings = analyze_file_static(str(fp), content, "python")

        report = fix_file(
            str(fp), content, "python", findings,
            dry_run=True, create_backup=False,
        )
        assert report.total_fixes > 0
        assert report.applied > 0

    def test_rules_filter(self, temp_dir):
        """--rules flag filters to specific rules only."""
        fp = temp_dir / "test.py"
        fp.write_text('import os\n\ntry:\n    x = 1\nexcept:\n    pass\n', encoding="utf-8")

        from wiz.detector import analyze_file_static
        content = fp.read_text(encoding="utf-8")
        findings = analyze_file_static(str(fp), content, "python")

        # Only fix bare-except, not unused-import
        report = fix_file(
            str(fp), content, "python", findings,
            dry_run=True, rules=["bare-except"],
        )
        for fix in report.fixes:
            assert fix.rule == "bare-except"

    def test_empty_findings_empty_report(self):
        """No findings produces empty report."""
        report = fix_file("test.py", "x = 1\n", "python", [], dry_run=True)
        assert report.total_fixes == 0
        assert report.applied == 0

    def test_json_output_valid(self, temp_dir):
        """Fix report serializes to valid JSON."""
        fp = temp_dir / "test.py"
        fp.write_text('import os\nx = 1\n', encoding="utf-8")

        from wiz.detector import analyze_file_static
        content = fp.read_text(encoding="utf-8")
        findings = analyze_file_static(str(fp), content, "python")

        report = fix_file(str(fp), content, "python", findings, dry_run=True)
        data = report.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        assert "fixes" in parsed
        assert "total_fixes" in parsed


# ─── CLI tests ────────────────────────────────────────────────────────


def _run_wiz(*args, cwd=None, timeout=30):
    """Run wiz CLI as subprocess."""
    cmd = [sys.executable, "-m", "wiz"] + list(args)
    result = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return result.returncode, stdout, stderr


class TestStringContextHelpers:
    """Tests for _in_multiline_string and _pattern_outside_strings."""

    def test_in_multiline_string_body(self):
        content = 'line1\n"""\ndocstring body\n"""\nline5\n'
        assert _in_multiline_string(content, 3) is True

    def test_not_in_multiline_string(self):
        content = 'line1\n"""\ndocstring body\n"""\nline5\n'
        assert _in_multiline_string(content, 1) is False
        assert _in_multiline_string(content, 5) is False

    def test_single_quote_triple(self):
        content = "line1\n'''\nbody\n'''\nline5\n"
        assert _in_multiline_string(content, 3) is True
        assert _in_multiline_string(content, 5) is False

    def test_pattern_outside_strings_in_code(self):
        import re
        pat = re.compile(r'==\s*None')
        assert _pattern_outside_strings('if x == None:', pat) is True

    def test_pattern_outside_strings_in_double_string(self):
        import re
        pat = re.compile(r'==\s*None')
        assert _pattern_outside_strings('msg = "x == None"', pat) is False

    def test_pattern_outside_strings_in_single_string(self):
        import re
        pat = re.compile(r'==\s*None')
        assert _pattern_outside_strings("msg = 'x == None'", pat) is False


class TestFixHardcodedSecret:
    def test_replaces_string_assignment(self):
        """Replace hardcoded secret with os.environ lookup."""
        line = 'API_KEY = "sk-secret-key-12345"\n'
        finding = _make_finding("hardcoded-secret", line=1)
        fix = _fix_hardcoded_secret(line, finding, line)
        assert fix is not None
        assert fix.fixed_code == 'API_KEY = os.environ["API_KEY"]\n'
        assert fix.source == FixSource.DETERMINISTIC

    def test_replaces_single_quoted(self):
        """Works with single-quoted strings too."""
        line = "DB_PASSWORD = 'admin123'\n"
        finding = _make_finding("hardcoded-secret", line=1)
        fix = _fix_hardcoded_secret(line, finding, line)
        assert fix is not None
        assert 'os.environ["DB_PASSWORD"]' in fix.fixed_code

    def test_preserves_indentation(self):
        """Preserves leading whitespace."""
        line = '    SECRET = "value"\n'
        finding = _make_finding("hardcoded-secret", line=1)
        fix = _fix_hardcoded_secret(line, finding, line)
        assert fix is not None
        assert fix.fixed_code.startswith("    ")

    def test_no_match_non_string(self):
        """Returns None for non-string assignments."""
        line = "x = 42\n"
        finding = _make_finding("hardcoded-secret", line=1)
        fix = _fix_hardcoded_secret(line, finding, line)
        assert fix is None


class TestFixOpenWithoutWith:
    def test_wraps_simple_open(self):
        """Wrap single open() call with no subsequent body."""
        content = 'f = open("file.txt", "r")\n'
        finding = _make_finding("open-without-with", line=1)
        fix = _fix_open_without_with(content.splitlines(keepends=True)[0], finding, content)
        assert fix is not None
        assert "with open" in fix.fixed_code
        assert "as f:" in fix.fixed_code

    def test_wraps_with_body(self):
        """Wrap open() and re-indent subsequent lines that use the variable."""
        content = 'f = open("config.json", "r")\ndata = json.load(f)\nreturn data\n'
        finding = _make_finding("open-without-with", line=1)
        fix = _fix_open_without_with(content.splitlines(keepends=True)[0], finding, content)
        assert fix is not None
        assert "with open" in fix.fixed_code
        assert "    data = json.load(f)" in fix.fixed_code

    def test_preserves_indentation(self):
        """Preserves leading whitespace of the open() call."""
        content = '    f = open("x.txt")\n    data = f.read()\n'
        finding = _make_finding("open-without-with", line=1)
        fix = _fix_open_without_with(content.splitlines(keepends=True)[0], finding, content)
        assert fix is not None
        assert fix.fixed_code.startswith("    with open")

    def test_no_match_non_open(self):
        """Returns None for non-open() lines."""
        line = 'x = some_function("arg")\n'
        finding = _make_finding("open-without-with", line=1)
        fix = _fix_open_without_with(line, finding, line)
        assert fix is None


class TestFixYamlUnsafe:
    def test_basic_replacement(self):
        """Replace yaml.load( with yaml.safe_load(."""
        line = 'data = yaml.load(content)\n'
        fix = _fix_yaml_unsafe(line, _make_finding("yaml-unsafe"), "")
        assert fix is not None
        assert "yaml.safe_load(content)" in fix.fixed_code
        assert fix.source == FixSource.DETERMINISTIC

    def test_skip_when_safe_loader_present(self):
        """Skip if SafeLoader already on the line."""
        line = 'data = yaml.load(content, Loader=yaml.SafeLoader)\n'
        fix = _fix_yaml_unsafe(line, _make_finding("yaml-unsafe"), "")
        assert fix is None

    def test_skip_when_loader_kwarg_present(self):
        """Skip if Loader= kwarg already on the line."""
        line = 'data = yaml.load(content, Loader=yaml.FullLoader)\n'
        fix = _fix_yaml_unsafe(line, _make_finding("yaml-unsafe"), "")
        assert fix is None

    def test_preserves_surrounding_code(self):
        """Other code on the line is preserved."""
        line = '    result = yaml.load(f.read())\n'
        fix = _fix_yaml_unsafe(line, _make_finding("yaml-unsafe"), "")
        assert fix is not None
        assert fix.fixed_code == '    result = yaml.safe_load(f.read())\n'


class TestFixWeakHash:
    def test_md5_to_sha256(self):
        """Replace hashlib.md5( with hashlib.sha256(."""
        line = 'h = hashlib.md5(data)\n'
        fix = _fix_weak_hash(line, _make_finding("weak-hash"), "")
        assert fix is not None
        assert "hashlib.sha256(data)" in fix.fixed_code

    def test_sha1_to_sha256(self):
        """Replace hashlib.sha1( with hashlib.sha256(."""
        line = 'h = hashlib.sha1(data)\n'
        fix = _fix_weak_hash(line, _make_finding("weak-hash"), "")
        assert fix is not None
        assert "hashlib.sha256(data)" in fix.fixed_code

    def test_skip_usedforsecurity_false(self):
        """Skip when usedforsecurity=False is present."""
        line = 'h = hashlib.md5(data, usedforsecurity=False)\n'
        fix = _fix_weak_hash(line, _make_finding("weak-hash"), "")
        assert fix is None

    def test_skip_usedforsecurity_with_spaces(self):
        """Skip usedforsecurity = False with spaces."""
        line = 'h = hashlib.sha1(data, usedforsecurity = False)\n'
        fix = _fix_weak_hash(line, _make_finding("weak-hash"), "")
        assert fix is None


class TestFixUnreachableCode:
    def test_delete_dead_line(self):
        """Delete the unreachable statement."""
        line = '    print("never runs")\n'
        fix = _fix_unreachable_code(line, _make_finding("unreachable-code"), "")
        assert fix is not None
        assert fix.fixed_code == ""

    def test_skip_block_starters(self):
        """Don't delete lines that start blocks (if/for/etc)."""
        line = '    if condition:\n'
        fix = _fix_unreachable_code(line, _make_finding("unreachable-code"), "")
        assert fix is None

    def test_preserves_surrounding(self, temp_dir):
        """Verify that surrounding code is preserved after fix application."""
        fp = temp_dir / "test.py"
        code = 'def foo():\n    return 1\n    x = 2\n    y = 3\n'
        fp.write_text(code, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=3, rule="unreachable-code",
            original_code="    x = 2", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        content = fp.read_text(encoding="utf-8")
        assert "return 1" in content
        assert "y = 3" in content
        assert "x = 2" not in content


class TestFixMutableDefault:
    def test_simple_list(self):
        """Replace def foo(x=[]) with None + guard."""
        content = 'def foo(x=[]):\n    x.append(1)\n'
        fix = _fix_mutable_default(
            content.splitlines(keepends=True)[0],
            _make_finding("mutable-default", line=1), content,
        )
        assert fix is not None
        assert "x=None" in fix.fixed_code
        assert "if x is None:" in fix.fixed_code
        assert "x = []" in fix.fixed_code

    def test_dict_default(self):
        """Replace def foo(d={}) with None + guard."""
        content = 'def foo(d={}):\n    d["key"] = 1\n'
        fix = _fix_mutable_default(
            content.splitlines(keepends=True)[0],
            _make_finding("mutable-default", line=1), content,
        )
        assert fix is not None
        assert "d=None" in fix.fixed_code
        assert "d = {}" in fix.fixed_code

    def test_set_default(self):
        """Replace def foo(s=set()) with None + guard."""
        content = 'def foo(s=set()):\n    s.add(1)\n'
        fix = _fix_mutable_default(
            content.splitlines(keepends=True)[0],
            _make_finding("mutable-default", line=1), content,
        )
        assert fix is not None
        assert "s=None" in fix.fixed_code
        assert "s = set()" in fix.fixed_code

    def test_preserves_indentation(self):
        """Guard lines use correct indentation."""
        content = '    def method(self, items=[]):\n        return items\n'
        fix = _fix_mutable_default(
            content.splitlines(keepends=True)[0],
            _make_finding("mutable-default", line=1), content,
        )
        assert fix is not None
        assert "        if items is None:" in fix.fixed_code
        assert "            items = []" in fix.fixed_code

    def test_no_match_immutable(self):
        """Returns None for immutable defaults."""
        content = 'def foo(x=None):\n    pass\n'
        fix = _fix_mutable_default(
            content.splitlines(keepends=True)[0],
            _make_finding("mutable-default", line=1), content,
        )
        assert fix is None


class TestFixExceptionSwallowed:
    def test_adds_todo_comment(self):
        """Add TODO comment to except: pass."""
        content = 'try:\n    risky()\nexcept Exception:\n    pass\n'
        fix = _fix_exception_swallowed(
            content.splitlines(keepends=True)[2],
            _make_finding("exception-swallowed", line=3), content,
        )
        assert fix is not None
        assert "# TODO: handle this exception" in fix.fixed_code
        assert "pass" in fix.fixed_code

    def test_preserves_except_type(self):
        """The except line itself is not modified."""
        content = 'try:\n    risky()\nexcept ValueError:\n    pass\n'
        fix = _fix_exception_swallowed(
            content.splitlines(keepends=True)[2],
            _make_finding("exception-swallowed", line=3), content,
        )
        assert fix is not None
        # Fix targets the pass line, not the except line
        assert fix.line == 4

    def test_skip_non_pass_body(self):
        """Don't fix if body isn't just `pass`."""
        content = 'try:\n    risky()\nexcept Exception:\n    log(e)\n'
        fix = _fix_exception_swallowed(
            content.splitlines(keepends=True)[2],
            _make_finding("exception-swallowed", line=3), content,
        )
        assert fix is None

    def test_preserves_indentation(self):
        """TODO comment preserves the pass line's indentation."""
        content = 'try:\n    risky()\nexcept:\n        pass\n'
        fix = _fix_exception_swallowed(
            content.splitlines(keepends=True)[2],
            _make_finding("exception-swallowed", line=3), content,
        )
        assert fix is not None
        assert fix.fixed_code.startswith("        pass")


# ─── Multi-line fix (end_line) tests ─────────────────────────────────


class TestMultiLineFix:
    def test_end_line_deletion(self, temp_dir):
        """Deletion fix with end_line blanks out entire range."""
        fp = temp_dir / "test.py"
        fp.write_text("line1\nline2\nline3\nline4\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=2, rule="test",
            original_code="line2", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
            end_line=3,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        assert fp.read_text(encoding="utf-8") == "line1\nline4\n"

    def test_end_line_replacement(self, temp_dir):
        """Replacement fix with end_line replaces first line, blanks rest."""
        fp = temp_dir / "test.py"
        fp.write_text("old1\nold2\nold3\nkeep\n", encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="test",
            original_code="old1", fixed_code="new_combined\n",
            explanation="merge", source=FixSource.DETERMINISTIC,
            end_line=3,
        )
        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        assert fp.read_text(encoding="utf-8") == "new_combined\nkeep\n"

    def test_open_without_with_no_duplication(self, temp_dir):
        """open-without-with fix doesn't duplicate body lines."""
        fp = temp_dir / "test.py"
        code = 'f = open("config.json", "r")\ndata = json.load(f)\nresult = process(data)\n'
        fp.write_text(code, encoding="utf-8")

        content = fp.read_text(encoding="utf-8")
        finding = _make_finding("open-without-with", line=1, file=str(fp))
        fix = _fix_open_without_with(
            content.splitlines(keepends=True)[0], finding, content,
        )
        assert fix is not None
        assert fix.end_line is not None

        result = apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        assert result[0].status == FixStatus.APPLIED
        final = fp.read_text(encoding="utf-8")
        # Body lines should appear exactly once (inside with block)
        assert final.count("json.load(f)") == 1
        assert final.count("process(data)") == 1
        assert "with open" in final


# ─── Integration: scan → fix → verify for new rules ──────────────────


class TestNewFixerIntegration:
    def test_yaml_unsafe_pipeline(self, temp_dir):
        """Scan → fix yaml.load() → verify."""
        fp = temp_dir / "test.py"
        fp.write_text('import yaml\ndata = yaml.load(content)\n', encoding="utf-8")
        content = fp.read_text(encoding="utf-8")
        from wiz.detector import analyze_file_static
        findings = analyze_file_static(str(fp), content, "python")
        yaml_findings = [f for f in findings if f.rule == "yaml-unsafe"]
        assert len(yaml_findings) >= 1
        report = fix_file(str(fp), content, "python", yaml_findings, dry_run=True)
        assert report.applied > 0
        yaml_fixes = [f for f in report.fixes if f.rule == "yaml-unsafe"]
        assert len(yaml_fixes) >= 1
        assert "safe_load" in yaml_fixes[0].fixed_code

    def test_weak_hash_pipeline(self, temp_dir):
        """Scan → fix hashlib.md5 → verify."""
        fp = temp_dir / "test.py"
        fp.write_text('import hashlib\nh = hashlib.md5(data)\n', encoding="utf-8")
        content = fp.read_text(encoding="utf-8")
        from wiz.detector import analyze_file_static
        findings = analyze_file_static(str(fp), content, "python")
        hash_findings = [f for f in findings if f.rule == "weak-hash"]
        assert len(hash_findings) >= 1
        report = fix_file(str(fp), content, "python", hash_findings, dry_run=True)
        assert report.applied > 0

    def test_unreachable_code_pipeline(self, temp_dir):
        """Scan → fix unreachable code → verify."""
        fp = temp_dir / "test.py"
        fp.write_text('def foo():\n    return 1\n    print("dead")\n', encoding="utf-8")
        content = fp.read_text(encoding="utf-8")
        from wiz.detector import analyze_file_static
        findings = analyze_file_static(str(fp), content, "python")
        dead_findings = [f for f in findings if f.rule == "unreachable-code"]
        assert len(dead_findings) >= 1
        report = fix_file(str(fp), content, "python", dead_findings, dry_run=True)
        assert report.applied > 0

    def test_exception_swallowed_pipeline(self, temp_dir):
        """Scan → fix except: pass → verify."""
        fp = temp_dir / "test.py"
        fp.write_text('try:\n    risky()\nexcept Exception:\n    pass\n', encoding="utf-8")
        content = fp.read_text(encoding="utf-8")
        from wiz.detector import analyze_file_static
        findings = analyze_file_static(str(fp), content, "python")
        swallowed = [f for f in findings if f.rule == "exception-swallowed"]
        assert len(swallowed) >= 1
        report = fix_file(str(fp), content, "python", swallowed, dry_run=True)
        assert report.applied > 0

    def test_mutable_default_pipeline(self, temp_dir):
        """Scan → fix mutable default → verify."""
        fp = temp_dir / "test.py"
        fp.write_text('def foo(items=[]):\n    items.append(1)\n    return items\n', encoding="utf-8")
        content = fp.read_text(encoding="utf-8")
        from wiz.detector import analyze_file_static
        findings = analyze_file_static(str(fp), content, "python")
        mutable = [f for f in findings if f.rule == "mutable-default"]
        assert len(mutable) >= 1
        report = fix_file(str(fp), content, "python", mutable, dry_run=True)
        assert report.applied > 0


# ─── Blank-line preservation tests (regression for bug #2) ───────────


class TestBlankLinePreservation:
    def test_blank_lines_between_functions_survive(self, temp_dir):
        """REGRESSION: Blank lines between functions must survive fix application."""
        fp = temp_dir / "test.py"
        code = 'import os\n\n\ndef foo():\n    return 1\n\n\ndef bar():\n    return 2\n'
        fp.write_text(code, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        content = fp.read_text(encoding="utf-8")
        # The two blank lines between functions must still be there
        assert "\n\ndef foo():" in content
        assert "\n\ndef bar():" in content

    def test_blank_lines_in_docstrings_survive(self, temp_dir):
        """REGRESSION: Blank lines inside docstrings must survive fix application."""
        fp = temp_dir / "test.py"
        code = 'import os\n\ndef foo():\n    """Docstring.\n\n    Details.\n    """\n    pass\n'
        fp.write_text(code, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        content = fp.read_text(encoding="utf-8")
        # Blank line inside docstring must survive
        assert '"""Docstring.\n\n    Details.\n    """' in content

    def test_multiple_deletions_preserve_blanks(self, temp_dir):
        """Multiple deletion fixes don't eat surrounding blank lines."""
        fp = temp_dir / "test.py"
        code = 'import os\nimport sys\n\n\ndef main():\n    pass\n'
        fp.write_text(code, encoding="utf-8")
        fixes = [
            Fix(file=str(fp), line=1, rule="unused-import",
                original_code="import os", fixed_code="",
                explanation="rm", source=FixSource.DETERMINISTIC),
            Fix(file=str(fp), line=2, rule="unused-import",
                original_code="import sys", fixed_code="",
                explanation="rm", source=FixSource.DETERMINISTIC),
        ]
        apply_fixes(str(fp), fixes, dry_run=False, create_backup=False)
        content = fp.read_text(encoding="utf-8")
        # Two blank lines before def should still be there
        assert "\n\ndef main():" in content

    def test_replacement_fix_preserves_blanks(self, temp_dir):
        """Replacement fix doesn't eat blank lines elsewhere in file."""
        fp = temp_dir / "test.py"
        code = '    except:\n        pass\n\n\ndef other():\n    return 1\n'
        fp.write_text(code, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="bare-except",
            original_code="    except:", fixed_code="    except Exception:\n",
            explanation="fix", source=FixSource.DETERMINISTIC,
        )
        apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        content = fp.read_text(encoding="utf-8")
        assert "except Exception:" in content
        # Blank lines between except block and def should survive
        assert "\n\ndef other():" in content

    def test_file_with_only_blank_lines_between_functions(self, temp_dir):
        """File where blank lines are the majority separator — all should survive."""
        fp = temp_dir / "test.py"
        code = 'import os\n\n\n\ndef a():\n    pass\n\n\n\ndef b():\n    pass\n'
        fp.write_text(code, encoding="utf-8")
        fix = Fix(
            file=str(fp), line=1, rule="unused-import",
            original_code="import os", fixed_code="",
            explanation="rm", source=FixSource.DETERMINISTIC,
        )
        apply_fixes(str(fp), [fix], dry_run=False, create_backup=False)
        content = fp.read_text(encoding="utf-8")
        # 3 blank lines before def a and 3 blank lines before def b
        assert "\n\n\ndef a():" in content
        assert "\n\n\ndef b():" in content


class TestFixCLI:
    def test_fix_dry_run(self, temp_dir):
        """wiz fix <file> --dry-run exits 0."""
        fp = temp_dir / "test.py"
        fp.write_text('import os\nx = 1\n', encoding="utf-8")
        rc, out, err = _run_wiz("fix", str(fp))
        assert rc == 0

    def test_fix_apply(self, temp_dir):
        """wiz fix <file> --apply creates backup and modifies file."""
        fp = temp_dir / "test.py"
        fp.write_text('import os\nx = 1\n', encoding="utf-8")
        rc, out, err = _run_wiz("fix", str(fp), "--apply")
        assert rc == 0
        backup = Path(str(fp) + ".wiz.bak")
        assert backup.exists()

    def test_fix_help(self):
        """wiz fix --help shows all flags."""
        rc, out, err = _run_wiz("fix", "--help")
        assert rc == 0
        assert "--apply" in out
        assert "--llm" in out
        assert "--rules" in out
        assert "--no-backup" in out
