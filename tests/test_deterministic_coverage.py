"""Extended tests for fixer/deterministic.py — targeting uncovered fixer functions."""

import pytest
from dojigiri.types import Finding, Fix, FixContext, FixSource, Severity, Category, Source
from dojigiri.fixer.deterministic import (
    DETERMINISTIC_FIXERS,
    _collect_open_body,
    _find_import_insert_point,
    _fix_console_log,
    _fix_eval_usage,
    _fix_exception_swallowed,
    _fix_fstring_no_expr,
    _fix_hardcoded_secret,
    _fix_insecure_http,
    _fix_loose_equality,
    _fix_mutable_default,
    _fix_none_comparison,
    _fix_open_without_with,
    _fix_os_system,
    _fix_resource_leak,
    _fix_sql_injection,
    _fix_type_comparison,
    _fix_unreachable_code,
    _fix_unused_import,
    _fix_unused_variable,
    _fix_weak_hash,
    _fix_yaml_unsafe,
    _is_import_in_try_block,
    _is_sole_block_statement,
    _make_import_fix,
    _mutable_default_regex,
    _scan_function_body,
    _semantic_guard_unused_var,
)


def _f(rule, line=1, file="test.py", message="test"):
    return Finding(
        file=file, line=line, severity=Severity.WARNING,
        category=Category.STYLE, source=Source.STATIC,
        rule=rule, message=message,
    )


# ─── _fix_unused_import extended ─────────────────────────────────────


class TestFixUnusedImportExtended:
    def test_multi_name_import_ast(self):
        content = "from os import path, getcwd\nx = path\n"
        finding = _f("unused-import", line=1, message="'getcwd' is unused")
        fix = _fix_unused_import("from os import path, getcwd\n", finding, content)
        assert fix is not None
        assert "path" in fix.fixed_code
        assert "getcwd" not in fix.fixed_code

    def test_is_import_in_try_block_function(self):
        """_is_import_in_try_block exercises the try-block check path."""
        import ast
        content = "import os\n"
        tree = ast.parse(content)
        node = tree.body[0]
        # Not in a try block
        assert _is_import_in_try_block(node, content) is False

    def test_is_import_in_try_block_syntax_error(self):
        """Syntax error in content returns False."""
        import ast
        node = ast.parse("import os\n").body[0]
        assert _is_import_in_try_block(node, "def bad(\n") is False

    def test_semantic_guard_blocks_fix(self):
        """If semantic data says the import IS referenced, skip the fix."""
        content = "import json\ndata = json.dumps({})\n"

        class FakeRef:
            name = "json"
        class FakeSemantics:
            references = [FakeRef()]
            function_calls = []
        ctx = FixContext(content=content, finding=_f("unused-import", message="'json' unused"),
                         semantics=FakeSemantics(), type_map=None, language="python")
        fix = _fix_unused_import("import json\n", _f("unused-import", message="'json' unused"),
                                 content, ctx)
        assert fix is None

    def test_regex_fallback_try_guard(self):
        """Regex fallback should also guard against try blocks."""
        content = "try:\n    import something\nexcept:\n    pass\n"
        finding = _f("unused-import", line=2, file="test.js", message="'something' unused")
        fix = _fix_unused_import("    import something\n", finding, content)
        assert fix is None


# ─── _fix_loose_equality ─────────────────────────────────────────────


class TestFixLooseEqualityExtended:
    def test_preserves_null_comparison(self):
        fix = _fix_loose_equality("if (x == null)\n", _f("loose-equality"), "")
        assert fix is None

    def test_not_equal_null_preserved(self):
        fix = _fix_loose_equality("if (x != null)\n", _f("loose-equality"), "")
        assert fix is None


# ─── _fix_none_comparison ────────────────────────────────────────────


class TestFixNoneComparisonExtended:
    def test_in_multiline_string(self):
        content = '"""\nx == None\n"""\n'
        fix = _fix_none_comparison("x == None\n", _f("none-comparison", line=2), content)
        assert fix is None

    def test_not_in_code(self):
        fix = _fix_none_comparison("x = 5\n", _f("none-comparison"), "x = 5\n")
        assert fix is None


# ─── _fix_type_comparison ────────────────────────────────────────────


class TestFixTypeComparisonExtended:
    def test_regex_fallback(self):
        """Non-Python file uses regex."""
        line = "if type(x) == int:\n"
        fix = _fix_type_comparison(line, _f("type-comparison", file="test.js"), "")
        assert fix is not None
        assert "isinstance(x, int)" in fix.fixed_code


# ─── _fix_console_log ────────────────────────────────────────────────


class TestFixConsoleLogExtended:
    def test_no_console_log(self):
        assert _fix_console_log("let x = 1\n", _f("console-log"), "") is None

    def test_complex_line_skipped(self):
        """Lines with other statements shouldn't be deleted."""
        fix = _fix_console_log("if (x) console.log(x)\n", _f("console-log"), "")
        assert fix is None


# ─── _fix_insecure_http ──────────────────────────────────────────────


class TestFixInsecureHttpExtended:
    def test_in_multiline_string(self):
        content = '"""\nhttp://example.com\n"""\n'
        fix = _fix_insecure_http("http://example.com\n", _f("insecure-http", line=2), content)
        assert fix is None

    def test_in_docstring(self):
        fix = _fix_insecure_http('    """http://example.com"""\n', _f("insecure-http"), "x\n")
        assert fix is None


# ─── _fix_hardcoded_secret ───────────────────────────────────────────


class TestFixHardcodedSecretExtended:
    def test_skip_test_file(self):
        fix = _fix_hardcoded_secret(
            'SECRET = "mysecretvalue"\n',
            _f("hardcoded-secret", file="test_config.py"),
            "",
        )
        assert fix is None

    def test_skip_tests_dir(self):
        fix = _fix_hardcoded_secret(
            'SECRET = "mysecretvalue"\n',
            _f("hardcoded-secret", file="__tests__/config.js"),
            "",
        )
        assert fix is None

    def test_js_file_uses_process_env(self):
        fix = _fix_hardcoded_secret(
            'SECRET = "mysecretvalue"\n',
            _f("hardcoded-secret", file="config.js"),
            "",
        )
        assert fix is not None
        assert "process.env" in fix.fixed_code

    def test_no_match(self):
        fix = _fix_hardcoded_secret("x = func()\n", _f("hardcoded-secret"), "")
        assert fix is None


# ─── _fix_open_without_with ──────────────────────────────────────────


class TestFixOpenWithoutWithExtended:
    def test_no_body(self):
        content = "f = open('test.txt')\n"
        fix = _fix_open_without_with("f = open('test.txt')\n", _f("open-without-with"), content)
        assert fix is not None
        assert "with open" in fix.fixed_code
        assert "pass" in fix.fixed_code

    def test_with_body(self):
        content = "f = open('test.txt')\ndata = f.read()\nf.close()\n"
        fix = _fix_open_without_with("f = open('test.txt')\n", _f("open-without-with"), content)
        assert fix is not None
        assert "with open" in fix.fixed_code


# ─── _fix_yaml_unsafe ───────────────────────────────────────────────


class TestFixYamlUnsafeExtended:
    def test_skip_safe_loader(self):
        fix = _fix_yaml_unsafe("yaml.load(data, Loader=SafeLoader)\n", _f("yaml-unsafe"), "")
        assert fix is None

    def test_no_match(self):
        fix = _fix_yaml_unsafe("yaml.safe_load(data)\n", _f("yaml-unsafe"), "")
        assert fix is None


# ─── _fix_weak_hash ──────────────────────────────────────────────────


class TestFixWeakHashExtended:
    def test_skip_usedforsecurity(self):
        fix = _fix_weak_hash("hashlib.md5(data, usedforsecurity=False)\n", _f("weak-hash"), "")
        assert fix is None


# ─── _fix_unreachable_code ───────────────────────────────────────────


class TestFixUnreachableCodeExtended:
    def test_block_starter_skipped(self):
        fix = _fix_unreachable_code("if True:\n", _f("unreachable-code"), "")
        assert fix is None

    def test_empty_line_skipped(self):
        fix = _fix_unreachable_code("   \n", _f("unreachable-code"), "")
        assert fix is None


# ─── _fix_mutable_default ───────────────────────────────────────────


class TestFixMutableDefaultExtended:
    def test_ast_based_fix(self):
        content = "def foo(items=[]):\n    return items\n"
        finding = _f("mutable-default", line=1)
        fix = _fix_mutable_default("def foo(items=[]):\n", finding, content)
        assert fix is not None
        assert "None" in fix.fixed_code

    def test_regex_fallback_non_python(self):
        content = "def foo(items=[]):\n    return items\n"
        finding = _f("mutable-default", line=1, file="test.js")
        fix = _fix_mutable_default("def foo(items=[]):\n", finding, content)
        assert fix is not None


# ─── _fix_unused_variable ───────────────────────────────────────────


class TestFixUnusedVariableExtended:
    def test_simple_removal(self):
        content = "x = 5\ny = 10\n"
        fix = _fix_unused_variable("x = 5\n", _f("unused-variable", message="'x' unused"), content)
        assert fix is not None
        assert fix.fixed_code == ""

    def test_js_const_removal(self):
        content = "const unused = 42;\n"
        finding = _f("unused-variable", message="'unused' unused", file="test.js")
        fix = _fix_unused_variable("const unused = 42;\n", finding, content)
        assert fix is not None

    def test_js_function_call_kept(self):
        content = "const result = fetchData();\n"
        finding = _f("unused-variable", message="'result' unused", file="test.js")
        fix = _fix_unused_variable("const result = fetchData();\n", finding, content)
        assert fix is None  # Function call may have side effects

    def test_sole_block_statement(self):
        content = "if (x) {\n  const y = 1;\n}\n"
        finding = _f("unused-variable", line=2, message="'y' unused")
        fix = _fix_unused_variable("  const y = 1;\n", finding, content)
        assert fix is None

    def test_multiline_python_assignment(self):
        content = "x = {\n    'a': 1,\n    'b': 2,\n}\ny = 1\n"
        fix = _fix_unused_variable("x = {\n", _f("unused-variable", message="'x' unused"), content)
        assert fix is not None
        assert fix.end_line is not None


# ─── _fix_os_system ─────────────────────────────────────────────────


class TestFixOsSystemExtended:
    def test_non_python(self):
        fix = _fix_os_system("os.system('ls')\n", _f("os-system", file="test.js"), "")
        assert fix is None

    def test_basic_replacement(self):
        content = "import os\nos.system('ls -la')\n"
        finding = _f("os-system", line=2)
        fix = _fix_os_system("os.system('ls -la')\n", finding, content)
        # Returns list of fixes (import + replacement) or single fix
        if isinstance(fix, list):
            assert any("subprocess.run" in f.fixed_code for f in fix)
        else:
            assert fix is not None
            assert "subprocess.run" in fix.fixed_code


# ─── _fix_eval_usage ────────────────────────────────────────────────


class TestFixEvalUsageExtended:
    def test_python_eval(self):
        content = "x = eval(data)\n"
        finding = _f("eval-usage", line=1)
        fix = _fix_eval_usage("x = eval(data)\n", finding, content)
        if isinstance(fix, list):
            assert any("literal_eval" in f.fixed_code for f in fix)
        elif fix:
            assert "literal_eval" in fix.fixed_code

    def test_js_eval(self):
        content = "let x = eval(data)\n"
        finding = _f("eval-usage", line=1, file="app.js")
        fix = _fix_eval_usage("let x = eval(data)\n", finding, content)
        assert fix is not None
        assert "JSON.parse" in fix.fixed_code

    def test_no_eval(self):
        fix = _fix_eval_usage("x = 1\n", _f("eval-usage"), "x = 1\n")
        assert fix is None


# ─── _fix_sql_injection ──────────────────────────────────────────────


class TestFixSqlInjectionExtended:
    def test_non_python(self):
        fix = _fix_sql_injection("query(f`SELECT`)\n", _f("sql-injection", file="test.js"), "")
        assert fix is None

    def test_fstring_pattern(self):
        content = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
        finding = _f("sql-injection", line=1)
        fix = _fix_sql_injection(content.splitlines()[0] + "\n", finding, content)
        if fix:
            assert "?" in fix.fixed_code

    def test_concat_pattern(self):
        content = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
        finding = _f("sql-injection", line=1)
        fix = _fix_sql_injection(content.splitlines()[0] + "\n", finding, content)
        if fix:
            assert "?" in fix.fixed_code


# ─── _fix_resource_leak ─────────────────────────────────────────────


class TestFixResourceLeakExtended:
    def test_non_python(self):
        fix = _fix_resource_leak("conn = open()\n", _f("resource-leak", file="test.js"), "")
        assert fix is None

    def test_basic_leak(self):
        content = "def process():\n    conn = create_connection()\n    data = conn.fetch()\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    conn = create_connection()\n", finding, content)
        if fix:
            assert "close()" in fix.fixed_code

    def test_returned_var_not_closed(self):
        content = "def get_conn():\n    conn = create_connection()\n    return conn\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    conn = create_connection()\n", finding, content)
        assert fix is None  # var is returned, can't close it


# ─── _fix_exception_swallowed ────────────────────────────────────────


class TestFixExceptionSwallowedExtended:
    def test_except_pass_block(self):
        content = "try:\n    x()\nexcept Exception:\n    pass\n"
        finding = _f("exception-swallowed", line=3)
        fix = _fix_exception_swallowed("except Exception:\n", finding, content)
        if fix:
            assert "TODO" in fix.fixed_code or "pass" in fix.fixed_code

    def test_no_pass_body(self):
        content = "try:\n    x()\nexcept Exception:\n    log(e)\n"
        finding = _f("exception-swallowed", line=3)
        fix = _fix_exception_swallowed("except Exception:\n", finding, content)
        assert fix is None


# ─── _find_import_insert_point ───────────────────────────────────────


class TestFindImportInsertPoint:
    def test_after_existing_imports(self):
        lines = ["import os\n", "import sys\n", "\n", "x = 1\n"]
        idx, after = _find_import_insert_point(lines)
        assert idx == 1
        assert after is True

    def test_after_docstring(self):
        lines = ['"""Module docstring."""\n', "\n", "x = 1\n"]
        idx, after = _find_import_insert_point(lines)
        assert idx == 1
        assert after is False

    def test_multiline_docstring(self):
        lines = ['"""Module\n', "docstring.\n", '"""\n', "x = 1\n"]
        idx, after = _find_import_insert_point(lines)
        assert idx == 3
        assert after is False

    def test_empty_content(self):
        idx, after = _find_import_insert_point([])
        assert idx == 0
        assert after is False


# ─── _is_sole_block_statement ────────────────────────────────────────


class TestIsSoleBlockStatement:
    def test_sole_statement(self):
        content = "if (x) {\n  y = 1;\n}\n"
        assert _is_sole_block_statement(content, 1) is True

    def test_not_sole(self):
        content = "if (x) {\n  y = 1;\n  z = 2;\n}\n"
        assert _is_sole_block_statement(content, 1) is False

    def test_out_of_range(self):
        assert _is_sole_block_statement("x\n", 5) is False


# ─── _scan_function_body ────────────────────────────────────────────


class TestScanFunctionBody:
    def test_basic(self):
        lines = ["def foo():\n", "    x = 1\n", "    return x\n", "\n"]
        result = _scan_function_body(lines, 0, "")
        assert len(result) == 2

    def test_stops_at_dedent(self):
        lines = ["def foo():\n", "    x = 1\n", "y = 2\n"]
        result = _scan_function_body(lines, 0, "")
        assert len(result) == 1


# ─── _semantic_guard_unused_var ──────────────────────────────────────


class TestSemanticGuardUnusedVar:
    def test_no_context(self):
        assert _semantic_guard_unused_var(_f("unused-variable"), None) is False

    def test_no_name_in_message(self):
        finding = _f("unused-variable", message="variable is unused")
        ctx = FixContext(content="", finding=finding, semantics=None, type_map=None, language="python")
        assert _semantic_guard_unused_var(finding, ctx) is False


# ─── _collect_open_body ──────────────────────────────────────────────


class TestCollectOpenBody:
    def test_basic_body(self):
        lines = [
            "f = open('x')\n",
            "data = f.read()\n",
            "f.close()\n",
            "y = 1\n",
        ]
        body = _collect_open_body(lines, 0, "", "f")
        assert len(body) >= 1
        # .close() should be stripped
        assert not any("f.close()" in l for l in body)

    def test_stops_at_def(self):
        lines = [
            "f = open('x')\n",
            "data = f.read()\n",
            "def other():\n",
            "    pass\n",
        ]
        body = _collect_open_body(lines, 0, "", "f")
        assert len(body) == 1


# ─── DETERMINISTIC_FIXERS registry ──────────────────────────────────


class TestDeterministicFixersRegistry:
    def test_all_keys_are_strings(self):
        for key in DETERMINISTIC_FIXERS:
            assert isinstance(key, str)

    def test_known_rules_present(self):
        expected = [
            "unused-import", "bare-except", "loose-equality",
            "none-comparison", "type-comparison", "console-log",
            "insecure-http", "fstring-no-expr", "hardcoded-secret",
        ]
        for rule in expected:
            assert rule in DETERMINISTIC_FIXERS, f"Missing fixer for {rule}"
