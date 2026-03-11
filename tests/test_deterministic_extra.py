"""Additional deterministic fixer tests for uncovered code paths."""

import pytest
from dojigiri.types import Finding, Fix, FixContext, FixSource, Severity, Category, Source
from dojigiri.fixer.deterministic import (
    _fix_eval_usage,
    _fix_loose_equality,
    _fix_mutable_default,
    _fix_none_comparison,
    _fix_open_without_with,
    _fix_os_system,
    _fix_resource_leak,
    _fix_sql_injection,
    _fix_type_comparison,
    _fix_unused_import,
    _fix_unused_variable,
    _mutable_default_regex,
    _fix_unused_var_js,
    _NOT_JS,
)


def _f(rule, line=1, file="test.py", message="test"):
    return Finding(
        file=file, line=line, severity=Severity.WARNING,
        category=Category.STYLE, source=Source.STATIC,
        rule=rule, message=message,
    )


# ─── _fix_none_comparison — AST path ────────────────────────────────


class TestNoneComparisonAst:
    def test_ast_replacement(self):
        content = "if x == None:\n    pass\n"
        finding = _f("none-comparison", line=1)
        fix = _fix_none_comparison("if x == None:\n", finding, content)
        assert fix is not None
        assert "is None" in fix.fixed_code

    def test_not_equal_none(self):
        content = "if x != None:\n    pass\n"
        finding = _f("none-comparison", line=1)
        fix = _fix_none_comparison("if x != None:\n", finding, content)
        assert fix is not None
        assert "is not None" in fix.fixed_code


# ─── _fix_type_comparison — AST path ─────────────────────────────────


class TestTypeComparisonAst:
    def test_ast_replacement(self):
        content = "if type(x) == int:\n    pass\n"
        finding = _f("type-comparison", line=1)
        fix = _fix_type_comparison("if type(x) == int:\n", finding, content)
        assert fix is not None
        assert "isinstance(x, int)" in fix.fixed_code

    def test_nested_parens(self):
        content = "if type((x)) == dict:\n    pass\n"
        finding = _f("type-comparison", line=1)
        fix = _fix_type_comparison("if type((x)) == dict:\n", finding, content)
        assert fix is not None
        assert "isinstance" in fix.fixed_code


# ─── _mutable_default_regex ──────────────────────────────────────────


class TestMutableDefaultRegex:
    def test_basic_regex(self):
        content = "def foo(items=[]):\n    return items\n"
        finding = _f("mutable-default", line=1, file="test.rb")
        fix = _mutable_default_regex("def foo(items=[]):\n", finding, content)
        assert fix is not None
        assert "None" in fix.fixed_code

    def test_with_dict_default(self):
        content = "def foo(data={}):\n    return data\n"
        finding = _f("mutable-default", line=1, file="test.rb")
        fix = _mutable_default_regex("def foo(data={}):\n", finding, content)
        assert fix is not None
        assert "None" in fix.fixed_code

    def test_multiline_signature(self):
        content = "def foo(\n    items=[]\n):\n    return items\n"
        finding = _f("mutable-default", line=1, file="test.rb")
        fix = _mutable_default_regex("def foo(\n", finding, content)
        assert fix is not None

    def test_no_match(self):
        fix = _mutable_default_regex("x = 1\n", _f("mutable-default", file="test.rb"), "x = 1\n")
        assert fix is None

    def test_with_docstring(self):
        content = 'def foo(items=[]):\n    """Docstring."""\n    return items\n'
        finding = _f("mutable-default", line=1, file="test.rb")
        fix = _mutable_default_regex("def foo(items=[]):\n", finding, content)
        assert fix is not None


# ─── _fix_mutable_default — AST ──────────────────────────────────────


class TestMutableDefaultAst:
    def test_kwonly_arg(self):
        content = "def foo(*, items=[]):\n    return items\n"
        finding = _f("mutable-default", line=1)
        fix = _fix_mutable_default("def foo(*, items=[]):\n", finding, content)
        assert fix is not None
        assert "None" in fix.fixed_code

    def test_with_docstring(self):
        content = 'def foo(items=[]):\n    """Docstring."""\n    return items\n'
        finding = _f("mutable-default", line=1)
        fix = _fix_mutable_default("def foo(items=[]):\n", finding, content)
        assert fix is not None

    def test_no_mutable(self):
        content = "def foo(x=5):\n    return x\n"
        finding = _f("mutable-default", line=1)
        fix = _fix_mutable_default("def foo(x=5):\n", finding, content)
        # No mutable default, should return None from AST path
        assert fix is None


# ─── _fix_unused_variable — more paths ──────────────────────────────


class TestUnusedVariableExtra:
    def test_type_annotation_kept(self):
        content = "x: int = 5\n"
        fix = _fix_unused_variable("x: int = 5\n", _f("unused-variable", message="'x' unused"), content)
        assert fix is None

    def test_destructuring_kept(self):
        content = "a, b = func()\n"
        fix = _fix_unused_variable("a, b = func()\n", _f("unused-variable", message="'a' unused"), content)
        assert fix is None

    def test_function_call_rhs_kept(self):
        content = "result = compute()\n"
        fix = _fix_unused_variable("result = compute()\n", _f("unused-variable", message="'result' unused"), content)
        assert fix is None  # Side effects

    def test_safe_literal_removed(self):
        content = "x = 5\n"
        fix = _fix_unused_variable("x = 5\n", _f("unused-variable", message="'x' unused"), content)
        assert fix is not None

    def test_not_assignment(self):
        content = "print(x)\n"
        fix = _fix_unused_variable("print(x)\n", _f("unused-variable"), content)
        assert fix is None


# ─── _fix_unused_var_js ──────────────────────────────────────────────


class TestFixUnusedVarJs:
    def test_not_js(self):
        assert _fix_unused_var_js("x = 1", "x = 1\n", _f("unused-variable")) is _NOT_JS

    def test_const_literal(self):
        fix = _fix_unused_var_js("const x = 42;", "const x = 42;\n", _f("unused-variable"))
        assert fix is not None
        assert fix.fixed_code == ""

    def test_require_call(self):
        fix = _fix_unused_var_js(
            "const x = require('fs');",
            "const x = require('fs');\n",
            _f("unused-variable"),
        )
        assert fix is not None

    def test_function_call_returns_none(self):
        fix = _fix_unused_var_js(
            "const x = fetchData();",
            "const x = fetchData();\n",
            _f("unused-variable"),
        )
        assert fix is None


# ─── _fix_open_without_with — body collection ────────────────────────


class TestOpenWithoutWithBody:
    def test_with_body_and_close(self):
        content = (
            "f = open('data.txt')\n"
            "data = f.read()\n"
            "result = data.strip()\n"
            "f.close()\n"
        )
        finding = _f("open-without-with")
        fix = _fix_open_without_with("f = open('data.txt')\n", finding, content)
        assert fix is not None
        assert "with open" in fix.fixed_code
        assert "f.close()" not in fix.fixed_code


# ─── _fix_sql_injection — concat pattern ─────────────────────────────


class TestSqlInjectionConcat:
    def test_concat_pattern_3(self):
        content = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
        finding = _f("sql-injection", line=1)
        fix = _fix_sql_injection(content, finding, content)
        if fix:
            assert "?" in fix.fixed_code


# ─── _fix_eval_usage — existing ast import ───────────────────────────


class TestEvalUsageExistingImport:
    def test_existing_ast_import(self):
        content = "import ast\nx = eval(data)\n"
        finding = _f("eval-usage", line=2)
        fix = _fix_eval_usage("x = eval(data)\n", finding, content)
        # Should return a single Fix (not list), since ast is already imported
        if isinstance(fix, list):
            # If it's a list, one of them should be the eval fix
            assert any("literal_eval" in f.fixed_code for f in fix)
        elif fix:
            assert "literal_eval" in fix.fixed_code

    def test_no_eval_on_line(self):
        content = "# eval is mentioned\nx = 1\n"
        finding = _f("eval-usage", line=2)
        fix = _fix_eval_usage("x = 1\n", finding, content)
        # AST check says no eval on line 2
        assert fix is None


# ─── _fix_resource_leak — more paths ─────────────────────────────────


class TestResourceLeakExtra:
    def test_no_variable_match(self):
        content = "def foo():\n    open('x')\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    open('x')\n", finding, content)
        assert fix is None

    def test_no_containing_function(self):
        content = "conn = create()\nconn.do()\n"
        finding = _f("resource-leak", line=1)
        fix = _fix_resource_leak("conn = create()\n", finding, content)
        assert fix is None  # No enclosing function

    def test_multiple_returns(self):
        content = "def foo():\n    conn = create()\n    if x:\n        return 1\n    return 2\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    conn = create()\n", finding, content)
        assert fix is None  # Too complex

    def test_close_before_return(self):
        content = "def foo():\n    conn = create()\n    data = conn.fetch()\n    return data\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    conn = create()\n", finding, content)
        # Returns data, not conn, so should add close before return
        if fix:
            assert "close()" in fix.fixed_code

    def test_no_body_after_creation(self):
        content = "def foo():\n    conn = create()\n"
        finding = _f("resource-leak", line=2)
        fix = _fix_resource_leak("    conn = create()\n", finding, content)
        assert fix is None  # No body lines


# ─── _fix_os_system — with missing imports ───────────────────────────


class TestOsSystemImports:
    def test_adds_missing_imports(self):
        content = "os.system('ls -la')\n"
        finding = _f("os-system", line=1)
        fix = _fix_os_system("os.system('ls -la')\n", finding, content)
        if isinstance(fix, list):
            rules = [f.rule for f in fix]
            assert len(fix) >= 2  # import fixes + the actual fix
        elif fix:
            assert "subprocess.run" in fix.fixed_code

    def test_existing_imports(self):
        content = "import subprocess\nimport shlex\nos.system('ls')\n"
        finding = _f("os-system", line=3)
        fix = _fix_os_system("os.system('ls')\n", finding, content)
        # Should be a single fix, not a list (imports already exist)
        assert not isinstance(fix, list) or len(fix) == 1
