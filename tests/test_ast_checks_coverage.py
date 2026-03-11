"""Tests for dojigiri/ast_checks.py — AST-based Python checks."""

import pytest
from dojigiri.ast_checks import (
    run_python_ast_checks,
    _build_import_alias_map,
    _check_aliased_dangerous_calls,
    _check_multiline_shell_true,
    _check_getattr_dangerous,
    _check_async_shell,
    _check_sql_fstring,
    _check_hardcoded_secret_defaults,
    _check_mutable_defaults,
    _check_shadowed_builtin_params,
    _count_branches,
    _is_empty_except,
    _is_broad_exception,
    _is_optional_import_pattern,
    _is_stop_iteration_pattern,
    _continue_msg_suffix,
)
from dojigiri.types import Finding
import ast


class TestAliasedDangerousCalls:
    def test_pickle_alias(self):
        code = "import pickle as pkl\npkl.loads(data)\n"
        findings = run_python_ast_checks(code, "test.py")
        rules = [f.rule for f in findings]
        assert "pickle-unsafe" in rules

    def test_no_aliases(self):
        code = "import os\nos.getcwd()\n"
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "pickle-unsafe" for f in findings)

    def test_from_import_alias(self):
        code = "from xml.etree import ElementTree as ET\nET.parse('file.xml')\n"
        findings = run_python_ast_checks(code, "test.py")
        rules = [f.rule for f in findings]
        assert "xxe-risk" in rules


class TestMultilineShellTrue:
    def test_detects_multiline(self):
        code = (
            "import subprocess\n"
            "subprocess.run(\n"
            "    'ls -la',\n"
            "    shell=True,\n"
            ")\n"
        )
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "shell-true" for f in findings)

    def test_no_shell_true(self):
        code = "import subprocess\nsubprocess.run(['ls', '-la'])\n"
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "shell-true" for f in findings)


class TestGetattrDangerous:
    def test_getattr_pickle(self):
        code = "import pickle\nfn = getattr(pickle, 'loads')\nfn(data)\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "pickle-unsafe" for f in findings)

    def test_getattr_os_system(self):
        code = "import os\nfn = getattr(os, 'system')\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "os-system" for f in findings)

    def test_getattr_not_dangerous(self):
        code = "getattr(obj, 'name')\n"
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "pickle-unsafe" for f in findings)


class TestAsyncShell:
    def test_create_subprocess_shell(self):
        code = "import asyncio\nawait asyncio.create_subprocess_shell('ls')\n"
        # Parse may fail due to await outside async, wrap in async function
        code = "import asyncio\nasync def foo():\n    await asyncio.create_subprocess_shell('ls')\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "shell-true" for f in findings)


class TestSqlFstring:
    def test_fstring_in_execute(self):
        code = 'conn.execute(f"SELECT * FROM {table}")\n'
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "sql-injection" for f in findings)

    def test_regular_string_ok(self):
        code = 'conn.execute("SELECT * FROM users")\n'
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "sql-injection" for f in findings)


class TestHardcodedSecretDefaults:
    def test_hardcoded_password_param(self):
        code = 'def connect(password="supersecretpassword123"):\n    pass\n'
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "hardcoded-password-default" for f in findings)

    def test_annotated_field(self):
        code = 'class Config:\n    api_key: str = "my_real_api_key_value"\n'
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "hardcoded-password-default" for f in findings)

    def test_placeholder_ok(self):
        code = 'def connect(password="changeme"):\n    pass\n'
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "hardcoded-password-default" for f in findings)

    def test_short_value_ok(self):
        code = 'def connect(password="abc"):\n    pass\n'
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "hardcoded-password-default" for f in findings)


class TestMutableDefaults:
    def test_list_default(self):
        code = "def foo(items=[]):\n    pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "mutable-default" for f in findings)

    def test_set_call_default(self):
        code = "def foo(items=set()):\n    pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "mutable-default" for f in findings)

    def test_kwonly_default(self):
        code = "def foo(*, items={}):\n    pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "mutable-default" for f in findings)


class TestShadowedBuiltinParams:
    def test_param_shadows(self):
        code = "def foo(list, dict):\n    pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "shadowed-builtin-param" for f in findings)

    def test_self_cls_ok(self):
        code = "class X:\n    def foo(self):\n        pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "shadowed-builtin-param" for f in findings)


class TestCountBranches:
    def test_counts_if_for_while(self):
        code = "def foo():\n    if x:\n        for i in y:\n            while z:\n                pass\n"
        tree = ast.parse(code)
        func = tree.body[0]
        assert _count_branches(func) >= 3

    def test_skips_nested_functions(self):
        code = "def foo():\n    def bar():\n        if x:\n            pass\n"
        tree = ast.parse(code)
        func = tree.body[0]
        count = _count_branches(func)
        # The nested def's if should not be counted
        assert count == 0


class TestContinueMsgSuffix:
    def test_both(self):
        assert "specific exception with comment" in _continue_msg_suffix(True, True)

    def test_comment_only(self):
        assert "comment explains" in _continue_msg_suffix(True, False)

    def test_specific_only(self):
        assert "specific exception" in _continue_msg_suffix(False, True)

    def test_neither(self):
        assert _continue_msg_suffix(False, False) == ""


class TestIsStopIterationPattern:
    def test_matches(self):
        code = "try:\n    next(it)\nexcept StopIteration:\n    pass\n"
        tree = ast.parse(code)
        handler = tree.body[0].handlers[0]
        assert _is_stop_iteration_pattern(handler) is True

    def test_no_match_bare(self):
        code = "try:\n    x()\nexcept:\n    pass\n"
        tree = ast.parse(code)
        handler = tree.body[0].handlers[0]
        assert _is_stop_iteration_pattern(handler) is False

    def test_tuple_form(self):
        code = "try:\n    next(it)\nexcept (StopIteration,):\n    pass\n"
        tree = ast.parse(code)
        handler = tree.body[0].handlers[0]
        assert _is_stop_iteration_pattern(handler) is True


class TestSyntaxError:
    def test_syntax_error_finding(self):
        code = "def bad(\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "syntax-error" for f in findings)


class TestTooManyArgs:
    def test_too_many_args(self):
        code = "def foo(a, b, c, d, e, f, g, h):\n    pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert any(f.rule == "too-many-args" for f in findings)

    def test_self_excluded(self):
        code = "class X:\n    def foo(self, a, b, c, d, e, f, g):\n        pass\n"
        findings = run_python_ast_checks(code, "test.py")
        assert not any(f.rule == "too-many-args" for f in findings)
