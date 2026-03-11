"""Tests for dojigiri/fixer/helpers.py — targeting uncovered helper functions."""

import ast
import re
import pytest

from dojigiri.fixer.helpers import (
    _extract_name_from_message,
    _find_ast_node,
    _in_multiline_string,
    _is_empty_mutable,
    _op_str,
    _pattern_outside_strings,
    _record_fix_metric,
    _replace_node_source,
    _semantic_import_is_referenced,
    _semantic_var_in_all_export,
    _semantic_var_is_used_in_child_scope,
    _sub_outside_strings,
    _type_map_var_is_non_nullable,
)


# ─── _in_multiline_string ────────────────────────────────────────────


class TestInMultilineString:
    def test_inside_triple_quoted(self):
        code = 'x = """\nline inside string\n"""\ny = 1'
        assert _in_multiline_string(code, 2) is True

    def test_outside_triple_quoted(self):
        code = 'x = """\nline inside string\n"""\ny = 1'
        assert _in_multiline_string(code, 4) is False

    def test_single_line_string(self):
        code = 'x = "hello"\ny = 1'
        assert _in_multiline_string(code, 2) is False

    def test_syntax_error_fallback(self):
        # Invalid Python triggers fallback heuristic
        code = 'x = """\nline inside\n"""\ny ='
        # The fallback should still work for valid triple-quote structure
        # Line 2 is inside triple quotes
        assert _in_multiline_string(code, 2) is True

    def test_fallback_single_quote_triple(self):
        code = "x = '''\nline inside\n'''\ny = 1\n# garbage ]["
        assert _in_multiline_string(code, 2) is True


# ─── _sub_outside_strings ────────────────────────────────────────────


class TestSubOutsideStrings:
    def test_substitutes_code_only(self):
        line = 'x == None and y = "== None"'
        result = _sub_outside_strings(line, r"==\s*None", "is None")
        assert "x is None" in result
        assert '"== None"' in result

    def test_no_strings(self):
        result = _sub_outside_strings("x == None", r"==\s*None", "is None")
        assert result == "x is None"


# ─── _pattern_outside_strings ────────────────────────────────────────


class TestPatternOutsideStrings:
    def test_pattern_in_code(self):
        assert _pattern_outside_strings("x == None", re.compile(r"==\s*None"))

    def test_pattern_only_in_string(self):
        assert not _pattern_outside_strings('"x == None"', re.compile(r"==\s*None"))


# ─── _find_ast_node ──────────────────────────────────────────────────


class TestFindAstNode:
    def test_finds_import(self):
        code = "import os\nx = 1\n"
        node = _find_ast_node(code, 1, ast.Import)
        assert node is not None

    def test_returns_none_for_wrong_line(self):
        code = "import os\nx = 1\n"
        node = _find_ast_node(code, 2, ast.Import)
        assert node is None

    def test_syntax_error_returns_none(self):
        node = _find_ast_node("def bad(:\n", 1, ast.FunctionDef)
        assert node is None

    def test_with_predicate(self):
        code = "import os\nimport sys\n"
        node = _find_ast_node(code, 1, ast.Import, lambda n: n.names[0].name == "os")
        assert node is not None
        node2 = _find_ast_node(code, 1, ast.Import, lambda n: n.names[0].name == "sys")
        assert node2 is None


# ─── _replace_node_source ────────────────────────────────────────────


class TestReplaceNodeSource:
    def test_replaces_node(self):
        code = "x = 1\ny = 2\n"
        tree = ast.parse(code)
        assign = tree.body[0]  # x = 1
        result = _replace_node_source(code, assign, "z = 99")
        assert "z = 99" in result
        assert "y = 2" in result


# ─── _extract_name_from_message ──────────────────────────────────────


class TestExtractName:
    def test_single_quoted(self):
        assert _extract_name_from_message("Variable 'foo' is unused") == "foo"

    def test_double_quoted(self):
        assert _extract_name_from_message('Import "bar" is unused') == "bar"

    def test_no_match(self):
        assert _extract_name_from_message("No quoted name here") is None


# ─── _op_str ─────────────────────────────────────────────────────────


class TestOpStr:
    def test_all_operators(self):
        assert _op_str(ast.Eq()) == "=="
        assert _op_str(ast.NotEq()) == "!="
        assert _op_str(ast.Lt()) == "<"
        assert _op_str(ast.LtE()) == "<="
        assert _op_str(ast.Gt()) == ">"
        assert _op_str(ast.GtE()) == ">="
        assert _op_str(ast.Is()) == "is"
        assert _op_str(ast.IsNot()) == "is not"
        assert _op_str(ast.In()) == "in"
        assert _op_str(ast.NotIn()) == "not in"

    def test_fallback(self):
        # Unknown operator returns "=="
        assert _op_str(ast.Add()) == "=="


# ─── _is_empty_mutable ──────────────────────────────────────────────


class TestIsEmptyMutable:
    def test_empty_list(self):
        node = ast.parse("[]").body[0].value
        assert _is_empty_mutable(node) == "[]"

    def test_empty_dict(self):
        node = ast.parse("{}").body[0].value
        assert _is_empty_mutable(node) == "{}"

    def test_empty_set_call(self):
        node = ast.parse("set()").body[0].value
        assert _is_empty_mutable(node) == "set()"

    def test_non_empty_list(self):
        node = ast.parse("[1]").body[0].value
        assert _is_empty_mutable(node) is None

    def test_non_mutable(self):
        node = ast.parse("42").body[0].value
        assert _is_empty_mutable(node) is None


# ─── Semantic helpers ────────────────────────────────────────────────


class _FakeRef:
    def __init__(self, name, scope_id=0):
        self.name = name
        self.scope_id = scope_id


class _FakeCall:
    def __init__(self, name, receiver=None):
        self.name = name
        self.receiver = receiver


class _FakeScope:
    def __init__(self, scope_id, parent_id=None):
        self.scope_id = scope_id
        self.parent_id = parent_id


class _FakeAssign:
    def __init__(self, name, value_text=None):
        self.name = name
        self.value_text = value_text


class _FakeSemantics:
    def __init__(self, references=None, function_calls=None, scopes=None, assignments=None):
        self.references = references or []
        self.function_calls = function_calls or []
        self.scopes = scopes or []
        self.assignments = assignments or []


class TestSemanticImportReferenced:
    def test_found_in_references(self):
        sem = _FakeSemantics(references=[_FakeRef("os")])
        assert _semantic_import_is_referenced("os", sem)

    def test_found_in_calls(self):
        sem = _FakeSemantics(function_calls=[_FakeCall("dumps", receiver="json")])
        assert _semantic_import_is_referenced("json", sem)

    def test_not_found(self):
        sem = _FakeSemantics()
        assert not _semantic_import_is_referenced("os", sem)


class TestSemanticVarUsedInChildScope:
    def test_used_in_child(self):
        sem = _FakeSemantics(
            scopes=[_FakeScope(1, parent_id=0), _FakeScope(2, parent_id=1)],
            references=[_FakeRef("x", scope_id=1)],
        )
        assert _semantic_var_is_used_in_child_scope("x", 0, sem)

    def test_not_used_in_child(self):
        sem = _FakeSemantics(
            scopes=[_FakeScope(1, parent_id=0)],
            references=[_FakeRef("x", scope_id=0)],
        )
        assert not _semantic_var_is_used_in_child_scope("x", 0, sem)

    def test_no_children(self):
        sem = _FakeSemantics(scopes=[], references=[])
        assert not _semantic_var_is_used_in_child_scope("x", 0, sem)


class TestSemanticVarInAllExport:
    def test_in_all(self):
        sem = _FakeSemantics(assignments=[_FakeAssign("__all__", "['foo', 'bar']")])
        assert _semantic_var_in_all_export("foo", sem)

    def test_not_in_all(self):
        sem = _FakeSemantics(assignments=[_FakeAssign("__all__", "['bar']")])
        assert not _semantic_var_in_all_export("foo", sem)


class TestTypeMapNonNullable:
    def test_non_nullable(self):
        class FakeType:
            nullable = False
        class FakeMap:
            types = {("x", 0): FakeType()}
        assert _type_map_var_is_non_nullable("x", 0, FakeMap())

    def test_nullable(self):
        class FakeType:
            nullable = True
        class FakeMap:
            types = {("x", 0): FakeType()}
        assert not _type_map_var_is_non_nullable("x", 0, FakeMap())

    def test_not_found(self):
        class FakeMap:
            types = {}
        assert not _type_map_var_is_non_nullable("x", 0, FakeMap())


# ─── _record_fix_metric ─────────────────────────────────────────────


class TestRecordFixMetric:
    def test_no_crash(self):
        """Should not raise even if metrics session is None."""
        _record_fix_metric("test-rule", True, 1.0)
        _record_fix_metric("test-rule", False, 2.0)
