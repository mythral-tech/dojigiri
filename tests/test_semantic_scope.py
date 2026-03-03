"""Tests for tree-sitter scope analysis: unused variables, shadowing, uninitialized access."""

import pytest

from wiz.config import Severity, Category, Source

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


def _semantics(code: str, filepath: str = "test.py", language: str = "python"):
    """Extract semantics from a Python code string."""
    from wiz.semantic.core import extract_semantics
    result = extract_semantics(code, filepath, language)
    assert result is not None, "extract_semantics returned None — tree-sitter may not be available"
    return result


# ───────────────────────────────────────────────────────────────────────────
# UNUSED VARIABLES
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestUnusedVariables:
    """Tests for check_unused_variables."""

    def test_assigned_but_never_used(self):
        """Variable assigned but never referenced should produce a finding."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    x = 42
    return None
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        assert len(findings) == 1
        assert findings[0].rule == "unused-variable"
        assert findings[0].severity == Severity.WARNING
        assert findings[0].category == Category.DEAD_CODE
        assert findings[0].source == Source.AST
        assert "'x'" in findings[0].message

    def test_assigned_and_used_no_finding(self):
        """Variable assigned and later used should not be flagged."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    x = 42
    return x
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        assert len(findings) == 0

    def test_underscore_prefixed_excluded(self):
        """Variables with _ prefix should not be flagged as unused."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    _unused = 42
    __private = 99
    return None
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        assert len(findings) == 0

    def test_augmented_assignment_excluded(self):
        """Augmented assignment (x += 1) implies prior use and should not be flagged."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    x = 0
    x += 1
    return x
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        # x is used (augmented assignment creates a reference, and x is returned)
        assert len(findings) == 0

    def test_variable_used_in_child_scope(self):
        """Variable assigned in outer scope and used in inner scope should not be flagged."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def outer():
    data = [1, 2, 3]
    def inner():
        return data
    return inner
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        # data is used in child scope (inner function)
        unused_names = [f.message for f in findings]
        assert not any("'data'" in m for m in unused_names)

    def test_parameter_not_flagged(self):
        """Function parameters should not be flagged by unused variables check."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f(x, y, z):
    return None
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        # Parameters are excluded from unused variable checks
        assert len(findings) == 0

    def test_self_attr_assignment_not_flagged(self):
        """self.attr = value assignments should not be flagged as unused."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
class MyClass:
    def __init__(self):
        self.name = "test"
        self.value = 42
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        # self.attr assignments have value_node_type == "self_attr" and are excluded
        unused_names = [f.message for f in findings]
        assert not any("'name'" in m for m in unused_names)
        assert not any("'value'" in m for m in unused_names)

    def test_multiple_unused_variables(self):
        """Multiple unused variables should produce multiple findings."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    a = 1
    b = 2
    c = 3
    return None
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        unused_names = {f.message for f in findings}
        assert len(findings) == 3
        assert any("'a'" in m for m in unused_names)
        assert any("'b'" in m for m in unused_names)
        assert any("'c'" in m for m in unused_names)

    def test_loop_variable_used_in_body(self):
        """Loop variable used inside the loop body should not be flagged."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    total = 0
    for i in range(10):
        total += i
    return total
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        unused_names = [f.message for f in findings]
        # i is used (referenced in the body), total is used (returned)
        assert not any("'i'" in m for m in unused_names)
        assert not any("'total'" in m for m in unused_names)

    def test_variable_used_as_function_call(self):
        """Variable assigned a callable and then called should not be flagged."""
        from wiz.semantic.scope import check_unused_variables
        code = """\
def f():
    callback = lambda: 42
    result = callback()
    return result
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        unused_names = [f.message for f in findings]
        # callback is used as a function call target
        assert not any("'callback'" in m for m in unused_names)


# ───────────────────────────────────────────────────────────────────────────
# VARIABLE SHADOWING
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestVariableShadowing:
    """Tests for check_variable_shadowing."""

    def test_inner_function_shadows_outer(self):
        """Variable in inner function shadowing outer should produce INFO finding."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    x = 10
    def inner():
        x = 20
        return x
    return inner
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        assert len(findings) >= 1
        shadow_finding = [f for f in findings if "'x'" in f.message]
        assert len(shadow_finding) >= 1
        assert shadow_finding[0].severity == Severity.INFO
        assert shadow_finding[0].category == Category.BUG
        assert shadow_finding[0].source == Source.AST
        assert shadow_finding[0].rule == "variable-shadowing"

    def test_no_shadowing(self):
        """No shadowing should produce no findings."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    x = 10
    def inner():
        y = 20
        return y
    return x
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        assert len(findings) == 0

    def test_underscore_prefixed_not_flagged(self):
        """Underscore-prefixed variables should not be flagged for shadowing."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    _temp = 10
    def inner():
        _temp = 20
        return _temp
    return _temp
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        # _temp starts with _ so should be excluded
        assert len(findings) == 0

    def test_same_scope_redefinition_not_shadowing(self):
        """Reassignment in the same scope is not shadowing."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def f():
    x = 10
    x = 20
    return x
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        # Both assignments are in the same scope, not shadowing
        assert len(findings) == 0

    def test_parameter_shadows_outer_variable(self):
        """Parameter in inner function shadowing an outer variable should be flagged."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    data = [1, 2, 3]
    def inner(data):
        return len(data)
    return inner(data)
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow_data = [f for f in findings if "'data'" in f.message]
        assert len(shadow_data) >= 1
        assert shadow_data[0].rule == "variable-shadowing"

    def test_multiple_levels_of_shadowing(self):
        """Multiple nesting levels with shadowing should produce findings for each."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
def level_one():
    val = 1
    def level_two():
        val = 2
        def level_three():
            val = 3
            return val
        return level_three
    return level_two
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow_val = [f for f in findings if "'val'" in f.message]
        # level_two's val shadows level_one's, level_three's val shadows both
        assert len(shadow_val) >= 2

    def test_class_scope_vs_function_scope(self):
        """Variable in a method that shadows a class-level name should be flagged."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
class MyClass:
    count = 0
    def method(self):
        count = 10
        return count
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow_count = [f for f in findings if "'count'" in f.message]
        assert len(shadow_count) >= 1

    def test_module_level_shadowed_by_function(self):
        """Module-level variable shadowed by a function-level variable should be flagged."""
        from wiz.semantic.scope import check_variable_shadowing
        code = """\
result = None

def compute():
    result = 42
    return result
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow_result = [f for f in findings if "'result'" in f.message]
        assert len(shadow_result) >= 1
        assert shadow_result[0].rule == "variable-shadowing"
        assert "shadows" in shadow_result[0].message


# ───────────────────────────────────────────────────────────────────────────
# UNINITIALIZED VARIABLES
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestUninitializedVariables:
    """Tests for check_uninitialized_variables."""

    def test_used_before_assignment(self):
        """Variable used before assignment in a function should produce a finding."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f():
    y = x + 1
    x = 10
    return y
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        assert len(findings) >= 1
        assert findings[0].rule == "possibly-uninitialized"
        assert findings[0].severity == Severity.WARNING
        assert findings[0].category == Category.BUG
        assert findings[0].source == Source.AST
        assert "'x'" in findings[0].message

    def test_assigned_before_use_no_finding(self):
        """Variable assigned before use should not be flagged."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f():
    x = 10
    y = x + 1
    return y
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        assert len(findings) == 0

    def test_parameter_not_flagged(self):
        """Function parameters are considered assigned and should not be flagged."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f(x, y):
    z = x + y
    return z
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        assert len(findings) == 0

    def test_builtin_name_not_flagged(self):
        """Builtin names (len, print, range, etc.) should not be flagged."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f():
    n = len([1, 2, 3])
    print(n)
    for i in range(n):
        pass
    return n
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        # len, print, range are builtins -- should not be flagged
        uninit_names = [f.message for f in findings]
        assert not any("'len'" in m for m in uninit_names)
        assert not any("'print'" in m for m in uninit_names)
        assert not any("'range'" in m for m in uninit_names)

    def test_underscore_prefixed_not_flagged(self):
        """Underscore-prefixed names should not be flagged for uninitialized access."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f():
    y = _helper + 1
    _helper = 10
    return y
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        uninit_names = [f.message for f in findings]
        assert not any("'_helper'" in m for m in uninit_names)

    def test_module_level_reference_not_checked(self):
        """Module-level references should not be checked (only function scopes)."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
y = x + 1
x = 10
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        # Module scope is excluded from uninitialized checks
        assert len(findings) == 0

    def test_used_at_same_line_as_assignment_no_finding(self):
        """Variable used on the same line as its assignment should not be flagged."""
        from wiz.semantic.scope import check_uninitialized_variables
        code = """\
def f():
    x = 10
    x = x + 1
    return x
"""
        sem = _semantics(code)
        findings = check_uninitialized_variables(sem, "test.py")
        # x is first assigned on line 2, then x = x + 1 on line 3 reads x at line 3
        # which is after assignment at line 2 -- no finding expected
        assert len(findings) == 0
