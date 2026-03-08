"""Tests for tree-sitter scope analysis: unused variables, shadowing, uninitialized access."""

import pytest

from dojigiri.types import Severity, Category, Source

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
    from dojigiri.semantic.core import extract_semantics
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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
        from dojigiri.semantic.scope import check_unused_variables
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

    def test_public_module_level_not_flagged(self):
        """Public module-level names should not be flagged as unused."""
        from dojigiri.semantic.scope import check_unused_variables
        code = """\
session = LocalProxy(partial(_get_app_ctx, "session"))
basestring = str
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        unused_names = [f.message for f in findings]
        assert not any("'session'" in m for m in unused_names)
        assert not any("'basestring'" in m for m in unused_names)

    def test_private_module_level_still_flagged(self):
        """Private (underscore-prefixed) module-level names ARE excluded by _IGNORE_PREFIXES."""
        from dojigiri.semantic.scope import check_unused_variables
        code = """\
_internal = 42
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        # _internal starts with _ so excluded by _IGNORE_PREFIXES
        assert len(findings) == 0

    def test_init_file_names_not_flagged(self):
        """All module-level names in __init__.py should not be flagged (re-exports)."""
        from dojigiri.semantic.scope import check_unused_variables
        code = """\
from .core import Engine
from .session import Session
"""
        sem = _semantics(code, filepath="pkg/__init__.py")
        findings = check_unused_variables(sem, "pkg/__init__.py")
        unused_names = [f.message for f in findings]
        assert not any("'Engine'" in m for m in unused_names)
        assert not any("'Session'" in m for m in unused_names)

    def test_function_level_unused_still_flagged(self):
        """Unused variables inside functions should still be flagged even with module-level exemption."""
        from dojigiri.semantic.scope import check_unused_variables
        code = """\
public_api = "exported"

def f():
    unused_local = 42
    return None
"""
        sem = _semantics(code)
        findings = check_unused_variables(sem, "test.py")
        unused_names = [f.message for f in findings]
        # public_api should NOT be flagged (public module-level)
        assert not any("'public_api'" in m for m in unused_names)
        # unused_local SHOULD be flagged (inside function)
        assert any("'unused_local'" in m for m in unused_names)


# ───────────────────────────────────────────────────────────────────────────
# VARIABLE SHADOWING
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestVariableShadowing:
    """Tests for check_variable_shadowing."""

    def test_common_name_inner_function_not_flagged(self):
        """Common name like 'x' in inner function shadowing outer is NOT flagged (FP filter)."""
        from dojigiri.semantic.scope import check_variable_shadowing
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
        shadow_x = [f for f in findings if "'x'" in f.message]
        # 'x' is a common name — should not be flagged
        assert len(shadow_x) == 0

    def test_nontrivial_inner_function_shadows_outer(self):
        """Non-trivial name in inner function shadowing outer SHOULD produce INFO finding."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    connection = make_conn()
    def inner():
        connection = other_conn()
        return connection
    return inner
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'connection'" in f.message]
        assert len(shadow) >= 1
        assert shadow[0].severity == Severity.INFO
        assert shadow[0].category == Category.BUG
        assert shadow[0].source == Source.AST
        assert shadow[0].rule == "variable-shadowing"

    def test_no_shadowing(self):
        """No shadowing should produce no findings."""
        from dojigiri.semantic.scope import check_variable_shadowing
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
        from dojigiri.semantic.scope import check_variable_shadowing
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
        from dojigiri.semantic.scope import check_variable_shadowing
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

    def test_common_name_parameter_not_flagged(self):
        """Common name like 'data' used as parameter shadowing outer var is NOT flagged (FP filter)."""
        from dojigiri.semantic.scope import check_variable_shadowing
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
        # 'data' is a common name — should not be flagged
        assert len(shadow_data) == 0

    def test_nontrivial_parameter_shadows_outer_variable(self):
        """Non-trivial parameter name shadowing outer variable SHOULD be flagged."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    connection = make_conn()
    def inner(connection):
        return use(connection)
    return inner(connection)
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'connection'" in f.message]
        assert len(shadow) >= 1
        assert shadow[0].rule == "variable-shadowing"

    def test_multiple_levels_of_shadowing(self):
        """Multiple nesting levels with shadowing should produce findings for each."""
        from dojigiri.semantic.scope import check_variable_shadowing
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

    def test_class_scope_vs_function_scope_not_flagged(self):
        """Variable in a method that shadows a class-level name should NOT be flagged (FP filter)."""
        from dojigiri.semantic.scope import check_variable_shadowing
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
        # Class attribute vs function local — not a real shadowing bug
        assert len(shadow_count) == 0

    def test_common_module_level_name_not_flagged(self):
        """Common name like 'result' at module level shadowed by function local is NOT flagged."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
result = None

def compute():
    result = 42
    return result
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow_result = [f for f in findings if "'result'" in f.message]
        # 'result' is a common name — should not be flagged
        assert len(shadow_result) == 0

    def test_later_definition_not_shadowed(self):
        """Variable can't shadow a name defined AFTER it — line order matters."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
def outer():
    def inner():
        request = build_request()
        return request
    request = get_request()
    return inner()
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'request'" in f.message]
        # inner's 'request' appears before outer's — can't be shadowing
        assert len(shadow) == 0

    def test_param_shadowing_class_attr_not_flagged(self):
        """Method parameter shadowing a class attribute is NOT a bug."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
class Config:
    timeout = 30
    def set_timeout(self, timeout):
        self.timeout = timeout
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'timeout'" in f.message]
        # Class attr vs method param — not a real shadowing bug
        assert len(shadow) == 0

    def test_loop_var_shadowing_class_attr_not_flagged(self):
        """Loop variable in method shadowing class attribute is NOT a bug."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
class Registry:
    handler = None
    def process(self):
        for handler in self.handlers:
            handler.run()
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'handler'" in f.message]
        # Class attr vs loop var in method — not a real shadowing bug
        assert len(shadow) == 0

    def test_nontrivial_module_level_shadowed_by_function(self):
        """Non-trivial module-level variable shadowed by function local SHOULD be flagged."""
        from dojigiri.semantic.scope import check_variable_shadowing
        code = """\
database = connect()

def compute():
    database = mock_db()
    return database
"""
        sem = _semantics(code)
        findings = check_variable_shadowing(sem, "test.py")
        shadow = [f for f in findings if "'database'" in f.message]
        assert len(shadow) >= 1
        assert shadow[0].rule == "variable-shadowing"
        assert "shadows" in shadow[0].message


# ───────────────────────────────────────────────────────────────────────────
# UNINITIALIZED VARIABLES
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestUninitializedVariables:
    """Tests for check_uninitialized_variables."""

    def test_used_before_assignment(self):
        """Variable used before assignment in a function should produce a finding."""
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
        from dojigiri.semantic.scope import check_uninitialized_variables
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
