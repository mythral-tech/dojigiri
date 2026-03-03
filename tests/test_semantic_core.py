"""Tests for the semantic extraction layer (wiz.ts_semantic)."""

import pytest
from unittest.mock import patch

from wiz.semantic.core import (
    extract_semantics,
    FileSemantics,
    Assignment,
    NameReference,
    FunctionDef,
    FunctionCall,
    ClassDef,
    ScopeInfo,
)

# Check if tree-sitter is available
try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


# ───────────────────────────────────────────────────────────────────────────
# BASIC EXTRACTION
# ───────────────────────────────────────────────────────────────────────────

class TestBasicExtraction:
    def test_unknown_language_returns_none(self):
        """extract_semantics returns None for an unsupported language."""
        result = extract_semantics("x = 1", "test.bf", "brainfuck")
        assert result is None

    @needs_tree_sitter
    def test_returns_file_semantics_for_python(self):
        """extract_semantics returns a FileSemantics dataclass for valid Python."""
        code = "x = 1\n"
        result = extract_semantics(code, "test.py", "python")
        assert result is not None
        assert isinstance(result, FileSemantics)
        assert result.filepath == "test.py"
        assert result.language == "python"

    @needs_tree_sitter
    def test_module_scope_always_created(self):
        """A module-level scope is always present, even for trivial code."""
        code = "pass\n"
        result = extract_semantics(code, "test.py", "python")
        assert result is not None
        module_scopes = [s for s in result.scopes if s.kind == "module"]
        assert len(module_scopes) == 1
        assert module_scopes[0].parent_id is None
        assert module_scopes[0].name == "test.py"

    @needs_tree_sitter
    def test_empty_file_produces_empty_lists(self):
        """An empty file returns FileSemantics with empty extraction lists."""
        code = ""
        result = extract_semantics(code, "empty.py", "python")
        assert result is not None
        assert result.assignments == []
        assert result.function_defs == []
        assert result.function_calls == []
        assert result.class_defs == []
        # Module scope still present
        assert len(result.scopes) == 1

    def test_returns_none_when_tree_sitter_unavailable(self):
        """When tree-sitter import fails, extract_semantics returns None."""
        with patch.dict("sys.modules", {"tree_sitter_language_pack": None}):
            import importlib
            from wiz.semantic import core as ts_semantic
            importlib.reload(ts_semantic)
            result = ts_semantic.extract_semantics("x = 1\n", "test.py", "python")
            importlib.reload(ts_semantic)
        assert result is None


# ───────────────────────────────────────────────────────────────────────────
# PYTHON ASSIGNMENTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestPythonAssignments:
    def test_simple_assignment(self):
        """Simple `x = 1` creates an Assignment with correct name and line."""
        code = "x = 1\n"
        result = extract_semantics(code, "test.py", "python")
        assigns = [a for a in result.assignments if a.name == "x"]
        assert len(assigns) == 1
        assert assigns[0].line == 1
        assert assigns[0].is_augmented is False
        assert assigns[0].is_parameter is False

    def test_augmented_assignment(self):
        """Augmented `x += 1` has is_augmented=True."""
        code = "x = 0\nx += 1\n"
        result = extract_semantics(code, "test.py", "python")
        augmented = [a for a in result.assignments if a.is_augmented]
        assert len(augmented) == 1
        assert augmented[0].name == "x"
        assert augmented[0].value_node_type == "augmented"

    def test_tuple_unpacking(self):
        """Tuple unpacking `a, b = 1, 2` creates separate Assignment for each name."""
        code = "a, b = 1, 2\n"
        result = extract_semantics(code, "test.py", "python")
        names = {a.name for a in result.assignments}
        assert "a" in names
        assert "b" in names

    def test_self_attr_assignment(self):
        """Assignment to self.attr is detected with value_node_type == 'self_attr'."""
        code = (
            "class Foo:\n"
            "    def __init__(self):\n"
            "        self.bar = 42\n"
        )
        result = extract_semantics(code, "test.py", "python")
        self_attrs = [a for a in result.assignments if a.value_node_type == "self_attr"]
        assert len(self_attrs) >= 1
        assert any(a.name == "bar" for a in self_attrs)

    def test_parameter_assignments(self):
        """Function parameters produce assignments with is_parameter=True."""
        code = "def greet(name, age):\n    pass\n"
        result = extract_semantics(code, "test.py", "python")
        params = [a for a in result.assignments if a.is_parameter]
        param_names = {p.name for p in params}
        assert "name" in param_names
        assert "age" in param_names
        for p in params:
            assert p.value_node_type == "parameter"


# ───────────────────────────────────────────────────────────────────────────
# JAVASCRIPT ASSIGNMENTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestJavaScriptAssignments:
    def test_const_declaration(self):
        """JS `const x = 5` is captured via variable_declarator."""
        code = "const x = 5;\n"
        result = extract_semantics(code, "test.js", "javascript")
        assigns = [a for a in result.assignments if a.name == "x"]
        assert len(assigns) == 1
        assert assigns[0].is_augmented is False

    def test_plain_assignment_expression(self):
        """JS `x = 5` bare assignment_expression is captured."""
        code = "let x;\nx = 5;\n"
        result = extract_semantics(code, "test.js", "javascript")
        # Should have the let declarator and the assignment expression
        x_assigns = [a for a in result.assignments if a.name == "x"]
        assert len(x_assigns) >= 1

    def test_augmented_assignment(self):
        """JS `x += 1` has is_augmented=True."""
        code = "let x = 0;\nx += 1;\n"
        result = extract_semantics(code, "test.js", "javascript")
        augmented = [a for a in result.assignments if a.is_augmented]
        assert len(augmented) >= 1
        assert augmented[0].name == "x"


# ───────────────────────────────────────────────────────────────────────────
# FUNCTION DEFINITIONS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestFunctionDefinitions:
    def test_python_function_with_params(self):
        """Python function definition captures name, params, and line."""
        code = "def add(a, b):\n    return a + b\n"
        result = extract_semantics(code, "test.py", "python")
        funcs = [f for f in result.function_defs if f.name == "add"]
        assert len(funcs) == 1
        assert funcs[0].params == ["a", "b"]
        assert funcs[0].line == 1
        assert funcs[0].parent_class is None

    def test_nested_function_creates_scope(self):
        """A nested function creates a new child scope."""
        code = (
            "def outer():\n"
            "    def inner():\n"
            "        pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        fn_scopes = [s for s in result.scopes if s.kind == "function"]
        assert len(fn_scopes) == 2
        outer_scope = [s for s in fn_scopes if s.name == "outer"]
        inner_scope = [s for s in fn_scopes if s.name == "inner"]
        assert len(outer_scope) == 1
        assert len(inner_scope) == 1

    def test_method_has_parent_class(self):
        """A method defined inside a class has parent_class set."""
        code = (
            "class MyClass:\n"
            "    def my_method(self):\n"
            "        pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        methods = [f for f in result.function_defs if f.name == "my_method"]
        assert len(methods) == 1
        assert methods[0].parent_class == "MyClass"

    def test_qualified_name_for_methods(self):
        """qualified_name is 'Class.method' for methods inside a class."""
        code = (
            "class Calculator:\n"
            "    def compute(self, x):\n"
            "        return x * 2\n"
        )
        result = extract_semantics(code, "test.py", "python")
        methods = [f for f in result.function_defs if f.name == "compute"]
        assert len(methods) == 1
        assert methods[0].qualified_name == "Calculator.compute"

    def test_has_varargs(self):
        """Functions with *args or **kwargs have has_varargs=True."""
        code = "def variadic(*args, **kwargs):\n    pass\n"
        result = extract_semantics(code, "test.py", "python")
        funcs = [f for f in result.function_defs if f.name == "variadic"]
        assert len(funcs) == 1
        assert funcs[0].has_varargs is True


# ───────────────────────────────────────────────────────────────────────────
# FUNCTION CALLS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestFunctionCalls:
    def test_simple_function_call_with_arg_count(self):
        """A simple call like `print(1, 2)` records name and arg_count."""
        code = "print(1, 2)\n"
        result = extract_semantics(code, "test.py", "python")
        calls = [c for c in result.function_calls if c.name == "print"]
        assert len(calls) == 1
        assert calls[0].arg_count == 2
        assert calls[0].receiver is None

    def test_method_call_has_receiver(self):
        """A method call like `obj.method()` sets receiver to 'obj'."""
        code = "items = []\nitems.append(42)\n"
        result = extract_semantics(code, "test.py", "python")
        calls = [c for c in result.function_calls if c.name == "append"]
        assert len(calls) == 1
        assert calls[0].receiver == "items"
        assert calls[0].arg_count == 1

    def test_chained_method_call(self):
        """A chained call like `a.b.c()` captures the method name."""
        code = 'result = "hello".upper().strip()\n'
        result = extract_semantics(code, "test.py", "python")
        call_names = [c.name for c in result.function_calls]
        assert "strip" in call_names

    def test_call_inside_function_scope(self):
        """Calls inside a function have the function's scope_id."""
        code = (
            "def wrapper():\n"
            "    do_something()\n"
        )
        result = extract_semantics(code, "test.py", "python")
        fn_scopes = [s for s in result.scopes if s.kind == "function"]
        assert len(fn_scopes) == 1
        fn_scope_id = fn_scopes[0].scope_id

        calls = [c for c in result.function_calls if c.name == "do_something"]
        assert len(calls) == 1
        assert calls[0].scope_id == fn_scope_id


# ───────────────────────────────────────────────────────────────────────────
# CLASS DEFINITIONS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestClassDefinitions:
    def test_python_class_with_methods(self):
        """A Python class is detected with its name and line."""
        code = (
            "class Animal:\n"
            "    def speak(self):\n"
            "        pass\n"
            "    def eat(self):\n"
            "        pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        classes = [c for c in result.class_defs if c.name == "Animal"]
        assert len(classes) == 1
        assert classes[0].line == 1

    def test_method_count_correct(self):
        """method_count reflects the number of methods in the class."""
        code = (
            "class Vehicle:\n"
            "    def start(self):\n"
            "        pass\n"
            "    def stop(self):\n"
            "        pass\n"
            "    def accelerate(self):\n"
            "        pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        classes = [c for c in result.class_defs if c.name == "Vehicle"]
        assert len(classes) == 1
        assert classes[0].method_count == 3

    def test_attribute_names_from_self_assignments(self):
        """attribute_names collects names assigned via self.x = ..."""
        code = (
            "class Point:\n"
            "    def __init__(self, x, y):\n"
            "        self.x = x\n"
            "        self.y = y\n"
        )
        result = extract_semantics(code, "test.py", "python")
        classes = [c for c in result.class_defs if c.name == "Point"]
        assert len(classes) == 1
        assert "x" in classes[0].attribute_names
        assert "y" in classes[0].attribute_names

    def test_class_scope_created(self):
        """A class definition creates a scope with kind='class'."""
        code = (
            "class Config:\n"
            "    DEBUG = True\n"
        )
        result = extract_semantics(code, "test.py", "python")
        class_scopes = [s for s in result.scopes if s.kind == "class"]
        assert len(class_scopes) == 1
        assert class_scopes[0].name == "Config"


# ───────────────────────────────────────────────────────────────────────────
# SCOPE TRACKING
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestScopeTracking:
    def test_module_scope_is_root(self):
        """The module scope has no parent (parent_id is None)."""
        code = "x = 1\n"
        result = extract_semantics(code, "test.py", "python")
        module = [s for s in result.scopes if s.kind == "module"]
        assert len(module) == 1
        assert module[0].parent_id is None

    def test_function_creates_child_scope(self):
        """A function creates a scope whose parent is the module scope."""
        code = "def f():\n    pass\n"
        result = extract_semantics(code, "test.py", "python")
        fn_scopes = [s for s in result.scopes if s.kind == "function"]
        module_scope = [s for s in result.scopes if s.kind == "module"][0]
        assert len(fn_scopes) == 1
        assert fn_scopes[0].parent_id == module_scope.scope_id

    def test_class_creates_child_scope(self):
        """A class creates a scope whose parent is the module scope."""
        code = "class Foo:\n    pass\n"
        result = extract_semantics(code, "test.py", "python")
        class_scopes = [s for s in result.scopes if s.kind == "class"]
        module_scope = [s for s in result.scopes if s.kind == "module"][0]
        assert len(class_scopes) == 1
        assert class_scopes[0].parent_id == module_scope.scope_id

    def test_nested_functions_create_nested_scopes(self):
        """Nested functions produce a chain of parent scopes."""
        code = (
            "def a():\n"
            "    def b():\n"
            "        def c():\n"
            "            pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        fn_scopes = [s for s in result.scopes if s.kind == "function"]
        assert len(fn_scopes) == 3

    def test_scope_parent_id_chain(self):
        """Scope parent_id forms a correct chain: c -> b -> a -> module."""
        code = (
            "def a():\n"
            "    def b():\n"
            "        def c():\n"
            "            pass\n"
        )
        result = extract_semantics(code, "test.py", "python")
        scope_map = {s.scope_id: s for s in result.scopes}

        scope_c = [s for s in result.scopes if s.name == "c"][0]
        scope_b = [s for s in result.scopes if s.name == "b"][0]
        scope_a = [s for s in result.scopes if s.name == "a"][0]
        scope_mod = [s for s in result.scopes if s.kind == "module"][0]

        assert scope_c.parent_id == scope_b.scope_id
        assert scope_b.parent_id == scope_a.scope_id
        assert scope_a.parent_id == scope_mod.scope_id
        assert scope_mod.parent_id is None


# ───────────────────────────────────────────────────────────────────────────
# CROSS-LANGUAGE
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestCrossLanguage:
    def test_go_function_extraction(self):
        """Go function declarations are extracted with params."""
        code = (
            "package main\n"
            "\n"
            "func add(a int, b int) int {\n"
            "    return a + b\n"
            "}\n"
        )
        result = extract_semantics(code, "main.go", "go")
        assert result is not None
        funcs = [f for f in result.function_defs if f.name == "add"]
        assert len(funcs) == 1
        assert funcs[0].line == 3

    def test_rust_struct_and_impl(self):
        """Rust struct and impl items are detected as class_defs."""
        code = (
            "struct Point {\n"
            "    x: f64,\n"
            "    y: f64,\n"
            "}\n"
            "\n"
            "impl Point {\n"
            "    fn new(x: f64, y: f64) -> Point {\n"
            "        Point { x, y }\n"
            "    }\n"
            "}\n"
        )
        result = extract_semantics(code, "lib.rs", "rust")
        assert result is not None
        class_names = [c.name for c in result.class_defs]
        assert "Point" in class_names
        # The impl block should also produce a class-like entry
        funcs = [f for f in result.function_defs if f.name == "new"]
        assert len(funcs) == 1

    def test_java_class_and_method(self):
        """Java class with methods is detected correctly."""
        code = (
            "public class Calculator {\n"
            "    public int add(int a, int b) {\n"
            "        return a + b;\n"
            "    }\n"
            "    public int subtract(int a, int b) {\n"
            "        return a - b;\n"
            "    }\n"
            "}\n"
        )
        result = extract_semantics(code, "Calculator.java", "java")
        assert result is not None
        classes = [c for c in result.class_defs if c.name == "Calculator"]
        assert len(classes) == 1
        assert classes[0].method_count == 2
        func_names = [f.name for f in result.function_defs]
        assert "add" in func_names
        assert "subtract" in func_names

    def test_js_arrow_function_extraction(self):
        """JavaScript arrow functions are captured as function definitions."""
        code = (
            "const greet = (name) => {\n"
            "    return `Hello ${name}`;\n"
            "};\n"
        )
        result = extract_semantics(code, "test.js", "javascript")
        assert result is not None
        # Arrow functions may be anonymous - check at least one function def exists
        arrow_funcs = [f for f in result.function_defs]
        assert len(arrow_funcs) >= 1
        # The const declaration should capture the variable
        assigns = [a for a in result.assignments if a.name == "greet"]
        assert len(assigns) >= 1
