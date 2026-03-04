"""Tests for call graph construction and analysis (dead functions, arg mismatches).

Covers:
- build_call_graph: ~8 tests
- find_dead_functions: ~9 tests
- find_arg_count_mismatches: ~8 tests
"""

import pytest

from dojigiri.semantic.core import extract_semantics
from dojigiri.graph.depgraph import DepGraph, FileNode, build_call_graph, CallGraph, FunctionNode
from dojigiri.graph.callgraph import find_dead_functions, find_arg_count_mismatches
from dojigiri.config import Severity, Category, Source

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


# ─── Helpers ──────────────────────────────────────────────────────────


def _make_dep_graph(files_and_imports):
    """Build a DepGraph from a dict of {path: {language, imports}}.

    files_and_imports: dict mapping file paths to dicts with keys:
        - language (str, default "python")
        - imports (list[str], default [])
    """
    graph = DepGraph(root="/test")
    for path, info in files_and_imports.items():
        graph.nodes[path] = FileNode(
            path=path,
            language=info.get("language", "python"),
            imports=set(info.get("imports", [])),
        )
    # Build reverse edges
    for path, node in graph.nodes.items():
        for imp in node.imports:
            if imp in graph.nodes:
                graph.nodes[imp].imported_by.add(path)
    return graph


def _extract(code: str, filepath: str = "test.py", language: str = "python"):
    """Extract semantics from a code string. Returns FileSemantics or None."""
    return extract_semantics(code, filepath, language)


def _build_cg(file_contents: dict, dep_graph=None):
    """Build a call graph from multiple file contents.

    file_contents: dict of {filepath: code_string}
    dep_graph: optional DepGraph (auto-built with no imports if omitted)

    Returns (call_graph, semantics_by_file).
    """
    semantics_by_file = {}
    files_and_imports = {}

    for filepath, code in file_contents.items():
        sem = _extract(code, filepath=filepath)
        if sem is not None:
            semantics_by_file[filepath] = sem
        files_and_imports[filepath] = {"language": "python", "imports": []}

    if dep_graph is None:
        dep_graph = _make_dep_graph(files_and_imports)

    cg = build_call_graph(dep_graph, semantics_by_file)
    return cg, semantics_by_file


# ═════════════════════════════════════════════════════════════════════════
# CALL GRAPH CONSTRUCTION (~8 tests)
# ═════════════════════════════════════════════════════════════════════════


@needs_tree_sitter
class TestBuildCallGraph:

    def test_single_file_caller_callee(self):
        """Function that calls another -> callers/callees populated."""
        code = """\
def foo():
    bar()

def bar():
    pass
"""
        cg, _ = _build_cg({"app.py": code})

        foo_qname = "app.py:foo"
        bar_qname = "app.py:bar"

        assert foo_qname in cg.functions
        assert bar_qname in cg.functions

        # foo calls bar
        assert bar_qname in cg.functions[foo_qname].callees
        # bar is called by foo
        assert foo_qname in cg.functions[bar_qname].callers

    def test_function_with_no_calls(self):
        """A function that calls nothing has empty callees."""
        code = """\
def lonely():
    x = 1
    return x
"""
        cg, _ = _build_cg({"app.py": code})
        qname = "app.py:lonely"
        assert qname in cg.functions
        assert len(cg.functions[qname].callees) == 0

    def test_cross_file_call_resolved_via_imports(self):
        """Call resolved through dep graph import edges."""
        code_a = """\
def helper():
    return 42
"""
        code_b = """\
def main_func():
    helper()
"""
        dep = _make_dep_graph({
            "utils.py": {"language": "python", "imports": []},
            "app.py": {"language": "python", "imports": ["utils.py"]},
        })

        sem_a = _extract(code_a, "utils.py")
        sem_b = _extract(code_b, "app.py")
        semantics = {"utils.py": sem_a, "app.py": sem_b}

        cg = build_call_graph(dep, semantics)

        helper_qname = "utils.py:helper"
        main_qname = "app.py:main_func"

        # Cross-file call resolved
        assert helper_qname in cg.functions[main_qname].callees
        assert main_qname in cg.functions[helper_qname].callers

    def test_unresolved_call_tracked(self):
        """Call to stdlib/external function is tracked as unresolved."""
        code = """\
def process():
    print("hello")
    len([1, 2, 3])
"""
        cg, _ = _build_cg({"app.py": code})

        unresolved_names = [name for (_, name, _) in cg.unresolved_calls]
        assert "print" in unresolved_names
        assert "len" in unresolved_names

    def test_method_call_within_class(self):
        """Method defined in a class is registered with qualified name."""
        code = """\
class MyClass:
    def my_method(self):
        pass
"""
        cg, _ = _build_cg({"app.py": code})

        qname = "app.py:MyClass.my_method"
        assert qname in cg.functions
        assert cg.functions[qname].name == "my_method"
        assert cg.functions[qname].params == ["self"]

    def test_multiple_callers_for_same_function(self):
        """Multiple functions call the same target."""
        code = """\
def target():
    pass

def caller_one():
    target()

def caller_two():
    target()
"""
        cg, _ = _build_cg({"app.py": code})

        target_qname = "app.py:target"
        callers = cg.functions[target_qname].callers
        assert "app.py:caller_one" in callers
        assert "app.py:caller_two" in callers

    def test_recursive_function_self_referencing(self):
        """Recursive function has itself in both callers and callees."""
        code = """\
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)
"""
        cg, _ = _build_cg({"app.py": code})

        qname = "app.py:factorial"
        assert qname in cg.functions[qname].callees
        assert qname in cg.functions[qname].callers

    def test_empty_semantics_empty_call_graph(self):
        """No files / empty semantics -> empty call graph."""
        dep = _make_dep_graph({})
        cg = build_call_graph(dep, {})

        assert len(cg.functions) == 0
        assert len(cg.unresolved_calls) == 0


# ═════════════════════════════════════════════════════════════════════════
# DEAD FUNCTIONS (~9 tests)
# ═════════════════════════════════════════════════════════════════════════


@needs_tree_sitter
class TestFindDeadFunctions:

    def test_uncalled_function_flagged(self):
        """A function that nobody calls should be flagged."""
        code = """\
def used():
    pass

def unused():
    pass

def entry():
    used()
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        dead_names = [f.message for f in findings]
        assert any("unused" in m for m in dead_names)
        assert all(f.rule == "dead-function" for f in findings)
        assert all(f.category == Category.DEAD_CODE for f in findings)
        assert all(f.severity == Severity.INFO for f in findings)

    def test_called_function_not_flagged(self):
        """A function that is called should not appear in findings."""
        code = """\
def helper():
    return 42

def main():
    helper()
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        dead_names = [f.message for f in findings]
        assert not any("helper" in m for m in dead_names)

    def test_main_function_excluded(self):
        """'main' is in _ENTRY_PATTERNS and should be excluded."""
        code = """\
def main():
    pass
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        assert len(findings) == 0

    def test_init_method_excluded(self):
        """__init__ is in _ENTRY_PATTERNS and should be excluded."""
        code = """\
class Foo:
    def __init__(self):
        pass
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        dead_names = [f.message for f in findings]
        assert not any("__init__" in m for m in dead_names)

    def test_test_prefix_function_excluded(self):
        """test_* and test-prefixed functions are excluded."""
        code = """\
def test_something():
    pass

def testAnother():
    pass
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        assert len(findings) == 0

    def test_function_in_init_file_excluded(self):
        """Functions defined in __init__.py are assumed to be re-exports."""
        code = """\
def public_api():
    pass
"""
        cg, _ = _build_cg({"pkg/__init__.py": code})
        dep = _make_dep_graph({"pkg/__init__.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        assert len(findings) == 0

    def test_dunder_method_excluded(self):
        """Dunder methods (__repr__, __str__, etc.) are excluded."""
        code = """\
class Foo:
    def __repr__(self):
        return "Foo"

    def __len__(self):
        return 0
"""
        cg, _ = _build_cg({"app.py": code})
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        dead_names = [f.message for f in findings]
        assert not any("__repr__" in m for m in dead_names)
        assert not any("__len__" in m for m in dead_names)

    def test_function_in_test_file_excluded(self):
        """Functions in test_*.py or *_test.py files are excluded."""
        code = """\
def helper_for_tests():
    pass
"""
        cg, _ = _build_cg({"test_utils.py": code})
        dep = _make_dep_graph({"test_utils.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        assert len(findings) == 0

        # Also check *_test.py pattern
        cg2, _ = _build_cg({"utils_test.py": code})
        dep2 = _make_dep_graph({"utils_test.py": {"language": "python"}})
        findings2 = find_dead_functions(cg2, dep2)

        assert len(findings2) == 0

    def test_anonymous_function_excluded(self):
        """Lambda / anonymous functions should be excluded.

        We simulate this by directly injecting a FunctionNode with name '<anonymous>'
        since Python lambdas are not always parsed as named function_definitions.
        """
        cg = CallGraph()
        cg.functions["app.py:<anonymous>"] = FunctionNode(
            name="<anonymous>",
            qualified_name="app.py:<anonymous>",
            file="app.py",
            line=1,
            params=[],
        )
        dep = _make_dep_graph({"app.py": {"language": "python"}})
        findings = find_dead_functions(cg, dep)

        assert len(findings) == 0


# ═════════════════════════════════════════════════════════════════════════
# ARG COUNT MISMATCHES (~8 tests)
# ═════════════════════════════════════════════════════════════════════════


@needs_tree_sitter
class TestFindArgCountMismatches:

    def test_wrong_arg_count_flagged(self):
        """Calling with wrong number of args produces a finding."""
        code = """\
def greet(name, greeting):
    print(greeting, name)

greet("Alice")
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "arg-count-mismatch"
        assert f.category == Category.BUG
        assert f.severity == Severity.WARNING
        assert "1" in f.message  # called with 1 arg
        assert "2" in f.message  # defined with 2 params

    def test_correct_arg_count_no_finding(self):
        """Calling with correct number of args produces no finding."""
        code = """\
def add(a, b):
    return a + b

result = add(1, 2)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        # Filter only for 'add' related findings
        add_findings = [f for f in findings if "add" in f.message]
        assert len(add_findings) == 0

    def test_varargs_function_skipped(self):
        """Functions with *args should not produce mismatch findings."""
        code = """\
def flexible(*args):
    return sum(args)

flexible(1, 2, 3, 4, 5)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        flexible_findings = [f for f in findings if "flexible" in f.message]
        assert len(flexible_findings) == 0

    def test_method_self_not_counted(self):
        """For methods, 'self' parameter is subtracted from expected count."""
        code = """\
class Calculator:
    def add(self, a, b):
        return a + b

calc = Calculator()
calc.add(1, 2)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        # The call calc.add(1, 2) passes 2 args; definition has (self, a, b)
        # After subtracting self, expected is 2 -> should match
        add_findings = [f for f in findings if "add" in f.message]
        assert len(add_findings) == 0

    def test_cross_file_mismatch_detected(self):
        """Arg mismatch across files is still caught."""
        code_lib = """\
def compute(x, y, z):
    return x + y + z
"""
        code_app = """\
def run():
    compute(1, 2)
"""
        dep = _make_dep_graph({
            "lib.py": {"language": "python", "imports": []},
            "app.py": {"language": "python", "imports": ["lib.py"]},
        })

        sem_lib = _extract(code_lib, "lib.py")
        sem_app = _extract(code_app, "app.py")
        semantics = {"lib.py": sem_lib, "app.py": sem_app}

        cg = build_call_graph(dep, semantics)
        findings = find_arg_count_mismatches(cg, semantics)

        compute_findings = [f for f in findings if "compute" in f.message]
        assert len(compute_findings) >= 1
        f = compute_findings[0]
        assert f.file == "app.py"
        assert "2" in f.message  # called with 2
        assert "3" in f.message  # defined with 3
        assert "lib.py" in f.message  # cross-file reference

    def test_multiple_calls_one_wrong_one_finding(self):
        """Multiple calls to same function, only the wrong one flagged."""
        code = """\
def process(a, b):
    return a + b

process(1, 2)
process(1)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        process_findings = [f for f in findings if "process" in f.message]
        assert len(process_findings) == 1
        assert "1" in process_findings[0].message  # called with 1 arg

    def test_no_matching_definition_no_finding(self):
        """Calling an unresolved function should not produce a mismatch."""
        code = """\
result = unknown_func(1, 2, 3)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        unknown_findings = [f for f in findings if "unknown_func" in f.message]
        assert len(unknown_findings) == 0

    def test_constructor_call_handled(self):
        """Calling ClassName() matches __init__ with self subtracted."""
        code = """\
class Widget:
    def __init__(self, width, height):
        self.width = width
        self.height = height

w = Widget(100, 200)
"""
        cg, sem = _build_cg({"app.py": code})
        findings = find_arg_count_mismatches(cg, sem)

        # Widget(100, 200) calls Widget with 2 args.
        # __init__(self, width, height) has 3 params but self is subtracted -> 2.
        # However, the call is to "Widget", not "__init__", so there may not be
        # a direct name match. Verify no false positive.
        widget_findings = [f for f in findings if "Widget" in f.message]
        assert len(widget_findings) == 0
