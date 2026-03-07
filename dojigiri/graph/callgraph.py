"""Dead function detection and argument count mismatch analysis.

Operates on the CallGraph and DepGraph built by depgraph.build_call_graph().
Identifies functions that are defined but never called, and call sites where
the argument count doesn't match the function signature.

Called by: graph/project.py (lazy import inside analyze_project)
Calls into: graph/depgraph.py (CallGraph, DepGraph), config.py (Finding, Severity, etc.)
Data in -> Data out: CallGraph + DepGraph -> list[Finding]
"""

from __future__ import annotations

from pathlib import Path

from ..types import Finding, Severity, Category, Source
from .depgraph import CallGraph, DepGraph


# Names/patterns to exclude from dead function detection
_ENTRY_PATTERNS = {
    "main", "__init__", "__new__", "__del__", "__repr__", "__str__",
    "__eq__", "__hash__", "__lt__", "__le__", "__gt__", "__ge__",
    "__len__", "__iter__", "__next__", "__getitem__", "__setitem__",
    "__delitem__", "__contains__", "__enter__", "__exit__",
    "__call__", "__bool__", "__getattr__", "__setattr__",
    "__get__", "__set__", "__delete__",
    "setUp", "tearDown", "setUpClass", "tearDownClass",
    "setup_method", "teardown_method",
}

_TEST_PREFIXES = ("test_", "test")


def _is_init_file(filepath: str) -> bool:
    return Path(filepath).name == "__init__.py"


def _is_test_file(filepath: str) -> bool:
    name = Path(filepath).name
    return name.startswith("test_") or name.endswith("_test.py")


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


# ─── Check: Dead Functions ───────────────────────────────────────────

def find_dead_functions(
    call_graph: CallGraph,
    dep_graph: DepGraph,
) -> list[Finding]:
    """Find functions that are defined but never called.

    Excludes:
    - main, __init__, dunder methods
    - test_* functions
    - Functions in __init__.py (likely re-exports)
    - Functions with decorators (may be registered externally)
    """
    findings = []

    for qname, fnode in call_graph.functions.items():
        # Skip if has callers
        if fnode.callers:
            continue

        name = fnode.name
        filepath = fnode.file

        # Exclusions
        if name in _ENTRY_PATTERNS:
            continue
        if _is_dunder(name):
            continue
        if any(name.startswith(p) for p in _TEST_PREFIXES):
            continue
        if _is_init_file(filepath):
            continue
        if _is_test_file(filepath):
            continue
        if name == "<anonymous>":
            continue

        # Skip class methods with common framework patterns
        if "." in fnode.qualified_name.split(":", 1)[-1]:
            # It's a method — more likely to be called via dispatch
            # Only flag if we're fairly confident
            continue

        findings.append(Finding(
            file=filepath,
            line=fnode.line,
            severity=Severity.INFO,
            category=Category.DEAD_CODE,
            source=Source.AST,
            rule="dead-function",
            message=f"Function '{name}' is defined but never called",
            suggestion=f"Remove '{name}' if it's not needed, or add a caller",
        ))

    return findings


# ─── Check: Argument Count Mismatches ────────────────────────────────

def find_arg_count_mismatches(
    call_graph: CallGraph,
    semantics_by_file: dict,
) -> list[Finding]:
    """Find call sites where argument count differs from definition.

    Skips functions with *args/**kwargs (varargs).
    """
    findings = []
    seen = set()  # avoid duplicate reports

    for rel_path, sem in semantics_by_file.items():
        for call in sem.function_calls:
            call_name = call.name
            if not call_name:
                continue

            # Find matching function definition(s)
            for qname, fnode in call_graph.functions.items():
                if fnode.name != call_name:
                    continue
                if fnode.has_varargs:
                    continue

                expected = len(fnode.params)
                actual = call.arg_count

                # For methods, account for self/this not being passed explicitly
                parts = fnode.qualified_name.split(":", 1)[-1]
                if "." in parts and fnode.params and fnode.params[0] in ("self", "cls", "this"):
                    expected -= 1

                if actual != expected and expected >= 0:
                    key = (rel_path, call.line, call_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Determine if cross-file
                    target_file = fnode.file
                    if target_file == rel_path:
                        findings.append(Finding(
                            file=rel_path,
                            line=call.line,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="arg-count-mismatch",
                            message=(
                                f"Function '{call_name}' called with {actual} arg(s), "
                                f"but defined with {expected} parameter(s) (line {fnode.line})"
                            ),
                            suggestion=f"Check argument count for '{call_name}'",
                        ))
                    else:
                        findings.append(Finding(
                            file=rel_path,
                            line=call.line,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="arg-count-mismatch",
                            message=(
                                f"Function '{call_name}' called with {actual} arg(s), "
                                f"but defined with {expected} parameter(s) "
                                f"in {target_file}:{fnode.line}"
                            ),
                            suggestion=f"Check argument count for '{call_name}'",
                        ))
                    break  # Only report first match per call site

    return findings
