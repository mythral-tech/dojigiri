"""Scope-based analysis: unused variables, shadowing, uninitialized access.

Operates on FileSemantics extracted by ts_semantic.py.
Returns [] when tree-sitter is not available.
"""

from __future__ import annotations

from .config import Finding, Severity, Category, Source
from .ts_semantic import FileSemantics, ScopeInfo


# ─── Helpers ─────────────────────────────────────────────────────────

def _child_scope_ids(scopes: list[ScopeInfo], scope_id: int) -> set[int]:
    """Get all descendant scope IDs (children, grandchildren, etc.)."""
    children = set()
    queue = [scope_id]
    while queue:
        sid = queue.pop()
        for s in scopes:
            if s.parent_id == sid and s.scope_id not in children:
                children.add(s.scope_id)
                queue.append(s.scope_id)
    return children


def _scope_and_children(scopes: list[ScopeInfo], scope_id: int) -> set[int]:
    """Get scope_id plus all descendant scope IDs."""
    result = {scope_id}
    result.update(_child_scope_ids(scopes, scope_id))
    return result


def _ancestor_scope_ids(scopes: list[ScopeInfo], scope_id: int) -> list[int]:
    """Get ancestor scope IDs from immediate parent up to module."""
    scope_map = {s.scope_id: s for s in scopes}
    ancestors = []
    current = scope_id
    while current in scope_map:
        parent = scope_map[current].parent_id
        if parent is None:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


# Names to never flag as unused
_IGNORE_PREFIXES = ("_",)
_PYTHON_BUILTINS = {
    "print", "len", "range", "type", "int", "float", "str", "bool",
    "list", "dict", "set", "tuple", "open", "input", "sum", "min",
    "max", "sorted", "next", "id", "map", "filter", "zip", "hash",
    "iter", "bytes", "complex", "frozenset", "object", "super",
    "True", "False", "None", "Exception", "ValueError", "TypeError",
    "KeyError", "IndexError", "AttributeError", "ImportError",
    "RuntimeError", "StopIteration", "OSError", "IOError",
    "isinstance", "issubclass", "hasattr", "getattr", "setattr",
    "delattr", "callable", "repr", "abs", "all", "any", "enumerate",
    "reversed", "round", "chr", "ord", "hex", "oct", "bin",
    "classmethod", "staticmethod", "property",
    "__name__", "__file__", "__all__", "__doc__",
}


# ─── Check: Unused Variables ─────────────────────────────────────────

# Module-scope call patterns that define type system or framework objects
# (never flagged as unused — they're consumed by type checkers or external imports)
_TYPE_DEFINITION_CALLS = (
    "TypeVar(", "TypeAlias(", "ParamSpec(", "TypeVarTuple(",
    "NewType(", "NamedTuple(", "TypedDict(",
    "namedtuple(",
)


def check_unused_variables(semantics: FileSemantics, filepath: str) -> list[Finding]:
    """Find variables that are assigned but never read in the same or child scope.

    Excludes: _ prefixed names, augmented assignments (x += 1 implies prior use),
    loop variables used in iteration, parameters, class-scope attributes,
    module-scope type definitions (TypeVar, NewType, etc.).
    """
    findings = []

    # Build set of class scope IDs to skip class-level attribute declarations
    # (Pydantic fields, dataclass fields, TypeVars, typed annotations, etc.)
    class_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "class"}

    # Build set of module scope IDs
    module_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "module"}

    for asgn in semantics.assignments:
        # Skip parameters (handled differently), augmented, and _ prefixed
        if asgn.is_parameter:
            continue
        if asgn.is_augmented:
            continue
        if any(asgn.name.startswith(p) for p in _IGNORE_PREFIXES):
            continue
        # Skip self.attr assignments
        if asgn.value_node_type == "self_attr":
            continue
        # Skip class-scope assignments — these are attribute declarations,
        # not unused local variables (Pydantic fields, TypeVars, etc.)
        if asgn.scope_id in class_scope_ids:
            continue
        # Skip module-scope type definitions (TypeVar, NewType, NamedTuple, etc.)
        # These are consumed by type checkers or imported by other modules.
        if asgn.scope_id in module_scope_ids and asgn.value_text:
            if any(asgn.value_text.startswith(p) for p in _TYPE_DEFINITION_CALLS):
                continue

        # Check if name is referenced in this scope or any child scope
        visible_scopes = _scope_and_children(semantics.scopes, asgn.scope_id)

        used = False
        for ref in semantics.references:
            if ref.name == asgn.name and ref.scope_id in visible_scopes:
                used = True
                break

        # Also check if used as a function call target
        if not used:
            for call in semantics.function_calls:
                if call.name == asgn.name and call.scope_id in visible_scopes:
                    used = True
                    break

        if not used:
            findings.append(Finding(
                file=filepath,
                line=asgn.line,
                severity=Severity.WARNING,
                category=Category.DEAD_CODE,
                source=Source.AST,
                rule="unused-variable",
                message=f"Variable '{asgn.name}' is assigned but never used",
                suggestion=f"Remove unused variable '{asgn.name}' or prefix with _",
            ))

    return findings


# ─── Check: Variable Shadowing ───────────────────────────────────────

def check_variable_shadowing(semantics: FileSemantics, filepath: str) -> list[Finding]:
    """Find variables in inner scopes that shadow names from outer scopes.

    Only checks assignments (not parameters — those have their own check).
    """
    findings = []

    # Build a map: scope_id -> set of assigned names
    scope_names: dict[int, dict[str, int]] = {}  # scope_id -> {name: line}
    for asgn in semantics.assignments:
        if asgn.name.startswith("_"):
            continue
        scope_names.setdefault(asgn.scope_id, {})[asgn.name] = asgn.line

    # Also include parameters
    for asgn in semantics.assignments:
        if asgn.is_parameter and not asgn.name.startswith("_"):
            scope_names.setdefault(asgn.scope_id, {})[asgn.name] = asgn.line

    # For each non-module scope, check if any assigned name exists in an ancestor
    scope_map = {s.scope_id: s for s in semantics.scopes}

    for scope in semantics.scopes:
        if scope.kind == "module":
            continue

        names_in_scope = scope_names.get(scope.scope_id, {})
        if not names_in_scope:
            continue

        # Get ancestor names
        ancestor_names: dict[str, tuple[int, int]] = {}  # name -> (scope_id, line)
        for anc_id in _ancestor_scope_ids(semantics.scopes, scope.scope_id):
            for name, line in scope_names.get(anc_id, {}).items():
                if name not in ancestor_names:
                    ancestor_names[name] = (anc_id, line)

        for name, line in names_in_scope.items():
            if name in ancestor_names:
                outer_scope_id, outer_line = ancestor_names[name]
                outer_scope = scope_map.get(outer_scope_id)
                outer_kind = outer_scope.kind if outer_scope else "outer"
                findings.append(Finding(
                    file=filepath,
                    line=line,
                    severity=Severity.INFO,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="variable-shadowing",
                    message=f"Variable '{name}' shadows name from {outer_kind} scope (line {outer_line})",
                    suggestion=f"Rename '{name}' to avoid shadowing",
                ))

    return findings


# ─── Check: Possibly Uninitialized Variables ─────────────────────────

def check_uninitialized_variables(semantics: FileSemantics, filepath: str) -> list[Finding]:
    """Find variables referenced before any assignment in the same scope.

    Conservative linear-order check (no CFG). Only flags when a reference
    appears at a line strictly before any assignment in the same scope.
    Excludes: parameters, imports, builtins, module-scope names, loop variables,
    attribute access references (obj.attr is not a local variable).
    """
    findings = []
    seen_flagged: set[tuple[str, int]] = set()

    # Build per-scope assignment info: {scope_id: {name: first_assignment_line}}
    first_assignment: dict[int, dict[str, int]] = {}
    for asgn in semantics.assignments:
        scope_assigns = first_assignment.setdefault(asgn.scope_id, {})
        if asgn.name not in scope_assigns or asgn.line < scope_assigns[asgn.name]:
            scope_assigns[asgn.name] = asgn.line

    # Build set of parameter names per scope (parameters are always initialized)
    param_names: dict[int, set[str]] = {}
    for asgn in semantics.assignments:
        if asgn.is_parameter:
            param_names.setdefault(asgn.scope_id, set()).add(asgn.name)

    # Build set of for-loop variable names per scope
    loop_var_names: dict[int, set[str]] = {}
    for asgn in semantics.assignments:
        if asgn.value_node_type == "loop_variable":
            loop_var_names.setdefault(asgn.scope_id, set()).add(asgn.name)

    # Only check function scopes (not module or class — those are more permissive)
    func_scopes = {s.scope_id for s in semantics.scopes if s.kind == "function"}

    for ref in semantics.references:
        if ref.scope_id not in func_scopes:
            continue

        name = ref.name
        if name in _PYTHON_BUILTINS:
            continue
        if name.startswith("_"):
            continue

        # Skip attribute access references — obj.attr is not a local variable
        if ref.context == "attribute_access":
            continue

        # Skip names that are parameters in this function scope
        if name in param_names.get(ref.scope_id, set()):
            continue

        # Skip for-loop variables (they are initialized by the loop)
        if name in loop_var_names.get(ref.scope_id, set()):
            continue

        # Check if name is assigned in this scope
        scope_assigns = first_assignment.get(ref.scope_id, {})
        if name in scope_assigns:
            if ref.line < scope_assigns[name]:
                key = (name, ref.scope_id)
                if key not in seen_flagged:
                    seen_flagged.add(key)
                    findings.append(Finding(
                        file=filepath,
                        line=ref.line,
                        severity=Severity.WARNING,
                        category=Category.BUG,
                        source=Source.AST,
                        rule="possibly-uninitialized",
                        message=f"Variable '{name}' may be used before assignment (first assigned line {scope_assigns[name]})",
                        suggestion=f"Ensure '{name}' is assigned before use on all code paths",
                    ))

    return findings
