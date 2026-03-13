"""Scope-based analysis: unused variables, shadowing, uninitialized access.

Walks the scope tree from FileSemantics to detect variables that are assigned
but never read, names that shadow outer scopes, and reads before assignment.
Returns [] when tree-sitter is not available.

Called by: detector.py
Calls into: semantic/core.py (FileSemantics), config.py
Data in → Data out: FileSemantics → list[Finding] (unused vars, shadowing, uninitialized)
"""

from __future__ import annotations  # noqa

from ..types import Category, Finding, Severity, Source
from .core import FileSemantics, ScopeInfo

# ─── Helpers ─────────────────────────────────────────────────────────


def _build_children_map(scopes: list[ScopeInfo]) -> dict[int, list[int]]:
    """Pre-build a parent_id -> [child_scope_ids] lookup dict."""
    children_map: dict[int, list[int]] = {}
    for s in scopes:
        if s.parent_id is not None:
            children_map.setdefault(s.parent_id, []).append(s.scope_id)
    return children_map


def _child_scope_ids(scopes: list[ScopeInfo], scope_id: int) -> set[int]:
    """Get all descendant scope IDs (children, grandchildren, etc.)."""
    children_map = _build_children_map(scopes)
    children = set()
    queue = [scope_id]
    while queue:
        sid = queue.pop()
        for child_id in children_map.get(sid, ()):
            if child_id not in children:
                children.add(child_id)
                queue.append(child_id)
    return children


def _scope_and_children(scopes: list[ScopeInfo], scope_id: int) -> set[int]:
    """Get scope_id plus all descendant scope IDs."""
    result = {scope_id}
    result.update(_child_scope_ids(scopes, scope_id))
    return result


def _scope_and_children_fast(children_map: dict[int, list[int]], scope_id: int) -> set[int]:
    """Get scope_id plus all descendant scope IDs using pre-built children map."""
    result = {scope_id}
    queue = [scope_id]
    while queue:
        sid = queue.pop()
        for child_id in children_map.get(sid, ()):
            if child_id not in result:
                result.add(child_id)
                queue.append(child_id)
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
    "print",
    "len",
    "range",
    "type",
    "int",
    "float",
    "str",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "open",
    "input",
    "sum",
    "min",
    "max",
    "sorted",
    "next",
    "id",
    "map",
    "filter",
    "zip",
    "hash",
    "iter",
    "bytes",
    "complex",
    "frozenset",
    "object",
    "super",
    "True",
    "False",
    "None",
    "Exception",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AttributeError",
    "ImportError",
    "RuntimeError",
    "StopIteration",
    "OSError",
    "IOError",
    "isinstance",
    "issubclass",
    "hasattr",
    "getattr",
    "setattr",
    "delattr",
    "callable",
    "repr",
    "abs",
    "all",
    "any",
    "enumerate",
    "reversed",
    "round",
    "chr",
    "ord",
    "hex",
    "oct",
    "bin",
    "classmethod",
    "staticmethod",
    "property",
    "__name__",
    "__file__",
    "__all__",
    "__doc__",
}


def _is_init_file(filepath: str) -> bool:
    """Return True if *filepath* is an ``__init__.py`` file."""
    import os
    return os.path.basename(filepath) == "__init__.py"


def _extract_all_names(semantics: FileSemantics) -> set[str]:
    """Extract names from ``__all__ = [...]`` if present at module scope."""
    module_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "module"}
    names: set[str] = set()
    for asgn in semantics.assignments:
        if asgn.name == "__all__" and asgn.scope_id in module_scope_ids and asgn.value_text:
            # Parse simple list/tuple of string literals from value_text
            # e.g. ``["foo", "bar", 'baz']`` or ``("a", "b")``
            import re
            for m in re.finditer(r"""['"]([^'"]+)['"]""", asgn.value_text):
                names.add(m.group(1))
    return names


# ─── Check: Unused Variables ─────────────────────────────────────────

# Module-scope call patterns that define type system or framework objects
# (never flagged as unused — they're consumed by type checkers or external imports)
_TYPE_DEFINITION_CALLS = (
    "TypeVar(",
    "TypeAlias(",
    "ParamSpec(",
    "TypeVarTuple(",
    "NewType(",
    "NamedTuple(",
    "TypedDict(",
    "namedtuple(",
)


def _should_skip_assignment(
    asgn: object,
    class_scope_ids: set[int],
    module_scope_ids: set[int],
    all_names: set[str],
    filepath: str,
) -> bool:
    """Return True if this assignment should not be checked for unused status."""
    if asgn.is_parameter or asgn.is_augmented:
        return True
    if any(asgn.name.startswith(p) for p in _IGNORE_PREFIXES):
        return True
    if asgn.value_node_type == "self_attr":
        return True
    if asgn.scope_id in class_scope_ids:
        return True

    # All module-scope checks grouped together
    if asgn.scope_id in module_scope_ids:
        # Type definitions (TypeVar, NewType, etc.)
        if asgn.value_text and any(asgn.value_text.startswith(p) for p in _TYPE_DEFINITION_CALLS):
            return True
        # Public module-level names (likely public API)
        if not asgn.name.startswith("_"):
            return True
        # __init__.py names (almost always re-exports)
        if _is_init_file(filepath):
            return True
        # Names listed in __all__
        if asgn.name in all_names:
            return True

    return False


def _build_name_scope_index(semantics: FileSemantics) -> dict[str, set[int]]:
    """Pre-build a name -> set[scope_id] index from references and calls."""
    index: dict[str, set[int]] = {}
    for ref in semantics.references:
        index.setdefault(ref.name, set()).add(ref.scope_id)
    for call in semantics.function_calls:
        index.setdefault(call.name, set()).add(call.scope_id)
    return index


def _is_name_used(
    name: str,
    visible_scopes: set[int],
    semantics: FileSemantics,
    name_scope_index: dict[str, set[int]] | None = None,
) -> bool:
    """Check if a name is referenced or called in the given scopes."""
    if name_scope_index is not None:
        scopes_with_name = name_scope_index.get(name)
        return scopes_with_name is not None and not scopes_with_name.isdisjoint(visible_scopes)  # doji:ignore(null-dereference) — guarded by short-circuit
    for ref in semantics.references:
        if ref.name == name and ref.scope_id in visible_scopes:
            return True
    for call in semantics.function_calls:
        if call.name == name and call.scope_id in visible_scopes:
            return True
    return False


def check_unused_variables(semantics: FileSemantics, filepath: str) -> list[Finding]:
    """Find variables that are assigned but never read in the same or child scope.

    Excludes: _ prefixed names, augmented assignments (x += 1 implies prior use),
    loop variables used in iteration, parameters, class-scope attributes,
    module-scope type definitions (TypeVar, NewType, etc.).
    """
    findings = []
    class_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "class"}
    module_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "module"}
    all_names = _extract_all_names(semantics)
    children_map = _build_children_map(semantics.scopes)
    name_scope_index = _build_name_scope_index(semantics)

    for asgn in semantics.assignments:
        if _should_skip_assignment(asgn, class_scope_ids, module_scope_ids, all_names, filepath):
            continue

        visible_scopes = _scope_and_children_fast(children_map, asgn.scope_id)
        if not _is_name_used(asgn.name, visible_scopes, semantics, name_scope_index):
            findings.append(
                Finding(
                    file=filepath,
                    line=asgn.line,
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    source=Source.AST,
                    rule="unused-variable",
                    message=f"Variable '{asgn.name}' is assigned but never used",
                    suggestion=f"Remove unused variable '{asgn.name}' or prefix with _",
                )
            )

    return findings


# ─── Check: Variable Shadowing ───────────────────────────────────────

# Common short names that collide everywhere — not worth flagging
_SHADOW_IGNORE_NAMES = frozenset({
    "key", "value", "name", "data", "path", "type", "id", "item", "result",
    "args", "kwargs", "self", "cls", "i", "j", "n", "x", "y", "tag", "gen",
})


def check_variable_shadowing(semantics: FileSemantics, filepath: str) -> list[Finding]:
    """Find variables in inner scopes that shadow names from outer scopes.

    Filters out common false positives:
    - Parameters or locals shadowing class attributes (different scope by design)
    - Names where the "shadowed" definition appears AFTER the shadowing one
    - Very common/short names that collide everywhere (key, value, name, etc.)
    """
    findings = []

    # Build a map: scope_id -> set of assigned names (with line numbers)
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

    # Identify class scope IDs for FP filtering
    class_scope_ids = {s.scope_id for s in semantics.scopes if s.kind == "class"}

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

                # --- FP filter 1: skip common/short names ---
                if name in _SHADOW_IGNORE_NAMES:
                    continue

                # --- FP filter 2: shadowed name must appear BEFORE shadowing ---
                # A variable can't shadow something defined later.
                if outer_line >= line:
                    continue

                # --- FP filter 3: skip class-attr vs function scope ---
                # Parameters and locals in methods naturally reuse class
                # attribute names (name, key, value, etc.). Not a bug.
                if outer_scope_id in class_scope_ids:
                    continue

                outer_scope = scope_map.get(outer_scope_id)
                outer_kind = outer_scope.kind if outer_scope else "outer"
                findings.append(
                    Finding(
                        file=filepath,
                        line=line,
                        severity=Severity.INFO,
                        category=Category.BUG,
                        source=Source.AST,
                        rule="variable-shadowing",
                        message=f"Variable '{name}' shadows name from {outer_kind} scope (line {outer_line})",
                        suggestion=f"Rename '{name}' to avoid shadowing",
                    )
                )

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

        # Skip nonlocal variables (declared as initialized from outer scope)
        if name in semantics.nonlocal_names.get(ref.scope_id, set()):
            continue

        # Check if name is assigned in this scope
        scope_assigns = first_assignment.get(ref.scope_id, {})
        if name in scope_assigns:
            if ref.line < scope_assigns[name]:
                key = (name, ref.scope_id)
                if key not in seen_flagged:
                    seen_flagged.add(key)
                    findings.append(
                        Finding(
                            file=filepath,
                            line=ref.line,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="possibly-uninitialized",
                            message=f"Variable '{name}' may be used before assignment (first assigned line {scope_assigns[name]})",
                            suggestion=f"Ensure '{name}' is assigned before use on all code paths",
                        )
                    )

    return findings
