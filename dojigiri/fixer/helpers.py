"""Shared utilities for the fixer subpackage — string-context, AST, and semantic helpers.

Small helper functions used by deterministic fixers, cascade logic, and the engine.
Extracted to avoid circular imports and keep each module focused on one responsibility.

Called by: deterministic.py, cascade.py, engine.py
Calls into: config.py (types only)
Data in -> Data out: source text + AST nodes -> transformed text / boolean checks
"""

from __future__ import annotations  # noqa

import ast
import logging
import re

logger = logging.getLogger(__name__)


# ─── String-context helpers ───────────────────────────────────────────


_STRING_LITERAL_RE = re.compile(
    r'""".*?"""|'
    r"'''.*?'''|"
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'"
)


def _in_multiline_string(content: str, line_num: int) -> bool:
    """Check if a 1-indexed line is inside a multiline triple-quoted string.

    Uses ast.parse to find all string node line ranges for accuracy.
    Falls back to a simple delimiter-counting heuristic if parsing fails.
    """
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if hasattr(node, "end_lineno") and node.end_lineno is not None:
                    if node.lineno < line_num < node.end_lineno:
                        return True
                    # Same start and end line is a single-line string, skip
        return False
    except SyntaxError as e:
        logger.debug("Failed to parse AST for multiline string check: %s", e)

    # Fallback: simple delimiter counting
    lines = content.splitlines()
    in_triple = False
    current_delimiter = None
    for i, cur_line in enumerate(lines):
        if i + 1 == line_num:
            return in_triple
        stripped = cur_line.strip()
        for tq in ('"""', "'''"):
            count = stripped.count(tq)
            if count % 2 == 1:
                if not in_triple:
                    in_triple = True
                    current_delimiter = tq
                elif tq == current_delimiter:
                    in_triple = False
                    current_delimiter = None
    return False


def _sub_outside_strings(line: str, pattern: str, replacement: str) -> str:
    """Apply regex substitution only to code segments (outside string literals)."""
    parts = []
    last_end = 0
    for m in _STRING_LITERAL_RE.finditer(line):
        # Apply substitution to code segment before this string literal
        code_seg = line[last_end : m.start()]
        parts.append(re.sub(pattern, replacement, code_seg))
        parts.append(m.group())  # preserve string literal unchanged
        last_end = m.end()
    # Handle trailing code segment after last string literal
    parts.append(re.sub(pattern, replacement, line[last_end:]))
    return "".join(parts)


def _pattern_outside_strings(line: str, pattern: re.Pattern) -> bool:
    """Check if pattern matches in code portions of a line (outside string literals)."""
    code_only = _STRING_LITERAL_RE.sub(lambda m: " " * len(m.group()), line)
    return bool(pattern.search(code_only))


# ─── AST helpers ─────────────────────────────────────────────────────


def _find_ast_node(content: str, line: int, node_type: type, predicate: object | None = None) -> ast.AST | None:
    """Parse content, find node of given type at target line matching optional predicate.

    Returns the node or None. Caches parse tree per content id within a call stack.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if not isinstance(node, node_type):
            continue
        if not hasattr(node, "lineno") or node.lineno != line:
            continue
        if predicate is None or predicate(node):
            return node
    return None


def _replace_node_source(content: str, node: ast.AST, replacement_text: str) -> str:
    """Replace the source text of an AST node with new text.

    Uses node.lineno/col_offset/end_lineno/end_col_offset for precise replacement.
    Returns the full modified content string.
    """
    lines = content.splitlines(keepends=True)
    start_line = node.lineno - 1
    start_col = node.col_offset
    end_line = (node.end_lineno - 1) if node.end_lineno else start_line
    end_col = node.end_col_offset if node.end_col_offset else len(lines[end_line])

    # Build prefix (everything before the node) and suffix (everything after)
    prefix = "".join(lines[:start_line]) + lines[start_line][:start_col]
    suffix = lines[end_line][end_col:] + "".join(lines[end_line + 1 :])

    return prefix + replacement_text + suffix


def _extract_name_from_message(message: str) -> str | None:
    """Extract a quoted identifier from a finding message."""
    for pattern in [r"'(\w+)'", r"\"(\w+)\""]:
        m = re.search(pattern, message)
        if m:
            return m.group(1)
    return None


_OP_MAP: dict[type, str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}


def _op_str(op: ast.AST) -> str:
    """Convert an ast comparison operator to its source string."""
    return _OP_MAP.get(type(op), "==")


def _is_empty_mutable(node: ast.AST) -> str | None:
    """If node is an empty mutable literal ([], {}, set()), return its string repr."""
    if isinstance(node, ast.List) and not node.elts:
        return "[]"
    if isinstance(node, ast.Dict) and not node.keys:
        return "{}"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "set"
        and not node.args
        and not node.keywords
    ):
        return "set()"
    return None


# ─── Semantic guard helpers ───────────────────────────────────────────
# Called by fixers when FixContext.semantics is available — provide
# deeper analysis than the detector's initial pass.


def _semantic_import_is_referenced(name: str, semantics: object) -> bool:
    """Check if an import name is referenced anywhere in the file's semantic data.

    Walks all scopes including nested ones — catches re-exports, closure use,
    and attribute-access patterns (e.g. `os.path` after `import os`).
    """
    # Direct name references
    for ref in semantics.references:
        if ref.name == name:
            return True
    # Function calls (e.g. `json.dumps()` — the `json` part is a reference)
    for call in semantics.function_calls:
        if call.receiver == name or call.name == name:
            return True
    return False


def _semantic_var_is_used_in_child_scope(name: str, assign_scope_id: int, semantics: object) -> bool:
    """Check if a variable assigned in scope X is referenced in a child scope.

    This catches closure variables and nested function access that the detector
    might miss because it only checks the immediate scope.
    """
    # Build set of child scope IDs
    child_ids = set()

    def _collect_children(parent_id: int) -> None:
        for scope in semantics.scopes:
            if scope.parent_id == parent_id:
                child_ids.add(scope.scope_id)
                _collect_children(scope.scope_id)

    _collect_children(assign_scope_id)
    if not child_ids:
        return False

    for ref in semantics.references:
        if ref.name == name and ref.scope_id in child_ids:
            return True
    return False


def _semantic_var_in_all_export(name: str, semantics: object) -> bool:
    """Check if a variable is listed in __all__ (re-export)."""
    for assign in semantics.assignments:
        if assign.name == "__all__" and assign.value_text:
            # value_text is the raw source of the RHS — check if our name is in it
            if re.search(r"""['"]""" + re.escape(name) + r"""['"]""", assign.value_text):
                return True
    return False


def _type_map_var_is_non_nullable(name: str, scope_id: int, type_map: object) -> bool:
    """Check FileTypeMap to see if (name, scope_id) has a non-nullable type."""
    # FileTypeMap.types is dict[(var_name, scope_id), TypeInfo]
    type_info = type_map.types.get((name, scope_id))
    if type_info and not type_info.nullable:
        return True
    return False


def _record_fix_metric(rule: str, succeeded: bool, duration_ms: float) -> None:
    """Record a fix attempt in the current metrics session (best-effort)."""
    try:
        from ..metrics import get_session

        session = get_session()
        if session:
            session.record_fix(rule, succeeded, duration_ms)
    except Exception as e:
        logger.debug("Failed to record fix metrics: %s", e)
