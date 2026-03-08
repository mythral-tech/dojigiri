"""Cascade derivation logic — predicts side-effect findings after fixes.

Instead of a static rule-to-rule whitelist, analyzes the AST to derive which
imports/variables will become unused after fixes modify their only usage sites.
This handles ALL rules automatically.

Called by: engine.py (fix_file uses derive_expected_cascades for rollback decisions)
Calls into: config.py (FixStatus, Fix types)
Data in -> Data out: file content + applied fixes + semantics -> set of rule names
"""

import ast
from ..types import Fix, FixStatus


def _get_fix_affected_lines(applied_fixes: list[Fix]) -> tuple[set[int], set[int]]:
    """Collect line numbers affected by applied fixes.

    Returns (deleted_lines, modified_lines):
    - deleted_lines: lines where the fix removes content entirely
    - modified_lines: lines where the fix replaces content (may still use imports)

    This distinction matters for cascade prediction: a deleted line guarantees
    the usage is gone, but a modified line might still reference the import.
    """
    deleted: set[int] = set()
    modified: set[int] = set()
    for fix in applied_fixes:
        if fix.status != FixStatus.APPLIED:
            continue
        start = fix.line
        end = fix.end_line or fix.line
        lines = set(range(start, end + 1))
        if not fix.fixed_code or not fix.fixed_code.strip():
            deleted |= lines
        else:
            modified |= lines
    return deleted, modified


def _derive_unused_imports_python(
    content: str,
    deleted_lines: set[int],
    modified_lines: set[int],
    applied_fixes: list[Fix] | None = None,
) -> bool:
    """Check if any Python import's only usages all fall on deleted/modified lines.

    Returns True if at least one import will become unused due to fixes.
    Uses Python's ast for accurate import->usage tracking.

    Deleted lines are safe -- the usage is definitely gone. Modified lines
    require checking whether the replacement text still references the import.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False

    # Build: name -> import_line
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                imported[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                name = alias.asname or alias.name
                imported[name] = node.lineno

    if not imported:
        return False

    # Build: name -> set of usage lines (excluding the import line itself)
    usage_lines: dict[str, set[int]] = {name: set() for name in imported}

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in imported:
            if node.lineno != imported.get(node.id):
                usage_lines[node.id].add(node.lineno)
        elif isinstance(node, ast.Attribute):
            root_node = node
            while isinstance(root_node, ast.Attribute):
                root_node = root_node.value  # type: ignore[assignment]
            if isinstance(root_node, ast.Name) and root_node.id in imported:
                if root_node.lineno != imported.get(root_node.id):
                    usage_lines[root_node.id].add(root_node.lineno)

    # Build line -> replacement text map for modified lines
    replacement_text: dict[int, str] = {}
    if applied_fixes:
        for fix in applied_fixes:
            if fix.status != FixStatus.APPLIED:
                continue
            start = fix.line
            end = fix.end_line or fix.line
            for ln in range(start, end + 1):
                if ln in modified_lines:
                    replacement_text[ln] = fix.fixed_code or ""

    all_affected = deleted_lines | modified_lines
    for name, lines in usage_lines.items():
        if not lines or not lines.issubset(all_affected):
            continue
        # All usages are on affected lines. Check if any modified line
        # still references this import in its replacement text.
        still_used = False
        for ln in lines:
            if ln in modified_lines:
                repl = replacement_text.get(ln, "")
                if name in repl:
                    still_used = True
                    break
        if not still_used:
            return True

    return False


def _build_descendant_map(scopes) -> dict[int, set[int]]:
    """Build scope_id -> all descendant scope_ids in O(s) time.

    Bottom-up propagation: process leaves first (no children), then propagate
    each node's descendants to its parent. Each scope is visited exactly once.
    """
    # Build adjacency: parent_id -> direct children
    children_of: dict[int, list[int]] = {}
    parent_of: dict[int, int | None] = {}
    all_ids: set[int] = set()
    for s in scopes:
        all_ids.add(s.scope_id)
        parent_of[s.scope_id] = s.parent_id
        if s.parent_id is not None:
            children_of.setdefault(s.parent_id, []).append(s.scope_id)

    # Topological order (leaves first): BFS by in-degree of children
    child_count: dict[int, int] = {sid: len(children_of.get(sid, [])) for sid in all_ids}
    queue = [sid for sid, count in child_count.items() if count == 0]
    result: dict[int, set[int]] = {sid: set() for sid in all_ids}

    while queue:
        next_queue = []
        for sid in queue:
            # Propagate this node's descendants to parent
            pid = parent_of.get(sid)
            if pid is not None and pid in result:
                result[pid].add(sid)
                result[pid] |= result[sid]
                child_count[pid] -= 1
                if child_count[pid] == 0:
                    next_queue.append(pid)
        queue = next_queue

    return result


def _derive_unused_variables(semantics, deleted_lines: set[int]) -> bool:
    """Check if any variable's only read-references all fall on deleted lines.

    Uses the same scope visibility model as check_unused_variables in scope.py:
    for each assignment, collects references from the assignment's scope AND
    all child scopes (since inner scopes can read outer variables). Returns
    True if at least one variable will become unused due to fixes deleting
    all its readers.

    Only considers deleted lines (not modified) -- a modified line might still
    reference the variable in its replacement text.
    """
    if semantics is None:
        return False

    # Build descendant map once, reuse for all assignments
    desc_map = _build_descendant_map(semantics.scopes)

    # Build inverted indexes: name -> list[ref], name -> list[call]
    refs_by_name: dict[str, list] = {}
    for ref in semantics.references:
        if ref.context in ("read", "call"):
            refs_by_name.setdefault(ref.name, []).append(ref)
    calls_by_name: dict[str, list] = {}
    for call in semantics.function_calls:
        calls_by_name.setdefault(call.name, []).append(call)

    for asgn in semantics.assignments:
        if asgn.is_parameter or asgn.is_augmented:
            continue
        if asgn.name.startswith("_"):
            continue
        if asgn.value_node_type == "self_attr":
            continue

        # Visible scopes: the assignment's scope + all descendants
        visible = {asgn.scope_id} | desc_map.get(asgn.scope_id, set())

        # Collect all read-reference lines for this variable in visible scopes
        ref_lines: set[int] = set()
        for ref in refs_by_name.get(asgn.name, ()):
            if ref.scope_id in visible:
                ref_lines.add(ref.line)
        for call in calls_by_name.get(asgn.name, ()):
            if call.scope_id in visible:
                ref_lines.add(call.line)

        # If this variable has readers and ALL are on deleted lines -> cascade
        if ref_lines and ref_lines.issubset(deleted_lines):
            return True

    return False


def derive_expected_cascades(
    content: str,
    language: str,
    applied_fixes: list[Fix],
    semantics=None,
) -> set[str]:
    """Derive rule names expected to appear as side-effects of applied fixes.

    Analyzes which imports/variables lose all usages due to fix-modified lines.
    Returns set of rule names (e.g. 'unused-import') to exclude from rollback.

    This replaces a static rule->rule whitelist with structural analysis:
    any fix that removes the only usage of an import or variable automatically
    predicts the cascade, regardless of which rule triggered the fix.

    Args:
        semantics: Optional FileSemantics for scope-aware variable analysis.
            When provided, unused-variable detection is precise (scope-aware).
            When None, unused-variable cascade is not predicted.
    """
    if not applied_fixes:
        return set()

    deleted_lines, modified_lines = _get_fix_affected_lines(applied_fixes)
    if not deleted_lines and not modified_lines:
        return set()

    expected: set[str] = set()

    # AST-derived: check if any import loses all usages
    if language == "python":
        if _derive_unused_imports_python(content, deleted_lines, modified_lines, applied_fixes):
            expected.add("unused-import")

    # Scope-aware: check if any variable loses all read-references
    # Only uses deleted lines -- modified lines might still reference the variable
    if _derive_unused_variables(semantics, deleted_lines):
        expected.add("unused-variable")

    return expected
