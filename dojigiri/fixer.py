"""Fix engine — deterministic fixers, LLM fix orchestration, fix application."""

import ast
import logging
import os
import re
import shutil
import sys
import tempfile
from typing import Optional, Protocol, Union

logger = logging.getLogger(__name__)

from .config import (
    Finding, Fix, FixContext, FixReport, FixSource, FixStatus, Severity,
)


# ─── Cascading effect derivation ──────────────────────────────────────
# Instead of a static rule→rule whitelist, we analyze the AST to derive
# which imports/variables will become unused after fixes modify their
# only usage sites. This handles ALL rules automatically.


def _get_fix_affected_lines(applied_fixes: list[Fix]) -> set[int]:
    """Collect all line numbers modified or removed by applied fixes."""
    affected = set()
    for fix in applied_fixes:
        if fix.status != FixStatus.APPLIED:
            continue
        start = fix.line
        end = fix.end_line or fix.line
        for ln in range(start, end + 1):
            affected.add(ln)
    return affected


def _derive_unused_imports_python(content: str, affected_lines: set[int]) -> bool:
    """Check if any Python import's only usages all fall on affected lines.

    Returns True if at least one import will become unused due to fixes.
    Uses Python's ast for accurate import→usage tracking.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False

    # Build: name → import_line
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

    # Build: name → set of usage lines (excluding the import line itself)
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

    # If any import's usages are ALL on affected lines, it will become unused
    for name, lines in usage_lines.items():
        if lines and lines.issubset(affected_lines):
            return True

    return False


def _build_descendant_map(scopes) -> dict[int, set[int]]:
    """Build scope_id → all descendant scope_ids in O(s) time.

    Single pass: builds parent→direct_children adjacency list, then one
    DFS per root to propagate descendants. Cached result is reused for
    every assignment lookup.
    """
    # parent_id → list of child scope_ids
    children_of: dict[int, list[int]] = {}
    all_ids: set[int] = set()
    for s in scopes:
        all_ids.add(s.scope_id)
        if s.parent_id is not None:
            children_of.setdefault(s.parent_id, []).append(s.scope_id)

    # For each scope, compute all descendants via iterative DFS
    result: dict[int, set[int]] = {}
    for sid in all_ids:
        if sid in result:
            continue
        # Iterative DFS from sid
        descendants: set[int] = set()
        stack = list(children_of.get(sid, []))
        while stack:
            child = stack.pop()
            if child not in descendants:
                descendants.add(child)
                stack.extend(children_of.get(child, []))
        result[sid] = descendants

    return result


def _derive_unused_variables(semantics, affected_lines: set[int]) -> bool:
    """Check if any variable's only read-references all fall on affected lines.

    Uses the same scope visibility model as check_unused_variables in scope.py:
    for each assignment, collects references from the assignment's scope AND
    all child scopes (since inner scopes can read outer variables). Returns
    True if at least one variable will become unused due to fixes removing
    all its readers.
    """
    if semantics is None:
        return False

    # Build descendant map once, reuse for all assignments
    desc_map = _build_descendant_map(semantics.scopes)

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
        for ref in semantics.references:
            if ref.name == asgn.name and ref.scope_id in visible:
                if ref.context in ("read", "call"):
                    ref_lines.add(ref.line)

        # Also check function calls (e.g. `my_var()`)
        for call in semantics.function_calls:
            if call.name == asgn.name and call.scope_id in visible:
                ref_lines.add(call.line)

        # If this variable has readers and ALL are on affected lines → cascade
        if ref_lines and ref_lines.issubset(affected_lines):
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

    This replaces a static rule→rule whitelist with structural analysis:
    any fix that removes the only usage of an import or variable automatically
    predicts the cascade, regardless of which rule triggered the fix.

    Args:
        semantics: Optional FileSemantics for scope-aware variable analysis.
            When provided, unused-variable detection is precise (scope-aware).
            When None, unused-variable cascade is not predicted.
    """
    if not applied_fixes:
        return set()

    affected_lines = _get_fix_affected_lines(applied_fixes)
    if not affected_lines:
        return set()

    expected: set[str] = set()

    # AST-derived: check if any import loses all usages
    if language == "python":
        if _derive_unused_imports_python(content, affected_lines):
            expected.add("unused-import")

    # Scope-aware: check if any variable loses all read-references
    if _derive_unused_variables(semantics, affected_lines):
        expected.add("unused-variable")

    return expected


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
                if hasattr(node, 'end_lineno') and node.end_lineno is not None:
                    if node.lineno < line_num < node.end_lineno:
                        return True
                    # Same start and end line is a single-line string, skip
        return False
    except SyntaxError:
        pass

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
        code_seg = line[last_end:m.start()]
        parts.append(re.sub(pattern, replacement, code_seg))
        parts.append(m.group())  # preserve string literal unchanged
        last_end = m.end()
    # Handle trailing code segment after last string literal
    parts.append(re.sub(pattern, replacement, line[last_end:]))
    return "".join(parts)


def _pattern_outside_strings(line: str, pattern: re.Pattern) -> bool:
    """Check if pattern matches in code portions of a line (outside string literals)."""
    code_only = _STRING_LITERAL_RE.sub(lambda m: ' ' * len(m.group()), line)
    return bool(pattern.search(code_only))


class FixerFn(Protocol):
    """Deterministic fix generator — unified protocol.

    All fixers receive FixContext which always carries the full file content,
    finding, and optionally semantic/type data. The `line` param is the raw
    line text for convenience (avoiding repeated splitlines).
    """

    def __call__(self, line: str, finding: Finding, content: str,
                 ctx: Optional[FixContext] = None) -> Optional[Union[Fix, list[Fix]]]: ...


# ─── AST helpers ─────────────────────────────────────────────────────


def _find_ast_node(content: str, line: int, node_type, predicate=None):
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
        if not hasattr(node, 'lineno') or node.lineno != line:
            continue
        if predicate is None or predicate(node):
            return node
    return None


def _replace_node_source(content: str, node, replacement_text: str) -> str:
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
    suffix = lines[end_line][end_col:] + "".join(lines[end_line + 1:])

    return prefix + replacement_text + suffix


# ─── Deterministic fixers ────────────────────────────────────────────
# Each takes (line, finding, full_content) and returns Fix | None.


def _fix_unused_import(line: str, finding: Finding, content: str,
                       ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Remove an unused import. AST-first: handles multiline from...import correctly.

    When semantic data is available via ctx, double-checks that the import name
    is truly unreferenced across all scopes (catches re-exports, attribute access).
    """
    # Extract the unused name from the finding message
    unused_name = _extract_name_from_message(finding.message)
    if not unused_name:
        # Fallback: extract from the line text
        m = re.match(r'^\s*import\s+(\w+)', line)
        if m:
            unused_name = m.group(1)

    # Semantic guard: if we have full semantic data, verify the import is truly unused
    if unused_name and ctx and ctx.semantics:
        if _semantic_import_is_referenced(unused_name, ctx.semantics):
            return None  # Detector was wrong — name IS used somewhere

    # AST approach for Python
    if finding.file.endswith('.py') and unused_name:
        node = _find_ast_node(content, finding.line, (ast.Import, ast.ImportFrom))
        if node:
            # Skip if inside a try block (optional import pattern)
            try:
                tree = ast.parse(content)
                for parent in ast.walk(tree):
                    for child in ast.iter_child_nodes(parent):
                        if child is node and isinstance(parent, ast.Try):
                            return None
            except SyntaxError:
                pass

            if isinstance(node, ast.ImportFrom) and len(node.names) > 1:
                # Multi-name import: remove only the unused name, keep the rest
                remaining = [a for a in node.names if a.name != unused_name]
                if remaining and len(remaining) < len(node.names):
                    remaining_strs = [
                        f"{a.name} as {a.asname}" if a.asname else a.name
                        for a in remaining
                    ]
                    lines_list = content.splitlines(keepends=True)
                    start = node.lineno - 1
                    end = node.end_lineno if node.end_lineno else node.lineno
                    original_text = "".join(lines_list[start:end])
                    indent = re.match(r'^(\s*)', lines_list[start]).group(1)
                    module = node.module or ''
                    new_text = f"{indent}from {module} import {', '.join(remaining_strs)}\n"
                    return Fix(
                        file=finding.file, line=finding.line, rule=finding.rule,
                        original_code=original_text,
                        fixed_code=new_text,
                        explanation=f"Removed unused '{unused_name}' from import",
                        source=FixSource.DETERMINISTIC,
                        end_line=end,
                    )

            # Single import or all names unused: delete the whole statement
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
                if unused_name in names and len(names) == 1:
                    return Fix(
                        file=finding.file, line=finding.line, rule=finding.rule,
                        original_code=line, fixed_code="",
                        explanation=f"Removed unused import: {unused_name}",
                        source=FixSource.DETERMINISTIC,
                    )
            elif isinstance(node, ast.ImportFrom) and len(node.names) == 1:
                return Fix(
                    file=finding.file, line=finding.line, rule=finding.rule,
                    original_code=line, fixed_code="",
                    explanation=f"Removed unused import: {line.strip()}",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback for non-Python or parse failure
    stripped = line.strip()
    if stripped.startswith("import ") or stripped.startswith("from "):
        if '(' in stripped and ')' not in stripped:
            return None
        lines = content.splitlines()
        line_idx = finding.line - 1
        for i in range(line_idx - 1, -1, -1):
            prev = lines[i].strip()
            if prev:
                if prev == "try:":
                    return None
                break
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code="",
            explanation=f"Removed unused import: {stripped}",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _extract_name_from_message(message: str) -> Optional[str]:
    """Extract a quoted identifier from a finding message."""
    for pattern in [r"'(\w+)'", r"\"(\w+)\""]:
        m = re.search(pattern, message)
        if m:
            return m.group(1)
    return None


def _fix_bare_except(line: str, finding: Finding, content: str,
                     ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace bare `except:` with `except Exception:`. AST-first with regex fallback."""
    # AST: confirm this is actually a bare except handler
    if finding.file.endswith('.py'):
        node = _find_ast_node(
            content, finding.line, ast.ExceptHandler,
            predicate=lambda n: n.type is None,
        )
        if node:
            # Use node position for precise replacement
            lines = content.splitlines(keepends=True)
            original_line = lines[node.lineno - 1]
            indent = re.match(r'^(\s*)', original_line).group(1)
            return Fix(
                file=finding.file, line=finding.line, rule=finding.rule,
                original_code=original_line,
                fixed_code=f"{indent}except Exception:\n",
                explanation="Replaced bare except with 'except Exception:' to avoid catching SystemExit/KeyboardInterrupt",
                source=FixSource.DETERMINISTIC,
            )

    # Regex fallback (non-Python)
    m = re.match(r'^(\s*)except\s*:', line)
    if m:
        indent = m.group(1)
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=f"{indent}except Exception:\n",
            explanation="Replaced bare except with 'except Exception:' to avoid catching SystemExit/KeyboardInterrupt",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_loose_equality(line: str, finding: Finding, content: str,
                        ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace == with === and != with !== in JS/TS."""
    # Preserve == null idiom (checks both null and undefined intentionally)
    code_only = _STRING_LITERAL_RE.sub(lambda m: ' ' * len(m.group()), line)
    if re.search(r'(?<!=)==(?!=)\s*null\b', code_only) or re.search(r'(?<!=)!=(?!=)\s*null\b', code_only):
        return None
    new_line = line
    # Replace != before == to avoid double-replacing !== back
    new_line = _sub_outside_strings(new_line, r'(?<!=)!=(?!=)', '!==')
    new_line = _sub_outside_strings(new_line, r'(?<!=)==(?!=)', '===')
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced loose equality with strict equality",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_none_comparison(line: str, finding: Finding, content: str,
                         ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace `== None` with `is None`, `!= None` with `is not None`. AST-first."""
    # AST approach: structurally rebuild the comparison
    if finding.file.endswith('.py'):
        def _is_none_eq(node):
            return (isinstance(node, ast.Compare)
                    and any(isinstance(comp, ast.Constant) and comp.value is None
                            and isinstance(op, (ast.Eq, ast.NotEq))
                            for op, comp in zip(node.ops, node.comparators)))

        node = _find_ast_node(content, finding.line, ast.Compare, _is_none_eq)
        if node and node.end_lineno and node.end_col_offset is not None:
            # Rebuild the comparison expression with `is`/`is not`
            # Use ast.unparse for the non-None parts, manually construct the ops
            parts = [ast.get_source_segment(content, node.left) or ast.unparse(node.left)]
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(comp, ast.Constant) and comp.value is None:
                    if isinstance(op, ast.Eq):
                        parts.append("is None")
                    elif isinstance(op, ast.NotEq):
                        parts.append("is not None")
                    else:
                        parts.append(f"{_op_str(op)} {ast.get_source_segment(content, comp) or ast.unparse(comp)}")
                else:
                    parts.append(f"{_op_str(op)} {ast.get_source_segment(content, comp) or ast.unparse(comp)}")

            new_expr = " ".join(parts)
            new_content = _replace_node_source(content, node, new_expr)
            new_lines = new_content.splitlines(keepends=True)
            lines = content.splitlines(keepends=True)
            li = finding.line - 1
            if li < len(lines) and li < len(new_lines) and new_lines[li] != lines[li]:
                return Fix(
                    file=finding.file, line=finding.line, rule=finding.rule,
                    original_code=lines[li], fixed_code=new_lines[li],
                    explanation="Use identity comparison for None (PEP 8)",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback (non-Python or parse failure)
    if not _pattern_outside_strings(line, re.compile(r'(?:==|!=)\s*None\b')):
        return None
    if _in_multiline_string(content, finding.line):
        return None
    new_line = line
    new_line = _sub_outside_strings(new_line, r'!=\s*None\b', 'is not None')
    new_line = _sub_outside_strings(new_line, r'==\s*None\b', 'is None')
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Use identity comparison for None (PEP 8)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _op_str(op) -> str:
    """Convert an ast comparison operator to its source string."""
    _OP_MAP = {
        ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
        ast.Gt: ">", ast.GtE: ">=", ast.Is: "is", ast.IsNot: "is not",
        ast.In: "in", ast.NotIn: "not in",
    }
    return _OP_MAP.get(type(op), "==")


def _fix_type_comparison(line: str, finding: Finding, content: str,
                         ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace `type(x) == Y` with `isinstance(x, Y)`. AST-first: handles nested parens."""
    # AST approach
    if finding.file.endswith('.py'):
        def _is_type_compare(node):
            return (isinstance(node, ast.Compare)
                    and len(node.ops) == 1
                    and isinstance(node.ops[0], (ast.Eq, ast.Is))
                    and isinstance(node.left, ast.Call)
                    and isinstance(node.left.func, ast.Name)
                    and node.left.func.id == 'type'
                    and len(node.left.args) == 1)

        node = _find_ast_node(content, finding.line, ast.Compare, _is_type_compare)
        if node and node.end_lineno and node.end_col_offset is not None:
            # Extract the argument to type() and the comparator using ast.unparse
            # This handles arbitrary nesting: type((x)) == dict → isinstance(x, dict)
            arg_src = ast.get_source_segment(content, node.left.args[0]) or ast.unparse(node.left.args[0])
            type_src = ast.get_source_segment(content, node.comparators[0]) or ast.unparse(node.comparators[0])
            replacement = f"isinstance({arg_src}, {type_src})"
            new_content = _replace_node_source(content, node, replacement)
            new_lines = new_content.splitlines(keepends=True)
            lines = content.splitlines(keepends=True)
            li = finding.line - 1
            if li < len(lines) and li < len(new_lines) and new_lines[li] != lines[li]:
                return Fix(
                    file=finding.file, line=finding.line, rule=finding.rule,
                    original_code=lines[li], fixed_code=new_lines[li],
                    explanation="Use isinstance() instead of type() comparison for proper subclass support",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback
    m = re.search(r'type\((.+?)\)\s*==\s*(\w+)', line)
    if m:
        var = m.group(1).strip()
        if var.startswith('(') and var.endswith(')'):
            var = var[1:-1].strip()
        typ = m.group(2).strip()
        new_line = line[:m.start()] + f"isinstance({var}, {typ})" + line[m.end():]
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Use isinstance() instead of type() comparison for proper subclass support",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_console_log(line: str, finding: Finding, content: str,
                     ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Remove console.log() line — only if it's the sole statement."""
    if "console.log" not in line:
        return None
    stripped = line.strip().rstrip(';').strip()
    # If the line has other statements (semicolons outside the console.log call),
    # or is chained, skip instead of deleting the whole line.
    # Match a standalone console.log(...) call
    if not re.match(r'^console\.log\s*\(.*\)\s*;?\s*$', stripped):
        return None
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation="Removed console.log() debug statement",
        source=FixSource.DETERMINISTIC,
    )


def _fix_insecure_http(line: str, finding: Finding, content: str,
                       ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace http:// with https:// in URLs."""
    # Skip if line is inside a multiline string (docstring)
    if _in_multiline_string(content, finding.line):
        return None
    # Skip single-line docstrings
    stripped = line.strip()
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return None
    # Skip localhost and internal URLs — these legitimately use HTTP
    new_line = re.sub(
        r'http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])',
        'https://', line,
    )
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Upgraded insecure HTTP URL to HTTPS",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_fstring_no_expr(line: str, finding: Finding, content: str,
                         ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Remove f-prefix from f-strings with no expressions."""
    # Match f"..." or f'...' where content has no { }
    new_line = re.sub(r"""\bf(["'])((?:[^{}\\]|\\.)*?)\1""", r'\1\2\1', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Removed unnecessary f-string prefix (no expressions)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_hardcoded_secret(line: str, finding: Finding, content: str,
                          ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace hardcoded secret with os.environ lookup."""
    # Skip test files — secrets there are usually fixtures, not real
    basename = os.path.basename(finding.file)
    dirparts = finding.file.replace('\\', '/').split('/')
    if (basename.startswith('test_') or basename.endswith(('_test.py', '.test.js', '.test.ts',
            '.spec.js', '.spec.ts')) or '__tests__' in dirparts):
        return None
    # Match: VAR_NAME = "secret_value" or VAR_NAME = 'secret_value'
    m = re.match(r'^(\s*)(\w+)\s*=\s*["\'].*?["\']', line)
    if not m:
        return None
    indent = m.group(1)
    var_name = m.group(2)
    is_js = finding.file.endswith(('.js', '.ts', '.jsx', '.tsx'))
    if is_js:
        new_line = f'{indent}{var_name} = process.env.{var_name}\n'
        explanation = f"Replaced hardcoded secret with process.env.{var_name}"
    else:
        new_line = f'{indent}{var_name} = os.environ["{var_name}"]\n'
        explanation = f'Replaced hardcoded secret with os.environ["{var_name}"]'
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_line,
        explanation=explanation,
        source=FixSource.DETERMINISTIC,
    )


def _fix_open_without_with(line: str, finding: Finding, content: str,
                           ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Wrap `x = open(...)` in a `with` statement."""
    m = re.match(r'^(\s*)(\w+)\s*=\s*open\((.+)\)\s*$', line.rstrip("\n"))
    if not m:
        return None
    indent = m.group(1)
    var_name = m.group(2)
    open_args = m.group(3)

    # Find subsequent lines that belong to the body of this open() usage.
    # Collect all lines at same-or-deeper indent until we hit a scope boundary.
    # Then trim from the end: drop lines after the last use of the variable.
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    candidate_lines = []
    # Match variable name as a word, but exclude f-string prefixes (f"...", f'...')
    var_pat = re.compile(r'\b' + re.escape(var_name) + r'\b(?!["\'])')
    indent_len = len(indent)
    for i in range(line_idx + 1, len(lines)):
        subsequent = lines[i]
        stripped = subsequent.strip()
        # Stop on def/class boundaries
        if stripped.startswith("def ") or stripped.startswith("class "):
            break
        # Blank lines are collected
        if not stripped:
            candidate_lines.append(subsequent)
            continue
        # Check indentation
        cur_indent = len(subsequent) - len(subsequent.lstrip())
        if cur_indent < indent_len:
            break  # shallower indent — left the scope
        candidate_lines.append(subsequent)

    # Trim from the end: find the last line that uses the variable
    last_var_use = -1
    for j, cl in enumerate(candidate_lines):
        if var_pat.search(cl):
            last_var_use = j
    body_lines = candidate_lines[:last_var_use + 1] if last_var_use >= 0 else []

    # If the last var-use line is a block header (for/if/while/with ending with ':'),
    # extend to include its indented body — otherwise we'd leave a headless block.
    if body_lines and body_lines[-1].rstrip().endswith(":"):
        header_indent = len(body_lines[-1]) - len(body_lines[-1].lstrip())
        extend_from = last_var_use + 1
        while extend_from < len(candidate_lines):
            ext_line = candidate_lines[extend_from]
            ext_stripped = ext_line.strip()
            if not ext_stripped:
                body_lines.append(ext_line)
                extend_from += 1
                continue
            ext_indent = len(ext_line) - len(ext_line.lstrip())
            if ext_indent <= header_indent:
                break
            body_lines.append(ext_line)
            extend_from += 1

    # Strip leading and trailing blank lines from collected body
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()

    # Remove explicit .close() calls on the variable — the with block handles it
    close_pat = re.compile(r'^\s*' + re.escape(var_name) + r'\.close\(\)\s*$')
    body_lines = [bl for bl in body_lines if not close_pat.match(bl)]

    if not body_lines:
        # No body found — emit with ... as f:\n    pass
        new_code = f"{indent}with open({open_args}) as {var_name}:\n{indent}    pass\n"
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_code,
            explanation="Wrapped open() in 'with' statement for automatic cleanup",
            source=FixSource.DETERMINISTIC,
        )

    # Build the with block with re-indented body (preserve relative indentation)
    new_code = f"{indent}with open({open_args}) as {var_name}:\n"
    for bl in body_lines:
        if bl.strip():
            # Preserve indentation relative to the original indent level
            if bl.startswith(indent):
                relative = bl[len(indent):]
            else:
                relative = bl.lstrip()
            new_code += indent + "    " + relative
        else:
            new_code += bl

    # Set end_line so apply_fixes blanks out the original body lines
    last_body_line = finding.line + len(body_lines)
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_code,
        explanation="Wrapped open() in 'with' statement for automatic cleanup",
        source=FixSource.DETERMINISTIC,
        end_line=last_body_line,
    )


def _fix_yaml_unsafe(line: str, finding: Finding, content: str,
                     ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace yaml.load() with yaml.safe_load()."""
    # Skip if SafeLoader or Loader= already present on this line
    if "SafeLoader" in line or "Loader=" in line:
        return None
    new_line = re.sub(r'\byaml\.load\s*\(', 'yaml.safe_load(', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced yaml.load() with yaml.safe_load() to prevent arbitrary code execution",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_weak_hash(line: str, finding: Finding, content: str,
                   ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace hashlib.md5/sha1 with hashlib.sha256."""
    # Skip if usedforsecurity=False is present (legitimate non-crypto use)
    if "usedforsecurity=False" in line or "usedforsecurity = False" in line:
        return None
    new_line = re.sub(r'\bhashlib\.(?:md5|sha1)\s*\(', 'hashlib.sha256(', line)
    if new_line != line:
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced weak hash (MD5/SHA1) with SHA-256",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_unreachable_code(line: str, finding: Finding, content: str,
                          ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Delete a single unreachable line after return/raise/break/continue."""
    stripped = line.strip()
    # Only fix simple single-line statements, not block starters
    if stripped.endswith(":") or not stripped:
        return None
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation=f"Removed unreachable code: {stripped}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_mutable_default(line: str, finding: Finding, content: str,
                         ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace mutable default argument with None + body guard.

    AST-first: uses ast.FunctionDef to identify mutable defaults precisely,
    then uses node positions for text replacement — handles multiline signatures.
    """
    if finding.file.endswith('.py'):
        node = _find_ast_node(
            content, finding.line,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
        if node:
            return _mutable_default_ast(node, finding, content)

    # Regex fallback for non-Python (shouldn't normally trigger for this rule)
    return _mutable_default_regex(line, finding, content)


def _mutable_default_ast(node, finding: Finding, content: str) -> Optional[Fix]:
    """AST-based mutable default fix: uses node structure for correct parameter identification."""
    lines = content.splitlines(keepends=True)
    indent = re.match(r'^(\s*)', lines[node.lineno - 1]).group(1)

    # Collect all (param_name, default_node, mutable_literal) triples
    mutable_params = []

    # Positional args: defaults are right-aligned
    n_args = len(node.args.args)
    n_defaults = len(node.args.defaults)
    for i, default in enumerate(node.args.defaults):
        arg = node.args.args[n_args - n_defaults + i]
        mutable_expr = _is_empty_mutable(default)
        if mutable_expr:
            mutable_params.append((arg.arg, default, mutable_expr))

    # Keyword-only args
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        if default is not None:
            mutable_expr = _is_empty_mutable(default)
            if mutable_expr:
                mutable_params.append((arg.arg, default, mutable_expr))

    if not mutable_params:
        return None

    # Replace each mutable default with None — work backwards through source
    # to preserve earlier positions
    modified = content
    for param_name, default_node, mutable_expr in reversed(mutable_params):
        if default_node.end_lineno and default_node.end_col_offset is not None:
            modified = _replace_node_source(modified, default_node, "None")

    # Now find the function body insertion point (after signature + docstring)
    body_start_line = node.body[0].lineno if node.body else node.end_lineno or node.lineno
    # If first body statement is a docstring, insert after it
    if (node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)):
        docstring_node = node.body[0]
        body_start_line = (docstring_node.end_lineno or docstring_node.lineno) + 1

    # Build guard lines
    body_indent = indent + "    "
    guard_text = ""
    for param_name, _, mutable_expr in mutable_params:
        guard_text += f"{body_indent}if {param_name} is None:\n"
        guard_text += f"{body_indent}    {param_name} = {mutable_expr}\n"

    # Insert guards at body_start_line
    mod_lines = modified.splitlines(keepends=True)
    insert_idx = body_start_line - 1
    if insert_idx <= len(mod_lines):
        mod_lines.insert(insert_idx, guard_text)
    modified = "".join(mod_lines)

    # Build the Fix spanning from def line to the last modified line
    orig_lines = content.splitlines(keepends=True)
    mod_lines_final = modified.splitlines(keepends=True)

    sig_end = node.end_lineno or node.lineno
    # The fixed code spans from the def line through the inserted guards
    start = node.lineno - 1
    # Calculate how many lines the fix covers in the original
    orig_end = max(sig_end, body_start_line)
    orig_text = "".join(orig_lines[start:orig_end])
    # In the modified version, we have extra guard lines
    new_end = orig_end + guard_text.count('\n')
    new_text = "".join(mod_lines_final[start:new_end])

    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=orig_lines[start],
        fixed_code=new_text,
        explanation="Replaced mutable default argument with None + guard clause",
        source=FixSource.DETERMINISTIC,
        end_line=orig_end,
    )


def _is_empty_mutable(node) -> Optional[str]:
    """If node is an empty mutable literal ([], {}, set()), return its string repr."""
    if isinstance(node, ast.List) and not node.elts:
        return "[]"
    if isinstance(node, ast.Dict) and not node.keys:
        return "{}"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'set' and not node.args and not node.keywords):
        return "set()"
    return None


def _mutable_default_regex(line: str, finding: Finding, content: str) -> Optional[Fix]:
    """Regex fallback for mutable default fix."""
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    def_line = lines[line_idx]
    m = re.match(r'^(\s*)(async\s+)?def\s+\w+\s*\(', def_line)
    if not m:
        return None
    indent = m.group(1)

    sig_end = line_idx
    sig_text = def_line
    if ')' not in def_line or ':' not in def_line.split(')')[-1]:
        for i in range(line_idx + 1, min(line_idx + 20, len(lines))):
            sig_text += lines[i]
            sig_end = i
            if ')' in lines[i]:
                break

    new_sig = sig_text
    guards = []
    matches = list(re.finditer(r'(\w+)\s*=\s*(\[\]|\{\}|set\(\))', sig_text))
    for match in reversed(matches):
        param = match.group(1)
        mutable = match.group(2)
        new_sig = new_sig[:match.start()] + f"{param}=None" + new_sig[match.end():]
        guards.insert(0, (param, mutable))

    if not guards:
        return None

    body_indent = indent + "    "
    guard_lines = ""
    for param, mutable in guards:
        guard_lines += f"{body_indent}if {param} is None:\n"
        guard_lines += f"{body_indent}    {param} = {mutable}\n"

    # Handle docstrings after signature
    next_idx = sig_end + 1
    if next_idx < len(lines):
        next_stripped = lines[next_idx].strip()
        ds_match = re.match(r'^[brufBRUF]{0,2}("""|\'\'\')', next_stripped)
        if ds_match:
            quote = ds_match.group(1)
            rest = next_stripped[ds_match.end():]
            if quote in rest:
                new_sig += lines[next_idx]
                sig_end = next_idx
            else:
                new_sig += lines[next_idx]
                for di in range(next_idx + 1, len(lines)):
                    new_sig += lines[di]
                    sig_end = di
                    if quote in lines[di]:
                        break

    fixed_code = new_sig + guard_lines
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=def_line, fixed_code=fixed_code,
        explanation="Replaced mutable default argument with None + guard clause",
        source=FixSource.DETERMINISTIC,
        end_line=sig_end + 1 if sig_end > line_idx else None,
    )


def _fix_unused_variable(line: str, finding: Finding, content: str,
                         ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Remove an unused variable assignment.

    When semantic data is available, checks for closure references, child-scope
    usage, and __all__ re-exports before removing.
    """
    stripped = line.strip()

    # Semantic guards: check if variable is actually used in ways the detector missed
    if ctx and ctx.semantics:
        var_name = _extract_name_from_message(finding.message)
        if var_name:
            # Find the assignment's scope_id
            assign_scope = None
            for assign in ctx.semantics.assignments:
                if assign.name == var_name and assign.line == finding.line:
                    assign_scope = assign.scope_id
                    break
            if assign_scope is not None:
                # Check child-scope references (closures, nested functions)
                if _semantic_var_is_used_in_child_scope(var_name, assign_scope, ctx.semantics):
                    return None
            # Check __all__ re-export
            if _semantic_var_in_all_export(var_name, ctx.semantics):
                return None

    # Don't remove if it's the only statement in a block (would create empty-exception-handler etc.)
    lines = content.splitlines()
    line_idx = finding.line - 1
    if 0 <= line_idx < len(lines):
        # Look backward for block opener, forward for block closer
        prev_code = ""
        for i in range(line_idx - 1, -1, -1):
            s = lines[i].strip()
            if s:
                prev_code = s
                break
        next_code = ""
        for i in range(line_idx + 1, len(lines)):
            s = lines[i].strip()
            if s:
                next_code = s
                break
        if prev_code.endswith('{') and next_code == '}':
            return None  # sole statement in block — removal would leave empty block

    # JS/TS: const x = ...; / let x = ...; / var x = ...;
    js_m = re.match(r'^(const|let|var)\s+(\w+)\s*=\s*(.+?);?\s*$', stripped)
    if js_m:
        var_name = js_m.group(2)
        rhs = js_m.group(3).strip()
        # Skip if RHS has side effects (function calls other than safe constructors)
        if re.search(r'\w+\s*\(', rhs) and not re.match(r'^["\'\d\[\{(]', rhs):
            if 'require(' not in rhs:  # require() is an import, safe to remove
                return None
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code="",
            explanation=f"Removed unused variable: {var_name}",
            source=FixSource.DETERMINISTIC,
        )

    # Python: x = <value>
    if not re.match(r'^\w+\s*=\s*', stripped):
        return None
    # Don't remove if it's a type annotation (x: int = 5)
    if re.match(r'^\w+\s*:', stripped):
        return None
    # Don't remove if it looks like a destructuring or multi-assignment
    if ',' in stripped.split('=')[0]:
        return None
    # Don't remove if the RHS has side effects (function calls, method calls, chained calls)
    rhs = stripped.split('=', 1)[1].strip()
    if re.search(r'\w+\s*\(', rhs) or re.search(r'\.\w+\s*\(', rhs):
        safe_calls = ('True', 'False', 'None', '[]', '{}', '""', "''", '0', 'set()', 'dict()', 'list()', 'tuple()')
        if rhs not in safe_calls and not re.match(r'^["\'\d\[\{(]', rhs):
            return None

    # Handle multi-line assignments (triple-quoted strings, multiline containers)
    # Use AST to find the full span if the assignment continues past this line
    if finding.file.endswith('.py'):
        node = _find_ast_node(content, finding.line, ast.Assign)
        if node and node.end_lineno and node.end_lineno > node.lineno:
            # Multi-line assignment — need to blank all lines
            all_lines = content.splitlines(keepends=True)
            orig_text = "".join(all_lines[node.lineno - 1:node.end_lineno])
            return Fix(
                file=finding.file, line=finding.line, rule=finding.rule,
                original_code=orig_text, fixed_code="",
                explanation=f"Removed unused variable: {stripped.split('=')[0].strip()}",
                source=FixSource.DETERMINISTIC,
                end_line=node.end_lineno,
            )

    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code="",
        explanation=f"Removed unused variable: {stripped.split('=')[0].strip()}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_os_system(line: str, finding: Finding, content: str,
                   ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace os.system() with subprocess.run()."""
    m = re.search(r'os\.system\((.+)\)', line)
    if not m:
        return None
    cmd_arg = m.group(1).strip()
    indent = re.match(r'^(\s*)', line).group(1)
    new_line = f"{indent}subprocess.run(shlex.split({cmd_arg}))\n"
    return Fix(
        file=finding.file, line=finding.line, rule=finding.rule,
        original_code=line, fixed_code=new_line,
        explanation="Replaced os.system() with subprocess.run() (safer, returns exit info)",
        source=FixSource.DETERMINISTIC,
    )


def _fix_eval_usage(line: str, finding: Finding, content: str,
                    ctx: Optional[FixContext] = None) -> Optional[Union[Fix, list[Fix]]]:
    """Replace eval() with safe alternative: ast.literal_eval (Python), JSON.parse (JS/TS). AST-validated."""
    # AST pre-validation: confirm eval() call exists at this line
    if finding.file.endswith('.py'):
        try:
            tree = ast.parse(content)
            found_eval = False
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                    and hasattr(node, 'lineno') and node.lineno == finding.line
                    and isinstance(node.func, ast.Name)
                    and node.func.id == 'eval'):
                    found_eval = True
                    break
            if not found_eval:
                return None  # AST says no eval() here — false positive
        except SyntaxError:
            pass  # fall through to regex

    m = re.search(r'\beval\s*\((.+)\)', line)
    if not m:
        return None
    eval_arg = m.group(1).strip()

    if finding.file.endswith('.py'):
        replacement = f"ast.literal_eval({eval_arg})"
        new_line = line[:m.start()] + replacement + line[m.end():]
        # Add inline warning if not already commented
        if '#' not in new_line:
            new_line = new_line.rstrip('\n') + "  # NOTE: only works for literal expressions\n"
        eval_fix = Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced eval() with ast.literal_eval() (safe for literals, rejects arbitrary code)",
            source=FixSource.DETERMINISTIC,
        )
        # Ensure 'import ast' exists — if not, add it after the last existing import
        if not re.search(r'^\s*import\s+ast\b', content, re.MULTILINE):
            content_lines = content.splitlines(keepends=True)
            # Find last top-level import line
            last_import_idx = -1
            for i, cl in enumerate(content_lines):
                if re.match(r'^(import |from \S+ import )', cl):
                    last_import_idx = i
            if last_import_idx >= 0:
                import_line = content_lines[last_import_idx]
                import_fix = Fix(
                    file=finding.file, line=last_import_idx + 1, rule=finding.rule,
                    original_code=import_line,
                    fixed_code=import_line.rstrip('\n') + "\nimport ast\n",
                    explanation="Added 'import ast' required by ast.literal_eval()",
                    source=FixSource.DETERMINISTIC,
                )
            else:
                # No imports found — insert after module docstring or at line 1
                insert_idx = 0
                if content_lines:
                    first_stripped = content_lines[0].strip()
                    for tq in ('"""', "'''"):
                        if first_stripped.startswith(tq):
                            # Find closing triple-quote
                            if first_stripped.count(tq) >= 2:
                                insert_idx = 1  # single-line docstring
                            else:
                                for j in range(1, len(content_lines)):
                                    if tq in content_lines[j]:
                                        insert_idx = j + 1
                                        break
                            break
                target_line = content_lines[insert_idx] if insert_idx < len(content_lines) else "\n"
                import_fix = Fix(
                    file=finding.file, line=insert_idx + 1, rule=finding.rule,
                    original_code=target_line,
                    fixed_code="import ast\n" + target_line,
                    explanation="Added 'import ast' required by ast.literal_eval()",
                    source=FixSource.DETERMINISTIC,
                )
            return [import_fix, eval_fix]
        return eval_fix

    if finding.file.endswith(('.js', '.ts', '.jsx', '.tsx')):
        # Strip the eval-idiom parens wrapper: eval("(" + x + ")") → JSON.parse(x)
        stripped_arg = re.sub(
            r'^(["\'])\(\1\s*\+\s*(.+?)\s*\+\s*(["\'])\)\3$',
            r'\2',
            eval_arg,
        )
        new_line = line[:m.start()] + f"JSON.parse({stripped_arg})" + line[m.end():]
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced eval() with JSON.parse() (safe — rejects arbitrary code execution)",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_sql_injection(line: str, finding: Finding, content: str,
                       ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Replace string-concatenated SQL with parameterized query."""
    # Only fix Python files
    if not finding.file.endswith('.py'):
        return None
    indent = re.match(r'^(\s*)', line).group(1)

    # Pattern 1: cursor.execute(f"...{var}...")
    m = re.match(r'^(\s*)(\w+)\.execute\(f(["\'])(.+)\3\)', line.rstrip())
    if m:
        call_obj = m.group(2)
        sql_body = m.group(4)
        # Extract interpolated variables
        params = re.findall(r'\{(\w+)\}', sql_body)
        if not params:
            return None
        # Replace {var} with ? placeholders
        clean_sql = re.sub(r"'\{(\w+)\}'", "?", sql_body)
        clean_sql = re.sub(r"\{(\w+)\}", "?", clean_sql)
        param_tuple = ", ".join(params)
        new_line = f"{indent}{call_obj}.execute(\"{clean_sql}\", ({param_tuple},))\n"
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced string interpolation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    # Pattern 2: "SELECT ... WHERE x = " + var — skip, incomplete fix
    # (adds ? placeholder but doesn't modify execute() call to pass params)
    m = re.match(r'^(\s*)(\w+)\s*=\s*(["\'])(.+?)\3\s*\+\s*(\w+)', line.rstrip())
    if m:
        return None

    # Pattern 3: conn.execute("..." + var)
    m = re.match(r'^(\s*)(\w+)\.execute\((["\'])(.+?)\3\s*\+\s*(\w+)\)', line.rstrip())
    if m:
        call_obj = m.group(2)
        sql_body = m.group(4)
        param_var = m.group(5)
        new_line = f'{indent}{call_obj}.execute("{sql_body} ?", ({param_var},))\n'
        return Fix(
            file=finding.file, line=finding.line, rule=finding.rule,
            original_code=line, fixed_code=new_line,
            explanation="Replaced string concatenation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_resource_leak(line: str, finding: Finding, content: str,
                       ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Add .close() for unclosed resources (connections, cursors, file handles)."""
    if not finding.file.endswith('.py'):
        return None

    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Extract the variable name and its indentation from the source line: var = something(...)
    src = lines[line_idx]
    m = re.match(r'^(\s*)(\w+)\s*=\s*', src)
    if not m:
        return None
    creation_indent = m.group(1)  # actual indent where the resource is created
    var_name = m.group(2)

    # Find the containing function
    func_indent = None
    for i in range(line_idx - 1, -1, -1):
        fm = re.match(r'^(\s*)(async\s+)?def\s+', lines[i])
        if fm:
            func_indent = fm.group(1)
            break
    if func_indent is None:
        return None

    body_indent = creation_indent  # use the indent of where the resource was created

    # Scan forward to find the function body lines and the last return
    body_lines = []  # (index, stripped) for lines in this function body
    for i in range(line_idx + 1, len(lines)):
        stripped = lines[i].strip()
        if not stripped:
            continue
        cur_indent = len(lines[i]) - len(lines[i].lstrip())
        # Stop at anything at function-level indent or less: decorators, defs, classes, module code
        if cur_indent <= len(func_indent) and stripped:
            break
        body_lines.append((i, stripped))

    if not body_lines:
        return None

    # Check if the variable is returned — if so, can't close it
    for idx, stripped in body_lines:
        if stripped.startswith('return') and var_name in stripped:
            return None

    # Skip functions with multiple returns or try/except (too complex for safe fix)
    return_count = sum(1 for _, s in body_lines if s.startswith('return') or s == 'return')
    has_try = any(s.startswith('try:') for _, s in body_lines)
    if return_count > 1 or has_try:
        return None

    # Find the last return in the function body
    last_return_idx = None
    for idx, stripped in body_lines:
        if stripped.startswith('return') or stripped == 'return':
            last_return_idx = idx

    if last_return_idx is not None:
        # Insert .close() BEFORE the return — use the return line's indentation
        return_line = lines[last_return_idx]
        return_indent = re.match(r'^(\s*)', return_line).group(1)
        close_line = f"{return_indent}{var_name}.close()\n"
        new_code = close_line + return_line
        return Fix(
            file=finding.file, line=last_return_idx + 1, rule=finding.rule,
            original_code=return_line, fixed_code=new_code,
            explanation=f"Added {var_name}.close() before return to prevent resource leak",
            source=FixSource.DETERMINISTIC,
        )

    # No return — add .close() after the last body line
    last_idx = body_lines[-1][0]
    last_line = lines[last_idx]
    close_line = f"{body_indent}{var_name}.close()\n"
    new_code = last_line.rstrip('\n') + '\n' + close_line
    return Fix(
        file=finding.file, line=last_idx + 1, rule=finding.rule,
        original_code=last_line, fixed_code=new_code,
        explanation=f"Added {var_name}.close() to prevent resource leak",
        source=FixSource.DETERMINISTIC,
    )


def _fix_exception_swallowed(line: str, finding: Finding, content: str,
                             ctx: Optional[FixContext] = None) -> Optional[Fix]:
    """Add TODO comment to bare except: pass blocks."""
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1  # finding.line points to the except handler
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Find the `pass` line in the except body (should be next non-empty line)
    pass_idx = None
    for i in range(line_idx + 1, min(line_idx + 5, len(lines))):
        stripped = lines[i].strip()
        if stripped == "pass":
            pass_idx = i
            break
        if stripped and stripped != "pass":
            break  # Body isn't just `pass`, skip

    if pass_idx is None:
        return None

    # Replace pass with pass + TODO
    pass_line = lines[pass_idx]
    m = re.match(r'^(\s*)', pass_line)
    pass_indent = m.group(1) if m else ""
    new_pass = f"{pass_indent}pass  # TODO: handle this exception\n"
    return Fix(
        file=finding.file, line=pass_idx + 1, rule=finding.rule,
        original_code=pass_line, fixed_code=new_pass,
        explanation="Added TODO comment to silently swallowed exception",
        source=FixSource.DETERMINISTIC,
    )


# ─── Semantic guard helpers ───────────────────────────────────────────
# Called by fixers when FixContext.semantics is available — provide
# deeper analysis than the detector's initial pass.


def _semantic_import_is_referenced(name: str, semantics) -> bool:
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


def _semantic_var_is_used_in_child_scope(name: str, assign_scope_id: int, semantics) -> bool:
    """Check if a variable assigned in scope X is referenced in a child scope.

    This catches closure variables and nested function access that the detector
    might miss because it only checks the immediate scope.
    """
    # Build set of child scope IDs
    child_ids = set()

    def _collect_children(parent_id):
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


def _semantic_var_in_all_export(name: str, semantics) -> bool:
    """Check if a variable is listed in __all__ (re-export)."""
    for assign in semantics.assignments:
        if assign.name == '__all__' and assign.value_text:
            # value_text is the raw source of the RHS — check if our name is in it
            if re.search(r"""['"]""" + re.escape(name) + r"""['"]""", assign.value_text):
                return True
    return False


def _type_map_var_is_non_nullable(name: str, scope_id: int, type_map) -> bool:
    """Check FileTypeMap to see if (name, scope_id) has a non-nullable type."""
    # FileTypeMap.types is dict[(var_name, scope_id), TypeInfo]
    type_info = type_map.types.get((name, scope_id))
    if type_info and not type_info.nullable:
        return True
    return False


def _record_fix_metric(rule: str, succeeded: bool, duration_ms: float) -> None:
    """Record a fix attempt in the current metrics session (best-effort)."""
    try:
        from .metrics import get_session
        session = get_session()
        if session:
            session.record_fix(rule, succeeded, duration_ms)
    except Exception:
        pass


DETERMINISTIC_FIXERS: dict[str, FixerFn] = {
    "unused-import": _fix_unused_import,
    "unused-variable": _fix_unused_variable,
    "bare-except": _fix_bare_except,
    "loose-equality": _fix_loose_equality,

    "none-comparison": _fix_none_comparison,
    "type-comparison": _fix_type_comparison,
    "console-log": _fix_console_log,
    "insecure-http": _fix_insecure_http,
    "fstring-no-expr": _fix_fstring_no_expr,
    "hardcoded-secret": _fix_hardcoded_secret,
    "open-without-with": _fix_open_without_with,
    "yaml-unsafe": _fix_yaml_unsafe,
    "weak-hash": _fix_weak_hash,
    "unreachable-code": _fix_unreachable_code,
    "mutable-default": _fix_mutable_default,
    "exception-swallowed": _fix_exception_swallowed,
    "resource-leak": _fix_resource_leak,
    "os-system": _fix_os_system,
    "eval-usage": _fix_eval_usage,
    "sql-injection": _fix_sql_injection,
}


# ─── LLM fix integration ─────────────────────────────────────────────


def generate_llm_fixes(
    filepath: str, content: str, language: str,
    findings: list[Finding], cost_tracker=None,
) -> list[Fix]:
    """Send findings to LLM, get back structured fixes.

    Falls back gracefully if LLM is unavailable.
    """
    if not findings:
        return []

    try:
        from .llm import fix_file as llm_fix_file, CostTracker, LLMError
        if cost_tracker is None:
            cost_tracker = CostTracker()

        findings_dicts = []
        for f in findings:
            findings_dicts.append({
                "line": f.line,
                "rule": f.rule,
                "message": f.message,
                "suggestion": f.suggestion or "",
            })

        raw_fixes, cost_tracker = llm_fix_file(
            content, filepath, language, findings_dicts, cost_tracker,
        )

        fixes = []
        for rf in raw_fixes:
            try:
                fixes.append(Fix(
                    file=filepath,
                    line=rf.get("line", 0),
                    rule=rf.get("rule", "llm-fix"),
                    original_code=rf.get("original_code", ""),
                    fixed_code=rf.get("fixed_code", ""),
                    explanation=rf.get("explanation", "LLM-generated fix"),
                    source=FixSource.LLM,
                ))
            except (KeyError, TypeError):
                continue

        return fixes

    except (LLMError, OSError, ValueError) as e:
        logger.warning("LLM fix generation failed: %s", e)
        return []


# ─── Fix application engine ──────────────────────────────────────────


def apply_fixes(
    filepath: str, fixes: list[Fix],
    dry_run: bool = True, create_backup: bool = True,
) -> list[Fix]:
    """Apply fixes to a file. Bottom-to-top to preserve line numbers.

    Returns the list of fixes with updated statuses.
    """
    if not fixes:
        return fixes

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        for fix in fixes:
            fix.status = FixStatus.FAILED
            fix.fail_reason = f"cannot read file: {e}"
        logger.warning("Cannot read %s: %s", filepath, e)
        return fixes

    lines = content.splitlines(keepends=True)

    # Sort by line descending so we apply from bottom up
    indexed_fixes = sorted(enumerate(fixes), key=lambda x: x[1].line, reverse=True)

    occupied_lines: set[int] = set()
    deleted_indices: set[int] = set()  # Track lines blanked by fixes (not original blank lines)

    for idx, fix in indexed_fixes:
        # Determine the full line range this fix covers
        start_line = fix.line
        end_line = fix.end_line if fix.end_line is not None else fix.line
        fix_range = set(range(start_line, end_line + 1))

        if fix_range & occupied_lines:
            fix.status = FixStatus.SKIPPED
            fix.fail_reason = "overlaps with another fix on the same line(s)"
            continue

        # Validate: check that original_code matches the actual file content
        line_idx = fix.line - 1  # 0-based
        if line_idx < 0 or line_idx >= len(lines):
            fix.status = FixStatus.FAILED
            fix.fail_reason = f"line {fix.line} out of range (file has {len(lines)} lines)"
            continue

        # For deletion fixes (empty fixed_code), remove the line(s)
        if fix.original_code and not fix.fixed_code:
            # Verify original matches
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() != actual.strip():
                fix.status = FixStatus.FAILED
                fix.fail_reason = "original code not found at this line (already fixed?)"
                continue
            if not dry_run:
                # Blank out all lines in the range
                for li in range(line_idx, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        elif fix.original_code and fix.fixed_code:
            # Replacement fix — verify original is present
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() != actual.strip():
                fix.status = FixStatus.FAILED
                fix.fail_reason = "original code not found at this line (already fixed?)"
                continue
            if not dry_run:
                # Replace the first line with fixed_code
                new_code = fix.fixed_code
                if not new_code.endswith("\n") and actual.endswith("\n"):
                    new_code += "\n"
                lines[line_idx] = new_code
                # Blank out remaining lines in range (line+1..end_line)
                for li in range(line_idx + 1, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        else:
            fix.status = FixStatus.FAILED
            fix.fail_reason = "missing original or replacement code"

    if not dry_run:
        # Remove only lines that were blanked by fixes, not original blank lines
        new_content = "".join(line for i, line in enumerate(lines) if i not in deleted_indices)

        # Backup
        if create_backup:
            backup_path = filepath + ".doji.bak"
            try:
                shutil.copy2(filepath, backup_path)
            except OSError as e:
                logger.warning("Could not create backup: %s", e)

        # Atomic write: write to temp file, then rename
        try:
            dir_name = os.path.dirname(filepath) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".doji.tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(new_content)
                # On Windows, we need to remove the target first
                if sys.platform == "win32" and os.path.exists(filepath):
                    os.replace(tmp_path, filepath)
                else:
                    os.rename(tmp_path, filepath)
            except (OSError, ValueError):  # cleanup-and-reraise for temp file
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.warning("Error writing %s: %s", filepath, e)
            for fix in fixes:
                if fix.status == FixStatus.APPLIED:
                    fix.status = FixStatus.FAILED
                    fix.fail_reason = f"cannot write file: {e}"

    return fixes


# ─── Fix verification ─────────────────────────────────────────────────


def verify_fixes(filepath: str, language: str,
                 pre_findings: list[Finding],
                 custom_rules=None,
                 allowed_cascades: set[str] | None = None) -> dict:
    """Re-scan a file after fixes and compare before/after.

    Uses 5-line bucket matching to determine which issues were resolved
    and whether any new issues were introduced.

    Args:
        allowed_cascades: Set of rule names (e.g. {'unused-import'}) that are
            expected side-effects of fixes and should not trigger rollback.
            Computed by derive_expected_cascades() from AST analysis.

    Returns dict with:
      - resolved: int (issues that were fixed)
      - remaining: int (issues still present)
      - new_issues: int (issues introduced by fixes — excludes expected cascades)
      - cascaded: int (new issues that are expected cascades, not counted)
      - new_findings: list of new Finding dicts
    """
    from .detector import analyze_file_static

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            new_content = f.read()
    except OSError:
        return {"resolved": 0, "remaining": 0, "new_issues": 0, "cascaded": 0,
                "new_findings": [], "error": f"Could not re-read {filepath}"}

    post_findings = analyze_file_static(filepath, new_content, language,
                                        custom_rules=custom_rules)

    if not allowed_cascades:
        allowed_cascades = set()

    # Compare by rule counts: for each rule, how many before vs after.
    # Increase in count for a rule = new issues. Decrease = resolved.
    from collections import Counter
    pre_counts = Counter(f.rule for f in pre_findings)
    post_counts = Counter(f.rule for f in post_findings)
    # Rules that fixers intentionally introduce (e.g., TODO markers) should
    # not trigger rollback. Track info-only new rules separately.
    info_only_rules = {f.rule for f in post_findings if getattr(f.severity, 'value', f.severity) == "info"} - set(pre_counts)

    all_rules = set(pre_counts) | set(post_counts)
    resolved = 0
    remaining = 0
    new_issues = 0
    cascaded = 0
    for rule in all_rules:
        if rule in info_only_rules:
            continue  # skip info-only rules that fixers intentionally introduce
        before = pre_counts.get(rule, 0)
        after = post_counts.get(rule, 0)
        if after <= before:
            resolved += before - after
            remaining += after
        else:
            delta = after - before
            if rule in allowed_cascades:
                cascaded += delta
            else:
                remaining += before
                new_issues += delta

    new_findings = []
    # Only report findings with rules not present at all before
    pre_rules = set(pre_counts)
    for finding in post_findings:
        if finding.rule not in pre_rules:
            new_findings.append(finding.to_dict())

    return {
        "resolved": resolved,
        "remaining": remaining,
        "new_issues": new_issues,
        "cascaded": cascaded,
        "new_findings": new_findings,
    }


# ─── Post-fix validation & rollback ──────────────────────────────────


def _strip_template_literals(content: str) -> str:
    """Replace template literal content (including nested ${} expressions) with spaces.

    Uses a stack-based state machine to handle nested backticks inside ${} expressions.
    Preserves string length so positions remain valid for brace counting.
    """
    result = list(content)
    i = 0
    n = len(content)
    # Stack tracks nesting: 'T' = inside template literal, 'E' = inside ${} expression
    stack: list[str] = []

    while i < n:
        ch = content[i]

        if not stack:
            # Outside any template literal
            if ch == '`':
                stack.append('T')
                result[i] = ' '
            i += 1
            continue

        top = stack[-1]

        if top == 'T':
            # Inside template literal body
            if ch == '\\' and i + 1 < n:
                result[i] = ' '
                result[i + 1] = ' '
                i += 2
                continue
            if ch == '$' and i + 1 < n and content[i + 1] == '{':
                # Enter ${} expression
                result[i] = ' '
                result[i + 1] = ' '
                stack.append('E')
                i += 2
                continue
            if ch == '`':
                # End of template literal
                result[i] = ' '
                stack.pop()
                i += 1
                continue
            # Regular template content — blank it
            result[i] = ' '
            i += 1
            continue

        if top == 'E':
            # Inside ${} expression — blank everything (braces here are
            # template-internal and must not be counted by the validator)
            if ch == '}':
                result[i] = ' '
                stack.pop()
                i += 1
                continue
            if ch == '`':
                # Nested template literal inside ${}
                result[i] = ' '
                stack.append('T')
                i += 1
                continue
            if ch == '{':
                # Nested object literal / block inside expression
                result[i] = ' '
                stack.append('E')
                i += 1
                continue
            # Blank all expression content (parens, brackets, code)
            result[i] = ' '
            i += 1
            continue

        i += 1

    return "".join(result)


def _validate_syntax(filepath: str, content: str, language: str) -> Optional[str]:
    """Validate syntax of fixed file. Returns error message or None if valid."""
    if language == "python":
        try:
            ast.parse(content, filename=filepath)
        except SyntaxError as e:
            return f"Python syntax error: {e.msg} (line {e.lineno})"
    elif language in ("javascript", "typescript"):
        # Lightweight check: balanced braces, parens, brackets
        # Strip string literals, template literals, and comments first
        # to avoid counting delimiters inside non-code regions.
        stripped = _strip_template_literals(content)                    # template literals (nested-safe)
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '', stripped)          # double-quoted strings
        stripped = re.sub(r"'(?:[^'\\]|\\.)*'", '', stripped)          # single-quoted strings
        stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)  # block comments
        stripped = re.sub(r'//[^\n]*', '', stripped)                    # line comments
        # Regex literals: /pattern/flags after common preceding tokens
        stripped = re.sub(r'(?<=[=(:,;\[!&|?{}\n])\s*/(?:[^/\\\n]|\\.)+/[gimsuy]*', '', stripped)
        counts = {'(': 0, '[': 0, '{': 0}
        closers = {')': '(', ']': '[', '}': '{'}
        for ch in stripped:
            if ch in counts:
                counts[ch] += 1
            elif ch in closers:
                counts[closers[ch]] -= 1
        for opener, count in counts.items():
            if count != 0:
                closer = {'(': ')', '[': ']', '{': '}'}[opener]
                return f"Unbalanced '{opener}'/'{closer}' (off by {count})"
    return None


def _rollback_from_backup(filepath: str, fixes: list[Fix], reason: str = "") -> None:
    """Restore file from .doji.bak backup and mark all applied fixes as FAILED."""
    backup_path = filepath + ".doji.bak"
    if os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, filepath)
            logger.info("Rolled back %s from backup", filepath)
        except OSError as e:
            logger.warning("Rollback failed for %s: %s", filepath, e)
    for fix in fixes:
        if fix.status == FixStatus.APPLIED:
            fix.status = FixStatus.FAILED
            if reason:
                fix.fail_reason = reason


# ─── Main orchestrator ────────────────────────────────────────────────


def fix_file(
    filepath: str, content: str, language: str,
    findings: list[Finding],
    use_llm: bool = False,
    dry_run: bool = True,
    create_backup: bool = True,
    rules: Optional[list[str]] = None,
    cost_tracker=None,
    verify: bool = True,
    custom_rules=None,
    semantics=None,
    type_map=None,
) -> FixReport:
    """Generate and optionally apply fixes for all findings in a file.

    Flow:
    1. Filter findings to rules if specified
    2. For each finding: check DETERMINISTIC_FIXERS first
    3. Remaining findings: batch to generate_llm_fixes() if use_llm=True
    4. Sort all fixes by line (descending)
    5. Call apply_fixes() with dry_run flag
    6. Return FixReport
    """
    # Filter by rules if specified
    if rules:
        rule_set = set(rules)
        findings = [f for f in findings if f.rule in rule_set]

    if not findings:
        return FixReport(
            root=filepath, files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )

    lines = content.splitlines(keepends=True)
    all_fixes: list[Fix] = []
    remaining: list[Finding] = []

    # Part 1: Deterministic fixes — all fixers receive FixContext
    import time as _time
    _fix_start = _time.perf_counter()

    for finding in findings:
        fixer = DETERMINISTIC_FIXERS.get(finding.rule)
        if not fixer:
            remaining.append(finding)
            continue

        line_idx = finding.line - 1
        if not (0 <= line_idx < len(lines)):
            remaining.append(finding)
            continue

        ctx = FixContext(
            content=content, finding=finding,
            semantics=semantics, type_map=type_map,
            language=language,
        )
        _t0 = _time.perf_counter()
        result = fixer(lines[line_idx], finding, content, ctx)
        _dur_ms = (_time.perf_counter() - _t0) * 1000

        if result:
            if isinstance(result, list):
                all_fixes.extend(result)
            else:
                all_fixes.append(result)
            _record_fix_metric(finding.rule, True, _dur_ms)
        else:
            _record_fix_metric(finding.rule, False, _dur_ms)
            remaining.append(finding)

    # Part 2: LLM fixes for remaining findings
    if use_llm and remaining:
        from .llm import CostTracker
        if cost_tracker is None:
            cost_tracker = CostTracker()
        llm_fixes = generate_llm_fixes(
            filepath, content, language, remaining, cost_tracker,
        )
        all_fixes.extend(llm_fixes)

    if not all_fixes:
        return FixReport(
            root=filepath, files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )

    # Resolve conflicts between fixers that target the same lines.
    #
    # 1. If a variable is both hardcoded-secret AND unused-variable,
    #    unused-variable wins (delete dead code, don't bother securing it).
    # 2. Don't remove imports that surviving fixes still need.
    unused_var_lines = {fix.line for fix in all_fixes if fix.rule == "unused-variable"}
    all_fixes = [
        fix for fix in all_fixes
        if not (fix.rule == "hardcoded-secret" and fix.line in unused_var_lines)
    ]

    # 3. If both open-without-with and resource-leak target the same variable in
    #    the same file, drop the resource-leak fix (the with block subsumes .close()).
    oww_vars: set[tuple[str, str]] = set()
    for fix in all_fixes:
        if fix.rule == "open-without-with" and fix.fixed_code:
            vm = re.search(r'as\s+(\w+)\s*:', fix.fixed_code)
            if vm:
                oww_vars.add((fix.file, vm.group(1)))
    if oww_vars:
        all_fixes = [
            fix for fix in all_fixes
            if not (fix.rule == "resource-leak" and fix.original_code and
                    any((fix.file, var) in oww_vars
                        for var in re.findall(r'(\w+)\.close\(\)', fix.fixed_code or "")))
        ]

    # Check which modules surviving fixes still need
    modules_needed: set[str] = set()
    for fix in all_fixes:
        if fix.rule != "unused-import" and fix.fixed_code:
            if "os.environ" in fix.fixed_code:
                modules_needed.add("os")
            if "ast.literal_eval" in fix.fixed_code:
                modules_needed.add("ast")
            if "subprocess.run" in fix.fixed_code:
                modules_needed.add("subprocess")
            if "shlex.split" in fix.fixed_code:
                modules_needed.add("shlex")
    if modules_needed:
        all_fixes = [
            fix for fix in all_fixes
            if not (fix.rule == "unused-import" and fix.original_code and
                    any(f"import {mod}" in fix.original_code for mod in modules_needed))
        ]

    # Apply fixes
    all_fixes = apply_fixes(filepath, all_fixes, dry_run=dry_run, create_backup=create_backup)

    applied = sum(1 for f in all_fixes if f.status == FixStatus.APPLIED)
    skipped = sum(1 for f in all_fixes if f.status == FixStatus.SKIPPED)
    failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)

    # Post-fix syntax validation — rollback if broken
    if not dry_run and applied > 0:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                fixed_content = f.read()
            syntax_err = _validate_syntax(filepath, fixed_content, language)
            if syntax_err:
                logger.warning("Syntax validation failed after fix: %s — rolling back", syntax_err)
                _rollback_from_backup(filepath, all_fixes, reason=f"rolled back — {syntax_err}")
                applied = 0
                failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
        except OSError:
            pass

    llm_cost = 0.0
    if cost_tracker:
        llm_cost = cost_tracker.total_cost

    # Verify fixes if actually applied
    verification = None
    if verify and not dry_run and applied > 0:
        # Derive expected cascades from AST analysis of original content + applied fixes
        applied_fix_list = [f for f in all_fixes if f.status == FixStatus.APPLIED]
        allowed_cascades = derive_expected_cascades(
            content, language, applied_fix_list, semantics=semantics)
        verification = verify_fixes(filepath, language, findings,
                                    custom_rules=custom_rules,
                                    allowed_cascades=allowed_cascades)
        # Auto-rollback if fixes introduced new issues
        if verification and verification.get("new_issues", 0) > 0:
            logger.warning("Fixes introduced %d new issue(s) — rolling back", verification["new_issues"])
            _rollback_from_backup(filepath, all_fixes, reason=f"rolled back — fixes introduced {verification['new_issues']} new issue(s)")
            applied = 0
            failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
            verification = {"rolled_back": True,
                            "reason": f"{verification.get('new_issues', 0)} new issue(s) introduced"}

    # Record total fix duration in metrics
    _fix_total_ms = (_time.perf_counter() - _fix_start) * 1000
    try:
        from .metrics import get_session
        session = get_session()
        if session:
            session.fix_duration_ms += _fix_total_ms
    except Exception:
        pass

    return FixReport(
        root=filepath,
        files_fixed=1 if applied > 0 else 0,
        total_fixes=len(all_fixes),
        applied=applied,
        skipped=skipped,
        failed=failed,
        fixes=all_fixes,
        llm_cost_usd=llm_cost,
        verification=verification,
    )
