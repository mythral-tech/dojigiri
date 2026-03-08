"""Deterministic fixers -- the catalog of 19 rule-specific fix functions.

Each fixer is a pure function: (line, finding, content, ctx?) -> Fix | None.
They use regex and AST transforms to produce fixes without LLM calls.
The DETERMINISTIC_FIXERS dict maps rule names to their fixer functions.

Called by: engine.py (fix_file iterates DETERMINISTIC_FIXERS)
Calls into: helpers.py (AST/string helpers, semantic guards), config.py (Fix, FixSource, etc.)
Data in -> Data out: source line + Finding + file content -> Fix object or None
"""

import ast
import logging
import os
import re
from typing import Protocol

from ..types import Finding, Fix, FixContext, FixSource

logger = logging.getLogger(__name__)

from .helpers import (
    _extract_name_from_message,
    _find_ast_node,
    _in_multiline_string,
    _is_empty_mutable,
    _op_str,
    _pattern_outside_strings,
    _replace_node_source,
    _semantic_import_is_referenced,
    _semantic_var_in_all_export,
    _semantic_var_is_used_in_child_scope,
    _sub_outside_strings,
)


class FixerFn(Protocol):
    """Deterministic fix generator -- unified protocol.

    All fixers receive FixContext which always carries the full file content,
    finding, and optionally semantic/type data. The `line` param is the raw
    line text for convenience (avoiding repeated splitlines).
    """

    def __call__(
        self, line: str, finding: Finding, content: str, ctx: FixContext | None = None
    ) -> Fix | list[Fix] | None: ...


# ─── Deterministic fixers ────────────────────────────────────────────
# Each takes (line, finding, full_content) and returns Fix | None.


def _fix_unused_import(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Remove an unused import. AST-first: handles multiline from...import correctly.

    When semantic data is available via ctx, double-checks that the import name
    is truly unreferenced across all scopes (catches re-exports, attribute access).
    """
    # Extract the unused name from the finding message
    unused_name = _extract_name_from_message(finding.message)
    if not unused_name:
        # Fallback: extract from the line text
        m = re.match(r"^\s*import\s+(\w+)", line)
        if m:
            unused_name = m.group(1)

    # Semantic guard: if we have full semantic data, verify the import is truly unused
    if unused_name and ctx and ctx.semantics:
        if _semantic_import_is_referenced(unused_name, ctx.semantics):
            return None  # Detector was wrong -- name IS used somewhere

    # AST approach for Python
    if finding.file.endswith(".py") and unused_name:
        node = _find_ast_node(content, finding.line, (ast.Import, ast.ImportFrom))
        if node:
            # Skip if inside a try block (optional import pattern)
            try:
                tree = ast.parse(content)
                for parent in ast.walk(tree):
                    for child in ast.iter_child_nodes(parent):
                        if child is node and isinstance(parent, ast.Try):
                            return None
            except SyntaxError as e:
                logger.debug("Failed to parse AST for import check: %s", e)

            if isinstance(node, ast.ImportFrom) and len(node.names) > 1:
                # Multi-name import: remove only the unused name, keep the rest
                remaining = [a for a in node.names if a.name != unused_name]
                if remaining and len(remaining) < len(node.names):
                    remaining_strs = [f"{a.name} as {a.asname}" if a.asname else a.name for a in remaining]
                    lines_list = content.splitlines(keepends=True)
                    start = node.lineno - 1
                    end = node.end_lineno if node.end_lineno else node.lineno
                    original_text = "".join(lines_list[start:end])
                    indent = re.match(r"^(\s*)", lines_list[start]).group(1)
                    module = node.module or ""
                    new_text = f"{indent}from {module} import {', '.join(remaining_strs)}\n"
                    return Fix(
                        file=finding.file,
                        line=finding.line,
                        rule=finding.rule,
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
                        file=finding.file,
                        line=finding.line,
                        rule=finding.rule,
                        original_code=line,
                        fixed_code="",
                        explanation=f"Removed unused import: {unused_name}",
                        source=FixSource.DETERMINISTIC,
                    )
            elif isinstance(node, ast.ImportFrom) and len(node.names) == 1:
                return Fix(
                    file=finding.file,
                    line=finding.line,
                    rule=finding.rule,
                    original_code=line,
                    fixed_code="",
                    explanation=f"Removed unused import: {line.strip()}",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback for non-Python or parse failure
    stripped = line.strip()
    if stripped.startswith("import ") or stripped.startswith("from "):
        if "(" in stripped and ")" not in stripped:
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
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code="",
            explanation=f"Removed unused import: {stripped}",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_bare_except(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace bare `except:` with `except Exception:`. AST-first with regex fallback."""
    # AST: confirm this is actually a bare except handler
    if finding.file.endswith(".py"):
        node = _find_ast_node(
            content,
            finding.line,
            ast.ExceptHandler,
            predicate=lambda n: n.type is None,
        )
        if node:
            # Use node position for precise replacement
            lines = content.splitlines(keepends=True)
            original_line = lines[node.lineno - 1]
            indent = re.match(r"^(\s*)", original_line).group(1)
            return Fix(
                file=finding.file,
                line=finding.line,
                rule=finding.rule,
                original_code=original_line,
                fixed_code=f"{indent}except Exception:\n",
                explanation="Replaced bare except with 'except Exception:' to avoid catching SystemExit/KeyboardInterrupt",
                source=FixSource.DETERMINISTIC,
            )

    # Regex fallback (non-Python)
    m = re.match(r"^(\s*)except\s*:", line)
    if m:
        indent = m.group(1)
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=f"{indent}except Exception:\n",
            explanation="Replaced bare except with 'except Exception:' to avoid catching SystemExit/KeyboardInterrupt",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_loose_equality(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace == with === and != with !== in JS/TS."""
    from .helpers import _STRING_LITERAL_RE

    # Preserve == null idiom (checks both null and undefined intentionally)
    code_only = _STRING_LITERAL_RE.sub(lambda m: " " * len(m.group()), line)
    if re.search(r"(?<!=)==(?!=)\s*null\b", code_only) or re.search(r"(?<!=)!=(?!=)\s*null\b", code_only):
        return None
    new_line = line
    # Replace != before == to avoid double-replacing !== back
    new_line = _sub_outside_strings(new_line, r"(?<!=)!=(?!=)", "!==")
    new_line = _sub_outside_strings(new_line, r"(?<!=)==(?!=)", "===")
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced loose equality with strict equality",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_none_comparison(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace ``x == None`` / ``x != None`` with identity checks. AST-first."""  # doji:ignore(none-comparison)
    # AST approach: structurally rebuild the comparison
    if finding.file.endswith(".py"):

        def _is_none_eq(node):
            return isinstance(node, ast.Compare) and any(
                isinstance(comp, ast.Constant) and comp.value is None and isinstance(op, (ast.Eq, ast.NotEq))
                for op, comp in zip(node.ops, node.comparators)
            )

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
                    file=finding.file,
                    line=finding.line,
                    rule=finding.rule,
                    original_code=lines[li],
                    fixed_code=new_lines[li],
                    explanation="Use identity comparison for None (PEP 8)",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback (non-Python or parse failure)
    if not _pattern_outside_strings(line, re.compile(r"(?:==|!=)\s*None\b")):
        return None
    if _in_multiline_string(content, finding.line):
        return None
    new_line = line
    new_line = _sub_outside_strings(new_line, r"!=\s*None\b", "is not None")
    new_line = _sub_outside_strings(new_line, r"==\s*None\b", "is None")
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Use identity comparison for None (PEP 8)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_type_comparison(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace `type(x) == Y` with `isinstance(x, Y)`. AST-first: handles nested parens."""
    # AST approach
    if finding.file.endswith(".py"):

        def _is_type_compare(node):
            return (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.Is))
                and isinstance(node.left, ast.Call)
                and isinstance(node.left.func, ast.Name)
                and node.left.func.id == "type"
                and len(node.left.args) == 1
            )

        node = _find_ast_node(content, finding.line, ast.Compare, _is_type_compare)
        if node and node.end_lineno and node.end_col_offset is not None:
            # Extract the argument to type() and the comparator using ast.unparse
            # This handles arbitrary nesting: type((x)) == dict -> isinstance(x, dict)
            arg_src = ast.get_source_segment(content, node.left.args[0]) or ast.unparse(node.left.args[0])
            type_src = ast.get_source_segment(content, node.comparators[0]) or ast.unparse(node.comparators[0])
            replacement = f"isinstance({arg_src}, {type_src})"
            new_content = _replace_node_source(content, node, replacement)
            new_lines = new_content.splitlines(keepends=True)
            lines = content.splitlines(keepends=True)
            li = finding.line - 1
            if li < len(lines) and li < len(new_lines) and new_lines[li] != lines[li]:
                return Fix(
                    file=finding.file,
                    line=finding.line,
                    rule=finding.rule,
                    original_code=lines[li],
                    fixed_code=new_lines[li],
                    explanation="Use isinstance() instead of type() comparison for proper subclass support",
                    source=FixSource.DETERMINISTIC,
                )

    # Regex fallback
    m = re.search(r"type\((.+?)\)\s*==\s*(\w+)", line)
    if m:
        var = m.group(1).strip()
        if var.startswith("(") and var.endswith(")"):
            var = var[1:-1].strip()
        typ = m.group(2).strip()
        new_line = line[: m.start()] + f"isinstance({var}, {typ})" + line[m.end() :]
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Use isinstance() instead of type() comparison for proper subclass support",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_console_log(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Remove console.log() line -- only if it's the sole statement."""
    if "console.log" not in line:
        return None
    stripped = line.strip().rstrip(";").strip()
    # If the line has other statements (semicolons outside the console.log call),
    # or is chained, skip instead of deleting the whole line.
    # Match a standalone console.log(...) call
    if not re.match(r"^console\.log\s*\(.*\)\s*;?\s*$", stripped):
        return None
    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code="",
        explanation="Removed console.log() debug statement",
        source=FixSource.DETERMINISTIC,
    )


def _fix_insecure_http(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace http:// with https:// in URLs."""
    # Skip if line is inside a multiline string (docstring)
    if _in_multiline_string(content, finding.line):
        return None
    # Skip single-line docstrings
    stripped = line.strip()
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return None
    # Skip localhost and internal URLs -- these legitimately use HTTP
    new_line = re.sub(
        r"http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\])",  # doji:ignore(insecure-http)
        "https://",
        line,
    )
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Upgraded insecure HTTP URL to HTTPS",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_fstring_no_expr(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Remove f-prefix from f-strings with no expressions."""
    # Match f"..." or f'...' where content has no { }
    new_line = re.sub(r"""\bf(["'])((?:[^{}\\]|\\.)*?)\1""", r"\1\2\1", line)
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Removed unnecessary f-string prefix (no expressions)",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_hardcoded_secret(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace hardcoded secret with os.environ lookup."""
    # Skip test files -- secrets there are usually fixtures, not real
    basename = os.path.basename(finding.file)
    dirparts = finding.file.replace("\\", "/").split("/")
    if (
        basename.startswith("test_")
        or basename.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
        or "__tests__" in dirparts
    ):
        return None
    # Match: VAR_NAME = "secret_value" or VAR_NAME = 'secret_value'
    m = re.match(r'^(\s*)(\w+)\s*=\s*["\'].*?["\']', line)
    if not m:
        return None
    indent = m.group(1)
    var_name = m.group(2)
    is_js = finding.file.endswith((".js", ".ts", ".jsx", ".tsx"))
    if is_js:
        new_line = f"{indent}{var_name} = process.env.{var_name}\n"
        explanation = f"Replaced hardcoded secret with process.env.{var_name}"
    else:
        new_line = f'{indent}{var_name} = os.environ["{var_name}"]\n'
        explanation = f'Replaced hardcoded secret with os.environ["{var_name}"]'
    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code=new_line,
        explanation=explanation,
        source=FixSource.DETERMINISTIC,
    )


def _fix_open_without_with(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Wrap `x = open(...)` in a `with` statement."""
    m = re.match(r"^(\s*)(\w+)\s*=\s*open\((.+)\)\s*$", line.rstrip("\n"))
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
    var_pat = re.compile(r"\b" + re.escape(var_name) + r'\b(?!["\'])')
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
            break  # shallower indent -- left the scope
        candidate_lines.append(subsequent)

    # Trim from the end: find the last line that uses the variable
    last_var_use = -1
    for j, cl in enumerate(candidate_lines):
        if var_pat.search(cl):
            last_var_use = j
    body_lines = candidate_lines[: last_var_use + 1] if last_var_use >= 0 else []

    # If the last var-use line is a block header (for/if/while/with ending with ':'),
    # extend to include its indented body -- otherwise we'd leave a headless block.
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

    # Remove explicit .close() calls on the variable -- the with block handles it
    close_pat = re.compile(r"^\s*" + re.escape(var_name) + r"\.close\(\)\s*$")
    body_lines = [bl for bl in body_lines if not close_pat.match(bl)]

    if not body_lines:
        # No body found -- emit with ... as f:\n    pass
        new_code = f"{indent}with open({open_args}) as {var_name}:\n{indent}    pass\n"  # doji:ignore(resource-leak)
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_code,
            explanation="Wrapped open() in 'with' statement for automatic cleanup",
            source=FixSource.DETERMINISTIC,
        )

    # Build the with block with re-indented body (preserve relative indentation)
    open_stmt = f"open({open_args})"  # doji:ignore(resource-leak)
    code_lines = [f"{indent}with {open_stmt} as {var_name}:\n"]
    for bl in body_lines:
        if bl.strip():
            # Preserve indentation relative to the original indent level
            if bl.startswith(indent):
                relative = bl[len(indent) :]
            else:
                relative = bl.lstrip()
            code_lines.append(indent + "    " + relative)
        else:
            code_lines.append(bl)
    new_code = "".join(code_lines)

    # Set end_line so apply_fixes blanks out the original body lines
    last_body_line = finding.line + len(body_lines)
    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code=new_code,
        explanation="Wrapped open() in 'with' statement for automatic cleanup",
        source=FixSource.DETERMINISTIC,
        end_line=last_body_line,
    )


def _fix_yaml_unsafe(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace yaml.load() with yaml.safe_load()."""
    # Skip if SafeLoader or Loader= already present on this line
    if "SafeLoader" in line or "Loader=" in line:
        return None
    new_line = re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", line)
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced yaml.load() with yaml.safe_load() to prevent arbitrary code execution",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_weak_hash(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace hashlib.md5/sha1 with hashlib.sha256."""
    # Skip if usedforsecurity=False is present (legitimate non-crypto use)
    if "usedforsecurity=False" in line or "usedforsecurity = False" in line:
        return None
    new_line = re.sub(r"\bhashlib\.(?:md5|sha1)\s*\(", "hashlib.sha256(", line)
    if new_line != line:
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced weak hash (MD5/SHA1) with SHA-256",
            source=FixSource.DETERMINISTIC,
        )
    return None


def _fix_unreachable_code(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Delete a single unreachable line after return/raise/break/continue."""
    stripped = line.strip()
    # Only fix simple single-line statements, not block starters
    if stripped.endswith(":") or not stripped:
        return None
    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code="",
        explanation=f"Removed unreachable code: {stripped}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_mutable_default(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace mutable default argument with None + body guard.

    AST-first: uses ast.FunctionDef to identify mutable defaults precisely,
    then uses node positions for text replacement -- handles multiline signatures.
    """
    if finding.file.endswith(".py"):
        node = _find_ast_node(
            content,
            finding.line,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
        if node:
            return _mutable_default_ast(node, finding, content)

    # Regex fallback for non-Python (shouldn't normally trigger for this rule)
    return _mutable_default_regex(line, finding, content)


def _mutable_default_ast(node, finding: Finding, content: str) -> Fix | None:
    """AST-based mutable default fix: uses node structure for correct parameter identification."""
    lines = content.splitlines(keepends=True)
    indent = re.match(r"^(\s*)", lines[node.lineno - 1]).group(1)

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

    # Replace each mutable default with None -- work backwards through source
    # to preserve earlier positions
    modified = content
    for param_name, default_node, mutable_expr in reversed(mutable_params):
        if default_node.end_lineno and default_node.end_col_offset is not None:
            modified = _replace_node_source(modified, default_node, "None")

    # Now find the function body insertion point (after signature + docstring)
    body_start_line = node.body[0].lineno if node.body else node.end_lineno or node.lineno
    # If first body statement is a docstring, insert after it
    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    ):
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
    _orig_text = "".join(orig_lines[start:orig_end])
    # In the modified version, we have extra guard lines
    new_end = orig_end + guard_text.count("\n")
    new_text = "".join(mod_lines_final[start:new_end])

    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=orig_lines[start],
        fixed_code=new_text,
        explanation="Replaced mutable default argument with None + guard clause",
        source=FixSource.DETERMINISTIC,
        end_line=orig_end,
    )


def _mutable_default_regex(line: str, finding: Finding, content: str) -> Fix | None:
    """Regex fallback for mutable default fix."""
    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    def_line = lines[line_idx]
    m = re.match(r"^(\s*)(async\s+)?def\s+\w+\s*\(", def_line)
    if not m:
        return None
    indent = m.group(1)

    sig_end = line_idx
    sig_text = def_line
    if ")" not in def_line or ":" not in def_line.split(")")[-1]:
        for i in range(line_idx + 1, min(line_idx + 20, len(lines))):
            sig_text += lines[i]
            sig_end = i
            if ")" in lines[i]:
                break

    new_sig = sig_text
    guards = []
    matches = list(re.finditer(r"(\w+)\s*=\s*(\[\]|\{\}|set\(\))", sig_text))
    for match in reversed(matches):
        param = match.group(1)
        mutable = match.group(2)
        new_sig = new_sig[: match.start()] + f"{param}=None" + new_sig[match.end() :]
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
            rest = next_stripped[ds_match.end() :]
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
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=def_line,
        fixed_code=fixed_code,
        explanation="Replaced mutable default argument with None + guard clause",
        source=FixSource.DETERMINISTIC,
        end_line=sig_end + 1 if sig_end > line_idx else None,
    )


def _fix_unused_variable(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
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
        if prev_code.endswith("{") and next_code == "}":
            return None  # sole statement in block -- removal would leave empty block

    # JS/TS: const x = ...; / let x = ...; / var x = ...;
    js_m = re.match(r"^(const|let|var)\s+(\w+)\s*=\s*(.+?);?\s*$", stripped)
    if js_m:
        var_name = js_m.group(2)
        rhs = js_m.group(3).strip()
        # Skip if RHS has side effects (function calls other than safe constructors)
        if re.search(r"\w+\s*\(", rhs) and not re.match(r'^["\'\d\[\{(]', rhs):
            if "require(" not in rhs:  # require() is an import, safe to remove
                return None
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code="",
            explanation=f"Removed unused variable: {var_name}",
            source=FixSource.DETERMINISTIC,
        )

    # Python: x = <value>
    if not re.match(r"^\w+\s*=\s*", stripped):
        return None
    # Don't remove if it's a type annotation (x: int = 5)
    if re.match(r"^\w+\s*:", stripped):
        return None
    # Don't remove if it looks like a destructuring or multi-assignment
    if "," in stripped.split("=")[0]:
        return None
    # Don't remove if the RHS has side effects (function calls, method calls, chained calls)
    rhs = stripped.split("=", 1)[1].strip()
    if re.search(r"\w+\s*\(", rhs) or re.search(r"\.\w+\s*\(", rhs):
        safe_calls = ("True", "False", "None", "[]", "{}", '""', "''", "0", "set()", "dict()", "list()", "tuple()")
        if rhs not in safe_calls and not re.match(r'^["\'\d\[\{(]', rhs):
            return None

    # Handle multi-line assignments (triple-quoted strings, multiline containers)
    # Use AST to find the full span if the assignment continues past this line
    if finding.file.endswith(".py"):
        node = _find_ast_node(content, finding.line, ast.Assign)
        if node and node.end_lineno and node.end_lineno > node.lineno:
            # Multi-line assignment -- need to blank all lines
            all_lines = content.splitlines(keepends=True)
            orig_text = "".join(all_lines[node.lineno - 1 : node.end_lineno])
            return Fix(
                file=finding.file,
                line=finding.line,
                rule=finding.rule,
                original_code=orig_text,
                fixed_code="",
                explanation=f"Removed unused variable: {stripped.split('=')[0].strip()}",
                source=FixSource.DETERMINISTIC,
                end_line=node.end_lineno,
            )

    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code="",
        explanation=f"Removed unused variable: {stripped.split('=')[0].strip()}",
        source=FixSource.DETERMINISTIC,
    )


def _fix_os_system(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace os.system() with subprocess.run()."""  # doji:ignore(os-system)
    m = re.search(r"os\.system\((.+)\)", line)  # doji:ignore(os-system)
    if not m:
        return None
    cmd_arg = m.group(1).strip()
    indent = re.match(r"^(\s*)", line).group(1)
    new_line = f"{indent}subprocess.run(shlex.split({cmd_arg}))\n"
    return Fix(
        file=finding.file,
        line=finding.line,
        rule=finding.rule,
        original_code=line,
        fixed_code=new_line,
        explanation="Replaced os.system() with subprocess.run() (safer, returns exit info)",  # doji:ignore(os-system)
        source=FixSource.DETERMINISTIC,
    )


def _fix_eval_usage(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | list[Fix] | None:
    """Replace eval() with safe alternative: ast.literal_eval (Python), JSON.parse (JS/TS). AST-validated."""
    # AST pre-validation: confirm eval() call exists at this line
    if finding.file.endswith(".py"):
        try:
            tree = ast.parse(content)
            found_eval = False
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and hasattr(node, "lineno")
                    and node.lineno == finding.line
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "eval"
                ):
                    found_eval = True
                    break
            if not found_eval:
                return None  # AST says no eval here -- false positive  # doji:ignore(eval-usage)
        except SyntaxError as e:
            logger.debug("Failed to parse AST for eval check: %s", e)

    m = re.search(r"\beval\s*\((.+)\)", line)
    if not m:
        return None
    eval_arg = m.group(1).strip()

    if finding.file.endswith(".py"):
        replacement = f"ast.literal_eval({eval_arg})"
        new_line = line[: m.start()] + replacement + line[m.end() :]
        # Add inline warning if not already commented
        if "#" not in new_line:
            new_line = new_line.rstrip("\n") + "  # NOTE: only works for literal expressions\n"
        eval_fix = Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced eval() with ast.literal_eval() (safe for literals, rejects arbitrary code)",
            source=FixSource.DETERMINISTIC,
        )
        # Ensure 'import ast' exists -- if not, add it after the last existing import
        if not re.search(r"^\s*import\s+ast\b", content, re.MULTILINE):
            content_lines = content.splitlines(keepends=True)
            # Find last top-level import line
            last_import_idx = -1
            for i, cl in enumerate(content_lines):
                if re.match(r"^(import |from \S+ import )", cl):
                    last_import_idx = i
            if last_import_idx >= 0:
                import_line = content_lines[last_import_idx]
                import_fix = Fix(
                    file=finding.file,
                    line=last_import_idx + 1,
                    rule=finding.rule,
                    original_code=import_line,
                    fixed_code=import_line.rstrip("\n") + "\nimport ast\n",
                    explanation="Added 'import ast' required by ast.literal_eval()",
                    source=FixSource.DETERMINISTIC,
                )
            else:
                # No imports found -- insert after module docstring or at line 1
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
                    file=finding.file,
                    line=insert_idx + 1,
                    rule=finding.rule,
                    original_code=target_line,
                    fixed_code="import ast\n" + target_line,
                    explanation="Added 'import ast' required by ast.literal_eval()",
                    source=FixSource.DETERMINISTIC,
                )
            return [import_fix, eval_fix]
        return eval_fix

    if finding.file.endswith((".js", ".ts", ".jsx", ".tsx")):
        # Strip the eval-idiom parens wrapper: eval("(" + x + ")") -> JSON.parse(x)
        stripped_arg = re.sub(
            r'^(["\'])\(\1\s*\+\s*(.+?)\s*\+\s*(["\'])\)\3$',
            r"\2",
            eval_arg,
        )
        new_line = line[: m.start()] + f"JSON.parse({stripped_arg})" + line[m.end() :]
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced eval() with JSON.parse() (safe -- rejects arbitrary code execution)",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_sql_injection(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Replace string-concatenated SQL with parameterized query."""
    # Only fix Python files
    if not finding.file.endswith(".py"):
        return None
    indent = re.match(r"^(\s*)", line).group(1)

    # Pattern 1: cursor.execute(f"...{var}...")
    m = re.match(r'^(\s*)(\w+)\.execute\(f(["\'])(.+)\3\)', line.rstrip())
    if m:
        call_obj = m.group(2)
        sql_body = m.group(4)
        # Extract interpolated variables
        params = re.findall(r"\{(\w+)\}", sql_body)
        if not params:
            return None
        # Replace {var} with ? placeholders
        clean_sql = re.sub(r"'\{(\w+)\}'", "?", sql_body)
        clean_sql = re.sub(r"\{(\w+)\}", "?", clean_sql)
        param_tuple = ", ".join(params)
        new_line = f'{indent}{call_obj}.execute("{clean_sql}", ({param_tuple},))\n'
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced string interpolation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    # Pattern 2: "SELECT ... WHERE x = " + var -- skip, incomplete fix
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
        new_line = f'{indent}{call_obj}.execute("{sql_body} ?", ({param_var},))\n'  # doji:ignore(sql-injection)
        return Fix(
            file=finding.file,
            line=finding.line,
            rule=finding.rule,
            original_code=line,
            fixed_code=new_line,
            explanation="Replaced string concatenation with parameterized query",
            source=FixSource.DETERMINISTIC,
        )

    return None


def _fix_resource_leak(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
    """Add .close() for unclosed resources (connections, cursors, file handles)."""
    if not finding.file.endswith(".py"):
        return None

    lines = content.splitlines(keepends=True)
    line_idx = finding.line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Extract the variable name and its indentation from the source line: var = something(...)
    src = lines[line_idx]
    m = re.match(r"^(\s*)(\w+)\s*=\s*", src)
    if not m:
        return None
    creation_indent = m.group(1)  # actual indent where the resource is created
    var_name = m.group(2)

    # Find the containing function
    func_indent = None
    for i in range(line_idx - 1, -1, -1):
        fm = re.match(r"^(\s*)(async\s+)?def\s+", lines[i])
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

    # Check if the variable is returned -- if so, can't close it
    for idx, stripped in body_lines:
        if stripped.startswith("return") and var_name in stripped:
            return None

    # Skip functions with multiple returns or try/except (too complex for safe fix)
    return_count = sum(1 for _, s in body_lines if s.startswith("return") or s == "return")
    has_try = any(s.startswith("try:") for _, s in body_lines)
    if return_count > 1 or has_try:
        return None

    # Find the last return in the function body
    last_return_idx = None
    for idx, stripped in body_lines:
        if stripped.startswith("return") or stripped == "return":
            last_return_idx = idx

    if last_return_idx is not None:
        # Insert .close() BEFORE the return -- use the return line's indentation
        return_line = lines[last_return_idx]
        return_indent = re.match(r"^(\s*)", return_line).group(1)
        close_line = f"{return_indent}{var_name}.close()\n"
        new_code = close_line + return_line
        return Fix(
            file=finding.file,
            line=last_return_idx + 1,
            rule=finding.rule,
            original_code=return_line,
            fixed_code=new_code,
            explanation=f"Added {var_name}.close() before return to prevent resource leak",
            source=FixSource.DETERMINISTIC,
        )

    # No return -- add .close() after the last body line
    last_idx = body_lines[-1][0]
    last_line = lines[last_idx]
    close_line = f"{body_indent}{var_name}.close()\n"
    new_code = last_line.rstrip("\n") + "\n" + close_line
    return Fix(
        file=finding.file,
        line=last_idx + 1,
        rule=finding.rule,
        original_code=last_line,
        fixed_code=new_code,
        explanation=f"Added {var_name}.close() to prevent resource leak",
        source=FixSource.DETERMINISTIC,
    )


def _fix_exception_swallowed(line: str, finding: Finding, content: str, ctx: FixContext | None = None) -> Fix | None:
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

    # Replace pass with pass + TODO  # doji:ignore(todo-marker)
    pass_line = lines[pass_idx]
    m = re.match(r"^(\s*)", pass_line)
    pass_indent = m.group(1) if m else ""
    new_pass = f"{pass_indent}pass  # TODO: handle this exception\n"  # doji:ignore(todo-marker)
    return Fix(
        file=finding.file,
        line=pass_idx + 1,
        rule=finding.rule,
        original_code=pass_line,
        fixed_code=new_pass,
        explanation="Added TODO comment to silently swallowed exception",
        source=FixSource.DETERMINISTIC,
    )


# ─── Fixer registry ──────────────────────────────────────────────────


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
