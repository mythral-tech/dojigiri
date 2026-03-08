"""Static analysis engine — regex matching + Python AST parsing.

Runs language-specific regex rules and, for Python files, a full suite of
AST-based semantic checks (scope, taint, CFG, types, null-safety, resources).

Called by: analyzer.py.
Calls into: config.py, languages.py, semantic/checks.py, semantic/core.py,
    semantic/scope.py, semantic/taint.py, semantic/cfg.py, semantic/types.py,
    semantic/nullsafety.py, semantic/resource.py, semantic/smells.py.
Data in → Data out: (filepath, content, language) in → list[Finding] out.
"""

from __future__ import annotations

import ast
import logging
import re

logger = logging.getLogger(__name__)

from .languages import get_rules_for_language
from .types import Category, Finding, Severity, Source

# Security-related categories where string lines should still be scanned
_SECURITY_CATEGORIES = {Category.SECURITY}

# Rules that specifically target comments — never skip on comment lines
_COMMENT_RULES = {"todo-marker"}

# Rules to suppress in test/example files (high FP in non-production code)
_SKIP_IN_TEST_FILES = {"insecure-http", "console-log"}
_SKIP_IN_EXAMPLE_FILES = {"console-log"}

# Path segments identifying test and example files
_TEST_PATH_SEGMENTS = ("/test/", "/tests/", "test_", "_test.", "/spec/", "/specs/")
_EXAMPLE_PATH_SEGMENTS = ("/examples/", "/example/")

# Inline comment patterns per language family
_INLINE_COMMENT_RE = {
    "hash": re.compile(r"""(?<!['"\\])#(?![!])"""),  # Python/Ruby/Bash style
    "slash": re.compile(r"""(?<!['"\\:])//"""),  # C-family style
}

# Single source of truth: language -> comment style ("hash" or "slash")
_SLASH_LANGUAGES = frozenset(
    {
        "javascript",
        "typescript",
        "go",
        "rust",
        "java",
        "c",
        "cpp",
        "csharp",
        "swift",
        "kotlin",
        "pine",
    }
)
_HASH_LANGUAGES = frozenset({"python", "ruby", "bash"})


def _get_comment_style(language: str) -> str | None:
    """Return 'hash' or 'slash' for the language, or None if unknown."""
    if language in _HASH_LANGUAGES:
        return "hash"
    if language in _SLASH_LANGUAGES:
        return "slash"
    return None


# Regex to detect lines that are predominantly string content
# Catches: var = 'javascript:eval(...)' and similar mid-line strings
_STRING_CONTENT_RE = re.compile(
    r"""['"][^'"]*(?:eval|exec)\s*\([^'"]*['"]"""  # eval/exec inside string literal
)

# Inline suppression: doji:ignore or doji:ignore(rule-a, rule-b, ...)
# \b prevents matching "undoji:ignore" etc. Empty parens doji:ignore()
# won't match the inner group ([a-z0-9...]+) so fall through to bare
# doji:ignore behavior (suppress all) — this is intentional.
_DOJI_IGNORE_RE = re.compile(r"\bdoji:ignore(?:\(([a-z0-9_,\s-]+)\))?")


def _parse_line_suppression(line: str, language: str) -> set[str] | bool | None:
    """Parse a doji:ignore directive from a line's trailing comment.

    Returns:
        True — suppress all rules (bare doji:ignore)
        set[str] — suppress only these rule names
        None — no suppression directive found
    """
    style = _get_comment_style(language)
    if style is None:
        return None

    pattern = _INLINE_COMMENT_RE[style]

    # Find the LAST comment marker — rightmost match is most likely the real
    # trailing comment, not one inside a string earlier on the line.
    last_match = None
    for m in pattern.finditer(line):
        last_match = m
    if last_match is None:
        return None

    comment_text = line[last_match.start() :]
    ignore_match = _DOJI_IGNORE_RE.search(comment_text)
    if not ignore_match:
        return None

    # No rule name in parens → suppress all
    rule_text = ignore_match.group(1)
    if rule_text is None:
        return True

    # Comma-separated rule names
    return {r.strip() for r in rule_text.split(",") if r.strip()}


def _is_line_suppressed(lines: list[str], line_no: int, rule: str, language: str) -> bool:
    """Check if a finding on the given line is suppressed by an inline doji:ignore comment.

    Only matches doji:ignore inside actual trailing comments (not string literals).
    line_no is 1-based.
    """
    if line_no < 1 or line_no > len(lines):
        return False

    result = _parse_line_suppression(lines[line_no - 1], language)
    if result is None:
        return False
    if result is True:
        return True
    return rule in result


def _strip_inline_comment(line: str, language: str) -> str:
    """Strip trailing inline comment from a line for non-security checks.

    Conservative: if in doubt, returns the full line (avoids hiding issues).
    Note: intentionally uses the FIRST comment marker match (via .search()),
    unlike _parse_line_suppression which uses the LAST. Stripping from the
    first '#' is the safe direction — it removes more, so more code is hidden
    from the pattern matcher, meaning fewer false positives (not more).
    """
    style = _get_comment_style(language)
    if style is None:
        return line

    m = _INLINE_COMMENT_RE[style].search(line)
    if m:
        return line[: m.start()]
    return line


def run_regex_checks(content: str, filepath: str, language: str, custom_rules=None) -> list[Finding]:
    """Run regex-based pattern matching against file content.

    Args:
        custom_rules: Optional list of compiled custom rules from compile_custom_rules().
            Each tuple: (re.Pattern, Severity, Category, name, message, suggestion, languages).
            Rules with languages=None apply to all languages; otherwise only to listed ones.
    """
    findings = []
    rules = get_rules_for_language(language)

    # Detect test/example files for rule suppression
    fp_lower = filepath.lower().replace("\\", "/")
    is_test_file = any(seg in fp_lower for seg in _TEST_PATH_SEGMENTS)
    is_example_file = any(seg in fp_lower for seg in _EXAMPLE_PATH_SEGMENTS)

    # Rules to skip for this file based on path
    skip_rules: set[str] = set()
    if is_test_file:
        skip_rules |= _SKIP_IN_TEST_FILES
    if is_example_file:
        skip_rules |= _SKIP_IN_EXAMPLE_FILES

    # Collect applicable custom rules (processed separately — match full line)
    applicable_custom_rules = []
    if custom_rules:
        for pattern, severity, category, name, message, suggestion, languages in custom_rules:
            if languages is None or language in languages:
                applicable_custom_rules.append((pattern, severity, category, name, message, suggestion))

    lines = content.splitlines()

    # Language-aware comment prefixes for full-line detection
    comment_prefixes = {"//"} if language in _SLASH_LANGUAGES else {"#"}

    # Block comment state tracking
    in_block_comment = False
    block_comment_delimiter = None  # tracks which delimiter opened the block
    # Block comment delimiters by language
    if language == "python":
        block_open, block_close = '"""', '"""'
        alt_block_open, alt_block_close = "'''", "'''"
    elif language in ("html", "css"):
        block_open, block_close = "<!--", "-->"
        alt_block_open, alt_block_close = "/*", "*/"
    elif language in _SLASH_LANGUAGES:
        block_open, block_close = "/*", "*/"
        alt_block_open, alt_block_close = None, None
    else:
        block_open, block_close = None, None
        alt_block_open, alt_block_close = None, None

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track block comments (/* */ style and """ """ style)
        if block_open and not in_block_comment:
            # For Python: only treat """ as block comment start if at line start
            # (docstring position, not mid-line string assignment)
            # For other languages: any /* is a comment
            block_start_match = False
            if language == "python":
                # Only treat leading triple-quote as docstring open if the
                # line is purely a docstring line.  A closing triple-quote
                # at line start (e.g. '""")  # comment') is NOT an opener —
                # it ends a multiline string from a previous line.
                if stripped.startswith(block_open):
                    after_open = stripped[len(block_open):]
                    # If the very next char is ) , ] or whitespace-then-), it's a close
                    if not after_open or after_open[0] not in ")],;":
                        block_start_match = True
            else:
                block_start_match = block_open in stripped

            if block_start_match:
                # Check if block opens and closes on same line
                idx = stripped.index(block_open)
                rest = stripped[idx + len(block_open) :]
                if block_close not in rest:  # type: ignore[operator]  # block_close is non-None here
                    in_block_comment = True
                    block_comment_delimiter = block_close
                    continue
            elif alt_block_open:
                # For Python ''' - same logic
                alt_start_match = False
                if language == "python":
                    if stripped.startswith(alt_block_open):
                        after_open = stripped[len(alt_block_open):]
                        if not after_open or after_open[0] not in ")],;":
                            alt_start_match = True
                else:
                    alt_start_match = alt_block_open in stripped

                if alt_start_match:
                    idx = stripped.index(alt_block_open)
                    rest = stripped[idx + len(alt_block_open) :]
                    if alt_block_close not in rest:  # type: ignore[operator]  # alt_block_close is non-None here
                        in_block_comment = True
                        block_comment_delimiter = alt_block_close
                        continue
        elif in_block_comment:
            # Only close on the delimiter that opened the block
            if block_comment_delimiter and block_comment_delimiter in stripped:
                in_block_comment = False
                block_comment_delimiter = None
            continue  # Skip lines inside block comments entirely

        is_comment = any(stripped.startswith(p) for p in comment_prefixes)
        # Skip lines that are purely string content (inside quotes)
        is_string_line = (
            (stripped.startswith('"') or stripped.startswith("'"))
            and not stripped.startswith('"""')
            and not stripped.startswith("'''")
        )

        # Inline suppression: parse once per line, reuse for all rule checks.
        # Lazy — only computed on first rule match (most lines have zero matches).
        line_suppression = None  # sentinel; computed on demand
        line_suppression_parsed = False

        def _line_is_suppressed(rule: str) -> bool:
            nonlocal line_suppression, line_suppression_parsed  # doji:ignore(possibly-uninitialized)
            if not line_suppression_parsed:
                line_suppression = _parse_line_suppression(line, language)
                line_suppression_parsed = True
            if line_suppression is None:
                return False
            if line_suppression is True:
                return True
            return rule in line_suppression

        for pattern, severity, category, rule_name, message, suggestion in rules:
            # Comment lines: only run comment-targeting rules
            if is_comment and rule_name not in _COMMENT_RULES:
                continue

            # Skip rules suppressed for test/example files
            if rule_name in skip_rules:
                continue

            # String-only lines: skip non-security patterns (secrets DO live in strings)
            if is_string_line and category not in _SECURITY_CATEGORIES:
                continue

            # For eval-usage/exec-usage: also check if the match is inside a string
            # literal mid-line (e.g. var = 'javascript:eval(...)' )
            if rule_name in ("eval-usage", "exec-usage") and _STRING_CONTENT_RE.search(stripped):
                continue

            # For non-security rules, strip inline comments before matching
            if category not in _SECURITY_CATEGORIES and rule_name not in _COMMENT_RULES:
                check_line = _strip_inline_comment(line, language)
            else:
                check_line = line

            if pattern.search(check_line):
                # yaml-unsafe: suppress if SafeLoader appears within ±3 lines
                if rule_name == "yaml-unsafe":
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 3)
                    context = "\n".join(lines[context_start:context_end])
                    if "SafeLoader" in context or "safe_load" in context:
                        continue

                # Inline suppression: doji:ignore or doji:ignore(rule-name)
                if _line_is_suppressed(rule_name):
                    continue

                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        severity=severity,
                        category=category,
                        source=Source.STATIC,
                        rule=rule_name,
                        message=message,
                        suggestion=suggestion,
                        snippet=stripped[:120],
                    )
                )

        # Custom rules: match against the full line (no comment stripping)
        for pattern, severity, category, rule_name, message, suggestion in applicable_custom_rules:
            if pattern.search(line):
                if _line_is_suppressed(rule_name):
                    continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        severity=severity,
                        category=category,
                        source=Source.STATIC,
                        rule=rule_name,
                        message=message,
                        suggestion=suggestion,
                        snippet=stripped[:120],
                    )
                )
    return findings


def run_python_ast_checks(content: str, filepath: str) -> list[Finding]:
    """Run Python-specific AST analysis for structural issues.

    Refactored to reduce complexity by delegating to focused helper functions.
    """
    findings = []
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError as e:
        findings.append(
            Finding(
                file=filepath,
                line=e.lineno or 1,
                severity=Severity.CRITICAL,
                category=Category.BUG,
                source=Source.AST,
                rule="syntax-error",
                message=f"Syntax error: {e.msg}",
                suggestion="Fix the syntax error before other checks can run",
                snippet=e.text.strip()[:120] if e.text else None,
            )
        )
        return findings

    # Run focused checks
    _check_imports(tree, filepath, findings, content)
    _check_functions(tree, filepath, findings)
    _check_exception_handling(tree, filepath, findings, content)
    _check_shadowed_builtins(tree, filepath, findings)
    _check_type_comparisons(tree, filepath, findings)
    _check_global_usage(tree, filepath, findings)
    _check_mutable_defaults(tree, filepath, findings)
    _check_shadowed_builtin_params(tree, filepath, findings)
    _check_aliased_dangerous_calls(tree, filepath, findings)
    _check_multiline_shell_true(tree, filepath, findings)
    _check_getattr_dangerous(tree, filepath, findings)
    _check_async_shell(tree, filepath, findings)
    _check_sql_fstring(tree, filepath, findings)
    _check_hardcoded_secret_defaults(tree, filepath, findings)

    return findings


def _check_imports(tree: ast.AST, filepath: str, findings: list[Finding], content: str = ""):
    """Check for unused imports.

    Skips:
    - `from __future__ import ...` (directives, not symbol imports)
    - `import X as X` / `from Y import X as X` (explicit re-export pattern, PEP 484)
    - Imports inside `if TYPE_CHECKING:` blocks
    - All imports in `__init__.py` files (public API re-exports)
    - Imports with `# noqa` or `# type:` comments on the same line
    """
    import os

    # __init__.py files: all imports are typically public API re-exports
    if os.path.basename(filepath) == "__init__.py":
        return

    source_lines = content.splitlines() if content else []

    imported_names = {}  # name -> line number
    re_exported_names = set()  # names explicitly re-exported via `as X` identity alias
    used_names = set()

    # Detect TYPE_CHECKING-guarded import lines
    type_checking_lines = _find_type_checking_lines(tree)

    def _import_has_noqa(node: ast.AST) -> bool:
        """Check if any line of this import node has a # noqa or # type: comment."""
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start) or start
        for ln in range(start, end + 1):
            if 0 < ln <= len(source_lines):
                line_text = source_lines[ln - 1]
                if "# noqa" in line_text or "# type:" in line_text:
                    return True
        return False

    for node in ast.walk(tree):
        # Track imports
        if isinstance(node, ast.Import):
            # Skip imports with # noqa or # type: comments
            if _import_has_noqa(node):
                continue
            for alias in node.names:
                # Explicit re-export: `import X as X`
                if alias.asname and alias.asname == alias.name:
                    re_exported_names.add(alias.name)
                    continue
                name = alias.asname or alias.name
                imported_names[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            # Skip __future__ imports entirely (directives, not symbols)
            if node.module == "__future__":
                continue
            # Skip TYPE_CHECKING-guarded imports
            if node.lineno in type_checking_lines:
                continue
            # Skip imports with # noqa or # type: comments
            if _import_has_noqa(node):
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                # Explicit re-export: `from X import Y as Y`
                if alias.asname and alias.asname == alias.name:
                    re_exported_names.add(alias.name)
                    continue
                name = alias.asname or alias.name
                imported_names[name] = node.lineno
        # Track name usage
        elif isinstance(node, ast.Name):
            used_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Track the root of attribute chains (e.g., 'os' in 'os.path.join')
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value  # type: ignore[assignment]  # narrowing through loop
            if isinstance(root, ast.Name):
                used_names.add(root.id)

    # Report unused imports
    for name, lineno in imported_names.items():
        if name.startswith("_"):  # Skip intentional underscore names
            continue
        # Skip TYPE_CHECKING-guarded imports (for `import X` style too)
        if lineno in type_checking_lines:
            continue
        # For dotted imports (`import email.message`), check if root is used
        # via attribute access (e.g., `email.message.Message()` uses `email`)
        is_used = name in used_names
        if not is_used and "." in name:
            root_name = name.split(".")[0]
            is_used = root_name in used_names
        if not is_used:
            findings.append(
                Finding(
                    file=filepath,
                    line=lineno,
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    source=Source.AST,
                    rule="unused-import",
                    message=f"Import '{name}' is never used",
                    suggestion=f"Remove unused import '{name}'",
                )
            )


def _find_type_checking_lines(tree: ast.AST) -> set[int]:
    """Find line numbers of imports inside `if TYPE_CHECKING:` blocks."""
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            # Check for `if TYPE_CHECKING:` or `if typing.TYPE_CHECKING:`
            test = node.test
            is_type_checking = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            )
            if is_type_checking:
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        lines.add(child.lineno)
    return lines


def _check_functions(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check all functions for common issues."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function(node, filepath, findings)  # type: ignore[arg-type]  # FunctionDef | AsyncFunctionDef both valid


def _is_empty_except(node: ast.ExceptHandler, terminal_type: type) -> bool:
    """Check if an except handler body is effectively empty.

    Matches bodies that are just ``[Pass]``, ``[Continue]``, or
    ``[Expr(string_constant), Pass]`` / ``[Expr(string_constant), Continue]``
    (a string "comment" followed by the terminal statement).
    """
    body = node.body
    if len(body) == 1 and isinstance(body[0], terminal_type):
        return True
    if len(body) == 2 and isinstance(body[1], terminal_type):
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(
            first.value, ast.Constant
        ):
            return True
    return False


def _has_explanatory_comment(
    node: ast.ExceptHandler, source_lines: list[str]
) -> bool:
    """Check if an except handler body has an explanatory comment.

    Returns True when the except block contains:
    - A comment on the ``pass`` / ``continue`` line (e.g. ``pass  # intentional``)
    - A comment on a line between the except clause and the pass/continue
    - A string-expression "comment" (``"reason string"``) preceding ``pass``
    """
    # String expression used as a comment (e.g. ``"keep value as string"``)
    if len(node.body) >= 1:
        first = node.body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
        ):
            return True

    # Check source lines for inline ``#`` comments in the except body range
    if source_lines:
        body_node = node.body[-1]  # pass or continue
        # Lines from except clause through the pass/continue (1-indexed → 0-indexed)
        start = node.lineno - 1
        end = body_node.lineno  # inclusive, already 1-indexed so slice to end
        for line in source_lines[start:end]:
            stripped = line.lstrip()
            # Pure comment line
            if stripped.startswith("#"):
                return True
            # Inline comment after code (e.g. ``pass  # reason``)
            if "#" in stripped:
                # Rough but sufficient: split on # outside strings
                code_part, _, comment_part = stripped.partition("#")
                if comment_part.strip():
                    return True
    return False


def _check_exception_handling(
    tree: ast.AST, filepath: str, findings: list[Finding], content: str = ""
):
    """Check for swallowed exceptions (except: pass/continue).

    When the except body contains an explanatory comment (inline ``#`` comment
    or a string-expression "docstring"), the finding is downgraded to INFO
    severity instead of WARNING — the developer explicitly acknowledged the
    swallowed exception.
    """
    source_lines = content.splitlines() if content else []

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            is_empty_pass = _is_empty_except(node, ast.Pass)
            is_empty_continue = (not is_empty_pass) and _is_empty_except(node, ast.Continue)

            if is_empty_pass:
                has_comment = _has_explanatory_comment(node, source_lines)
                if has_comment:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.INFO,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="exception-swallowed",
                            message="Exception caught and silently ignored (except: pass) — comment explains intent",
                            suggestion="Acknowledged via comment; consider logging for observability",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="exception-swallowed",
                            message="Exception caught and silently ignored (except: pass)",
                            suggestion="Log the exception or handle it explicitly",
                        )
                    )
            elif is_empty_continue:
                has_comment = _has_explanatory_comment(node, source_lines)
                if has_comment:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.INFO,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="exception-swallowed-continue",
                            message="Exception caught and silently continued (except: continue) — comment explains intent",
                            suggestion="Acknowledged via comment; consider logging for observability",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="exception-swallowed-continue",
                            message="Exception caught and silently continued (except: continue)",
                            suggestion="Log the exception before continuing, or handle it explicitly",
                        )
                    )


# Builtins that should not be shadowed by variables or parameters
_SHADOW_BUILTINS = {
    "list",
    "dict",
    "type",
    "str",
    "int",
    "float",
    "set",
    "tuple",
    "len",
    "range",
    "open",
    "input",
    "print",
    "sum",
    "min",
    "max",
    "id",
    "sorted",
    "next",
    "map",
    "filter",
    "zip",
    "hash",
    "iter",
    "bool",
    "bytes",
    "complex",
    "frozenset",
    "object",
    "super",
}


def _check_shadowed_builtins(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for variables that shadow Python builtins."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _SHADOW_BUILTINS:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="shadowed-builtin",
                            message=f"Assignment shadows builtin '{target.id}'",
                            suggestion=f"Rename variable to avoid shadowing builtin '{target.id}'",
                        )
                    )


def _check_type_comparisons(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for type() == comparison instead of isinstance()."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    if (
                        isinstance(node.left, ast.Call)
                        and isinstance(node.left.func, ast.Name)
                        and node.left.func.id == "type"
                    ):
                        findings.append(
                            Finding(
                                file=filepath,
                                line=node.lineno,
                                severity=Severity.WARNING,
                                category=Category.BUG,
                                source=Source.AST,
                                rule="type-comparison",
                                message="Use isinstance() instead of type() comparison",
                                suggestion="Replace type(x) == Y with isinstance(x, Y)",
                            )
                        )
                        break


def _check_global_usage(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for global keyword usage."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Global):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=stmt.lineno,
                            severity=Severity.INFO,
                            category=Category.STYLE,
                            source=Source.AST,
                            rule="global-keyword",
                            message=f"'global' keyword used for: {', '.join(stmt.names)}",
                            suggestion="Consider passing values as arguments or using a class",
                        )
                    )


def _check_mutable_defaults(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for mutable default arguments via AST (handles multiline defs)."""
    _MUTABLE_TYPES = (ast.List, ast.Dict, ast.Set)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            is_mutable = isinstance(default, _MUTABLE_TYPES)
            # Also catch set() call
            if (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id == "set"
                and not default.args
                and not default.keywords
            ):
                is_mutable = True
            if is_mutable:
                findings.append(
                    Finding(
                        file=filepath,
                        line=node.lineno,
                        severity=Severity.WARNING,
                        category=Category.BUG,
                        source=Source.AST,
                        rule="mutable-default",
                        message=f"Mutable default argument in '{node.name}' — shared across all calls",
                        suggestion="Use None as default and create inside function body",
                    )
                )
                break  # One report per function is enough


def _check_shadowed_builtin_params(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for function parameters that shadow Python builtins."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        all_args = node.args.args + node.args.posonlyargs + node.args.kwonlyargs
        for arg in all_args:
            if arg.arg in ("self", "cls"):
                continue
            if arg.arg in _SHADOW_BUILTINS:
                findings.append(
                    Finding(
                        file=filepath,
                        line=arg.lineno if hasattr(arg, "lineno") else node.lineno,
                        severity=Severity.WARNING,
                        category=Category.BUG,
                        source=Source.AST,
                        rule="shadowed-builtin-param",
                        message=f"Parameter '{arg.arg}' in '{node.name}' shadows builtin",
                        suggestion=f"Rename parameter to avoid shadowing builtin '{arg.arg}'",
                    )
                )


# ── Import-alias-aware dangerous call detection ─────────────────────────
# Maps canonical module.function to (rule, severity, category, message, suggestion).
# When code does `import pickle as pkl`, we resolve pkl.loads → pickle.loads.
_DANGEROUS_CALLS: dict[str, tuple[str, Severity, Category, str, str]] = {
    "os.system": ("os-system", Severity.WARNING, Category.SECURITY,
                  "os.system() is vulnerable to shell injection",
                  "Use subprocess.run() with a list of arguments"),
    "os.popen": ("os-popen", Severity.WARNING, Category.SECURITY,
                 "os.popen() starts a shell process — vulnerable to injection",
                 "Use subprocess.run() with a list of arguments instead"),
    "pickle.loads": ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                     "pickle.loads() can execute arbitrary code during deserialization",
                     "Use json, msgpack, or a safe serialization format instead"),
    "pickle.load": ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                    "pickle.load() can execute arbitrary code during deserialization",
                    "Use json, msgpack, or a safe serialization format instead"),
    "yaml.load": ("yaml-unsafe", Severity.CRITICAL, Category.SECURITY,
                  "yaml.load() without SafeLoader can execute arbitrary code",
                  "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"),
    "marshal.loads": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                      "marshal.loads() can execute arbitrary code during deserialization",
                      "Use json or msgpack for untrusted data"),
    "marshal.load": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                     "marshal.load() can execute arbitrary code during deserialization",
                     "Use json or msgpack for untrusted data"),
    "shelve.open": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                    "shelve.open() is pickle-backed — can execute arbitrary code",
                    "Use json or msgpack for untrusted data"),
    "hashlib.md5": ("weak-hash", Severity.WARNING, Category.SECURITY,
                    "MD5 is a cryptographically weak hash algorithm",
                    "Use hashlib.sha256() or stronger for security-sensitive hashing"),
    "hashlib.sha1": ("weak-hash", Severity.WARNING, Category.SECURITY,
                     "SHA1 is a cryptographically weak hash algorithm",
                     "Use hashlib.sha256() or stronger for security-sensitive hashing"),
    "random.choice": ("weak-random", Severity.INFO, Category.SECURITY,
                      "random module is not cryptographically secure",
                      "Use secrets module for security-sensitive random values"),
    "random.randint": ("weak-random", Severity.INFO, Category.SECURITY,
                       "random module is not cryptographically secure",
                       "Use secrets module for security-sensitive random values"),
    "random.random": ("weak-random", Severity.INFO, Category.SECURITY,
                      "random module is not cryptographically secure",
                      "Use secrets module for security-sensitive random values"),
    "random.uniform": ("weak-random", Severity.INFO, Category.SECURITY,
                       "random module is not cryptographically secure",
                       "Use secrets module for security-sensitive random values"),
    "random.randrange": ("weak-random", Severity.INFO, Category.SECURITY,
                         "random module is not cryptographically secure",
                         "Use secrets module for security-sensitive random values"),
    "random.shuffle": ("weak-random", Severity.INFO, Category.SECURITY,
                       "random module is not cryptographically secure",
                       "Use secrets module for security-sensitive random values"),
    "random.sample": ("weak-random", Severity.INFO, Category.SECURITY,
                      "random module is not cryptographically secure",
                      "Use secrets module for security-sensitive random values"),
    "tempfile.mktemp": ("insecure-tempfile", Severity.WARNING, Category.SECURITY,
                        "mktemp is vulnerable to race conditions (TOCTOU)",
                        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()"),
    # XML parsers — XXE risk through aliases
    "xml.etree.ElementTree.parse": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                                     "XML parsing — ensure external entities are disabled (XXE)",
                                     "Use defusedxml or disable DTDs/external entities"),
    "xml.etree.ElementTree.fromstring": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                                          "XML parsing — ensure external entities are disabled (XXE)",
                                          "Use defusedxml or disable DTDs/external entities"),
    "xml.etree.ElementTree.iterparse": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                                         "XML parsing — ensure external entities are disabled (XXE)",
                                         "Use defusedxml or disable DTDs/external entities"),
    "xml.dom.minidom.parse": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                               "XML parsing — ensure external entities are disabled (XXE)",
                               "Use defusedxml or disable DTDs/external entities"),
    "xml.dom.minidom.parseString": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                                     "XML parsing — ensure external entities are disabled (XXE)",
                                     "Use defusedxml or disable DTDs/external entities"),
    "xml.sax.parse": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                       "XML parsing — ensure external entities are disabled (XXE)",
                       "Use defusedxml or disable DTDs/external entities"),
    "xml.sax.parseString": ("xxe-risk", Severity.WARNING, Category.SECURITY,
                             "XML parsing — ensure external entities are disabled (XXE)",
                             "Use defusedxml or disable DTDs/external entities"),
}


def _check_aliased_dangerous_calls(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect dangerous function calls through import aliases.

    Builds a map of alias → canonical module name from import statements,
    then walks all Call nodes to check if any resolve to a known dangerous call.
    Only fires for calls using non-canonical names (aliases), since the regex
    engine already catches canonical names like pickle.loads().
    """
    # Build alias → canonical module map
    alias_map: dict[str, str] = {}  # e.g. {"pkl": "pickle", "sp": "subprocess"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname != alias.name:
                    # import pickle as pkl → pkl → pickle
                    alias_map[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    if alias.asname and alias.asname != alias.name:
                        # from xml.dom import minidom as mdom → mdom → xml.dom.minidom
                        alias_map[alias.asname] = f"{node.module}.{alias.name}"

    if not alias_map:
        return  # No aliases, regex covers everything

    # Walk call nodes looking for aliased dangerous calls
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        # Case 1: alias.method() — e.g. pkl.loads()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            alias = func.value.id
            attr = func.attr
            if alias in alias_map:
                canonical = f"{alias_map[alias]}.{attr}"
                if canonical in _DANGEROUS_CALLS:
                    rule, sev, cat, msg, sug = _DANGEROUS_CALLS[canonical]
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        severity=sev, category=cat, source=Source.AST,
                        rule=rule,
                        message=f"{msg} (via alias '{alias}')",
                        suggestion=sug,
                    ))

        # Case 2: bare alias() — e.g. xml_parse() from "from X import parse as xml_parse"
        elif isinstance(func, ast.Name):
            name = func.id
            if name in alias_map:
                canonical = alias_map[name]
                if canonical in _DANGEROUS_CALLS:
                    rule, sev, cat, msg, sug = _DANGEROUS_CALLS[canonical]
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        severity=sev, category=cat, source=Source.AST,
                        rule=rule,
                        message=f"{msg} (via alias '{name}')",
                        suggestion=sug,
                    ))


# ── Multiline shell=True detection (AST) ────────────────────────────────
# subprocess.run/Popen/call/check_output with shell=True on different lines.
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})


def _check_multiline_shell_true(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect subprocess calls with shell=True across multiple lines.

    The regex engine catches shell=True on the same line as the function call.
    This AST check catches it when shell=True is a keyword arg on a different line.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Match subprocess.run(..., shell=True, ...)
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            continue
        if func.value.id != "subprocess" or func.attr not in _SUBPROCESS_FUNCS:
            continue

        # Check for shell=True keyword
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append(Finding(
                    file=filepath, line=node.lineno,
                    severity=Severity.WARNING, category=Category.SECURITY,
                    source=Source.AST, rule="shell-true",
                    message=f"subprocess.{func.attr}() with shell=True (multiline)",
                    suggestion="Pass command as a list without shell=True",
                ))
                break


# ── getattr-based dangerous call detection (AST) ────────────────────────
# Catches getattr(os, "system"), getattr(pickle, "loads"), etc.
_GETATTR_DANGEROUS: dict[tuple[str, str], tuple[str, Severity, Category, str, str]] = {
    ("os", "system"): ("os-system", Severity.WARNING, Category.SECURITY,
                       "os.system() via getattr — shell injection risk",
                       "Use subprocess.run() with a list of arguments"),
    ("os", "popen"): ("os-popen", Severity.WARNING, Category.SECURITY,
                      "os.popen() via getattr — shell injection risk",
                      "Use subprocess.run() with a list of arguments"),
    ("pickle", "loads"): ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                          "pickle.loads() via getattr — arbitrary code execution",
                          "Use json or msgpack instead"),
    ("pickle", "load"): ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                         "pickle.load() via getattr — arbitrary code execution",
                         "Use json or msgpack instead"),
    ("subprocess", "Popen"): ("subprocess-audit", Severity.INFO, Category.SECURITY,
                              "subprocess.Popen via getattr — verify arguments",
                              "Ensure command is not user-controlled"),
}


def _check_getattr_dangerous(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect getattr(module, 'dangerous_func') patterns."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "getattr"):
            continue
        if len(node.args) < 2:
            continue

        # getattr(module_name, "func_name")
        mod_arg = node.args[0]
        attr_arg = node.args[1]

        if isinstance(mod_arg, ast.Name) and isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
            key = (mod_arg.id, attr_arg.value)
            if key in _GETATTR_DANGEROUS:
                rule, sev, cat, msg, sug = _GETATTR_DANGEROUS[key]
                findings.append(Finding(
                    file=filepath, line=node.lineno,
                    severity=sev, category=cat, source=Source.AST,
                    rule=rule,
                    message=msg,
                    suggestion=sug,
                ))


# ── asyncio.create_subprocess_shell detection (AST) ─────────────────────

def _check_async_shell(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect asyncio.create_subprocess_shell — equivalent to shell=True."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # asyncio.create_subprocess_shell(...)
        if isinstance(func, ast.Attribute) and func.attr == "create_subprocess_shell":
            if isinstance(func.value, ast.Name) and func.value.id == "asyncio":
                findings.append(Finding(
                    file=filepath, line=node.lineno,
                    severity=Severity.WARNING, category=Category.SECURITY,
                    source=Source.AST, rule="shell-true",
                    message="asyncio.create_subprocess_shell() runs command through shell",
                    suggestion="Use asyncio.create_subprocess_exec() with argument list instead",
                ))
        # Also catch: await asyncio.create_subprocess_shell in Await nodes
        elif isinstance(func, ast.Attribute) and func.attr == "create_subprocess_shell":
            # Covers any obj.create_subprocess_shell
            findings.append(Finding(
                file=filepath, line=node.lineno,
                severity=Severity.WARNING, category=Category.SECURITY,
                source=Source.AST, rule="shell-true",
                message="create_subprocess_shell() runs command through shell",
                suggestion="Use create_subprocess_exec() with argument list instead",
            ))


# ── SQL injection via f-string in execute/executemany (AST) ──────────────
# Catches multiline cases where execute(\n  f"SQL...\n) spans lines.
_SQL_EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})
_SQL_KEYWORDS_RE = re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b")


def _check_sql_fstring(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect SQL injection via f-strings passed to execute/executemany.

    Catches the multiline pattern:
        conn.execute(
            f"INSERT INTO {table} ..."
        )
    where the f-string is on a different line than execute(.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match *.execute(...) / *.executemany(...)
        if not (isinstance(func, ast.Attribute) and func.attr in _SQL_EXECUTE_METHODS):
            continue
        if not node.args:
            continue

        first_arg = node.args[0]
        # Check if first arg is a JoinedStr (f-string)
        if isinstance(first_arg, ast.JoinedStr):
            # Check if the f-string contains SQL keywords
            static_parts = []
            has_interpolation = False
            for val in first_arg.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    static_parts.append(val.value)
                elif isinstance(val, ast.FormattedValue):
                    has_interpolation = True
            if has_interpolation and _SQL_KEYWORDS_RE.search("".join(static_parts)):
                findings.append(Finding(
                    file=filepath, line=first_arg.lineno,
                    severity=Severity.CRITICAL, category=Category.SECURITY,
                    source=Source.AST, rule="sql-injection",
                    message="SQL injection — f-string with interpolation in execute()",
                    suggestion="Use parameterized queries with ? placeholders",
                ))


# ── Hardcoded secret defaults in function params (AST) ────────────────
# Catches multiline function signatures where regex can't span lines.
_SECRET_PARAM_NAMES = re.compile(
    r"(?i)^(?:password|passwd|secret|secret_key|api_key|token|auth_token|jwt_secret|"
    r"signing_key|encryption_key|private_key|client_secret)$"
)
_SECRET_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:demo|example|placeholder|test|sample|changeme|change[_-]me|your[_-]?|xxx|"
    r"TODO|INSERT|REPLACE|None|)$"
)


def _check_hardcoded_secret_defaults(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Detect hardcoded secrets as default values in function parameters and class fields."""
    for node in ast.walk(tree):
        # Case 1: Function/method parameters with secret defaults
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            defaults = args.defaults
            num_args = len(args.args)
            num_defaults = len(defaults)
            for i, default in enumerate(defaults):
                if not isinstance(default, ast.Constant) or not isinstance(default.value, str):
                    continue
                val = default.value
                if len(val) < 6 or _SECRET_PLACEHOLDER_RE.match(val):
                    continue
                arg_index = num_args - num_defaults + i
                arg_name = args.args[arg_index].arg
                if _SECRET_PARAM_NAMES.match(arg_name):
                    findings.append(Finding(
                        file=filepath, line=default.lineno,
                        severity=Severity.WARNING, category=Category.SECURITY,
                        source=Source.AST, rule="hardcoded-password-default",
                        message=f"Hardcoded secret default for parameter '{arg_name}' (multiline signature)",
                        suggestion="Use None as default and require explicit argument or env var",
                    ))

        # Case 2: Annotated assignments (dataclass fields, class vars): api_key: str = "secret"
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value
                if len(val) < 6 or _SECRET_PLACEHOLDER_RE.match(val):
                    continue
                field_name = node.target.id
                if _SECRET_PARAM_NAMES.match(field_name):
                    findings.append(Finding(
                        file=filepath, line=node.value.lineno,
                        severity=Severity.WARNING, category=Category.SECURITY,
                        source=Source.AST, rule="hardcoded-password-default",
                        message=f"Hardcoded secret in annotated field '{field_name}'",
                        suggestion="Use environment variables or a secrets manager",
                    ))


def _count_branches(node: ast.AST) -> int:
    """Count branch nodes without descending into nested function definitions."""
    count = 0
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # Don't count branches inside nested functions
        if isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.ExceptHandler, ast.With)):
            count += 1
        count += _count_branches(child)
    return count


def _check_function(node: ast.FunctionDef, filepath: str, findings: list[Finding]):
    """Check a function for common issues."""
    # Unreachable code after return/raise/break/continue
    for i, stmt in enumerate(node.body):
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            if i < len(node.body) - 1:
                next_stmt = node.body[i + 1]
                findings.append(
                    Finding(
                        file=filepath,
                        line=next_stmt.lineno,
                        severity=Severity.WARNING,
                        category=Category.DEAD_CODE,
                        source=Source.AST,
                        rule="unreachable-code",
                        message="Unreachable code after return/raise/break/continue",
                        suggestion="Remove dead code or restructure control flow",
                    )
                )
                break  # Only report the first unreachable block

    # Overly complex functions (too many branches)
    # Use _count_branches to avoid counting nested function bodies
    branch_count = _count_branches(node)
    if branch_count > 15:
        findings.append(
            Finding(
                file=filepath,
                line=node.lineno,
                severity=Severity.INFO,
                category=Category.STYLE,
                rule="high-complexity",
                source=Source.AST,
                message=f"Function '{node.name}' has high cyclomatic complexity ({branch_count} branches)",
                suggestion="Consider breaking into smaller functions",
            )
        )

    # Too many arguments
    total_args = len(node.args.args) + len(node.args.posonlyargs) + len(node.args.kwonlyargs)
    # Don't count 'self' and 'cls'
    if node.args.args and node.args.args[0].arg in ("self", "cls"):
        total_args -= 1
    if total_args > 7:
        findings.append(
            Finding(
                file=filepath,
                line=node.lineno,
                severity=Severity.INFO,
                category=Category.STYLE,
                source=Source.AST,
                rule="too-many-args",
                message=f"Function '{node.name}' has {total_args} arguments",
                suggestion="Consider using a dataclass or config object to group parameters",
            )
        )


def analyze_file_static(filepath: str, content: str, language: str, custom_rules=None) -> StaticAnalysisResult:  # noqa: F821
    """Run all static checks (regex + tree-sitter AST + Python AST fallback + semantic).

    Always returns a StaticAnalysisResult with findings, semantics, and type_map.
    Callers that only need findings can use result.findings.
    """
    import time as _time

    from .types import StaticAnalysisResult

    _scan_start = _time.perf_counter()

    findings = run_regex_checks(content, filepath, language, custom_rules=custom_rules)

    # AST checks: tree-sitter for all languages, Python ast as supplement/fallback
    from .semantic.checks import run_tree_sitter_checks

    ts_findings = run_tree_sitter_checks(content, filepath, language)
    if ts_findings:
        findings.extend(ts_findings)

    if language == "python":
        # Always run Python AST checks — they cover checks tree-sitter doesn't
        # (type-comparison, global-keyword, shadowed-builtin assignments, etc.)
        # Dedup below merges overlapping findings by (file, line, rule)
        findings.extend(run_python_ast_checks(content, filepath))

    # v0.8.0: Semantic analysis (scope, taint, smells)
    from .semantic.core import extract_semantics
    from .semantic.lang_config import get_config

    _file_type_map = None  # captured for return_semantics
    semantics = extract_semantics(content, filepath, language)
    if semantics:
        from .semantic.scope import (
            check_uninitialized_variables,
            check_unused_variables,
            check_variable_shadowing,
        )
        from .semantic.smells import check_feature_envy, check_god_class, check_long_method
        from .semantic.taint import analyze_taint

        findings.extend(check_unused_variables(semantics, filepath))
        findings.extend(check_variable_shadowing(semantics, filepath))
        findings.extend(check_uninitialized_variables(semantics, filepath))

        config = get_config(language)
        if config:
            source_bytes = content.encode("utf-8")

            # v0.9.0: Build CFG and use path-sensitive analysis when available
            from .semantic.cfg import build_cfg

            cfgs = build_cfg(semantics, source_bytes, config)
            if cfgs:
                from .semantic.resource import check_resource_leaks
                from .semantic.taint import analyze_taint_pathsensitive

                findings.extend(analyze_taint_pathsensitive(semantics, source_bytes, config, filepath, cfgs))
                findings.extend(check_resource_leaks(semantics, source_bytes, config, filepath, cfgs))
            else:
                # Fallback to flow-insensitive taint analysis
                findings.extend(analyze_taint(semantics, source_bytes, config, filepath))

        # v0.10.0: Type inference + null safety
        if config:
            try:
                from .semantic.nullsafety import check_null_safety
                from .semantic.types import infer_types

                _file_type_map = infer_types(semantics, source_bytes, config, cfgs=cfgs if config else None)
                type_map = _file_type_map
                if type_map and type_map.types:
                    findings.extend(
                        check_null_safety(semantics, type_map, config, filepath, cfgs=cfgs if config else None)
                    )
            except (ValueError, OSError, AttributeError) as e:
                logger.debug("Type inference/null safety skipped: %s", e)

        findings.extend(check_god_class(semantics, filepath))
        findings.extend(check_feature_envy(semantics, filepath))
        findings.extend(check_long_method(semantics, filepath))
        # Note: semantic clone detection is handled project-wide in analyzer.py
        # to avoid duplicate intra-file findings.

    # v0.11.0: AST-based taint analysis with variable indirection tracking
    # Catches patterns tree-sitter taint misses: f-string interpolation,
    # multi-hop variable chains, function parameter taint.
    # Only runs on Python files (uses built-in ast module).
    if language == "python":
        try:
            from .taint import analyze_taint_ast

            ast_taint_findings = analyze_taint_ast(filepath, content)
            # Deduplicate against existing taint-flow findings (same file + line + rule)
            existing_taint_keys = {
                (f.file, f.line, f.rule) for f in findings if f.rule == "taint-flow"
            }
            for tf in ast_taint_findings:
                if (tf.file, tf.line, tf.rule) not in existing_taint_keys:
                    findings.append(tf)
        except Exception as e:
            logger.debug("AST taint analysis skipped: %s", e)

    # Inline suppression post-filter for AST/semantic findings.
    # Regex findings (Source.STATIC) are already filtered in run_regex_checks,
    # so only check AST/semantic findings here. Cache parse per-line.
    lines = content.splitlines()
    _suppression_cache: dict[int, set[str] | bool | None] = {}

    def _check_suppressed(line_no: int, rule: str) -> bool:
        if line_no not in _suppression_cache:
            if line_no < 1 or line_no > len(lines):
                _suppression_cache[line_no] = None
            else:
                _suppression_cache[line_no] = _parse_line_suppression(lines[line_no - 1], language)
        result = _suppression_cache[line_no]
        if result is None:
            return False
        if result is True:
            return True
        return rule in result

    findings = [f for f in findings if f.source == Source.STATIC or not _check_suppressed(f.line, f.rule)]

    # Deduplicate: same file + line + rule
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity (critical first), then line number
    from .types import SEVERITY_ORDER

    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line))

    # Record metrics
    _scan_ms = (_time.perf_counter() - _scan_start) * 1000
    try:
        from .metrics import get_session

        session = get_session()
        if session:
            session.record_file(_scan_ms)
            for f in unique:
                session.record_finding(f.rule, f.severity.value)
    except Exception as e:
        logger.debug("Failed to record metrics: %s", e)

    return StaticAnalysisResult(findings=unique, semantics=semantics, type_map=_file_type_map)
