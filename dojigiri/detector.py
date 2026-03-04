"""Static analysis engine — regex matching + Python AST parsing."""

import ast
import logging
import re

logger = logging.getLogger(__name__)

from .config import Finding, Severity, Category, Source
from .languages import get_rules_for_language

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
    "slash": re.compile(r"""(?<!['"\\:])//"""),       # C-family style
}

# Regex to detect lines that are predominantly string content
# Catches: var = 'javascript:eval(...)' and similar mid-line strings
_STRING_CONTENT_RE = re.compile(
    r"""['"][^'"]*(?:eval|exec)\s*\([^'"]*['"]"""  # eval/exec inside string literal
)


def _strip_inline_comment(line: str, language: str) -> str:
    """Strip trailing inline comment from a line for non-security checks.

    Conservative: if in doubt, returns the full line (avoids hiding issues).
    """
    if language in ("python", "ruby", "bash"):
        m = _INLINE_COMMENT_RE["hash"].search(line)
    elif language in ("javascript", "typescript", "go", "rust", "java",
                      "c", "cpp", "csharp", "swift", "kotlin", "pine"):
        m = _INLINE_COMMENT_RE["slash"].search(line)
    else:
        return line

    if m:
        return line[:m.start()]
    return line


def run_regex_checks(content: str, filepath: str, language: str,
                     custom_rules=None) -> list[Finding]:
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
    comment_prefixes = {"#"}
    if language in ("javascript", "typescript", "go", "rust", "java",
                     "c", "cpp", "csharp", "swift", "kotlin", "pine"):
        comment_prefixes = {"//"}

    # Block comment state tracking
    in_block_comment = False
    # Block comment delimiters by language
    if language == "python":
        block_open, block_close = '"""', '"""'
        alt_block_open, alt_block_close = "'''", "'''"
    elif language in ("html", "css"):
        block_open, block_close = "<!--", "-->"
        alt_block_open, alt_block_close = "/*", "*/"
    elif language in ("javascript", "typescript", "go", "rust", "java",
                      "c", "cpp", "csharp", "swift", "kotlin", "pine", "css"):
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
                block_start_match = stripped.startswith(block_open)
            else:
                block_start_match = block_open in stripped
            
            if block_start_match:
                # Check if block opens and closes on same line
                idx = stripped.index(block_open)
                rest = stripped[idx + len(block_open):]
                if block_close not in rest:  # type: ignore[operator]  # block_close is non-None here
                    in_block_comment = True
                    continue
            elif alt_block_open:
                # For Python ''' - same logic
                alt_start_match = False
                if language == "python":
                    alt_start_match = stripped.startswith(alt_block_open)
                else:
                    alt_start_match = alt_block_open in stripped
                
                if alt_start_match:
                    idx = stripped.index(alt_block_open)
                    rest = stripped[idx + len(alt_block_open):]
                    if alt_block_close not in rest:  # type: ignore[operator]  # alt_block_close is non-None here
                        in_block_comment = True
                        continue
        elif in_block_comment:
            if block_close and block_close in stripped:
                in_block_comment = False
            elif alt_block_close and alt_block_close in stripped:
                in_block_comment = False
            continue  # Skip lines inside block comments entirely

        is_comment = any(stripped.startswith(p) for p in comment_prefixes)
        # Skip lines that are purely string content (inside quotes)
        is_string_line = (
            (stripped.startswith('"') or stripped.startswith("'"))
            and not stripped.startswith('"""') and not stripped.startswith("'''")
        )

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

                findings.append(Finding(
                    file=filepath,
                    line=line_num,
                    severity=severity,
                    category=category,
                    source=Source.STATIC,
                    rule=rule_name,
                    message=message,
                    suggestion=suggestion,
                    snippet=stripped[:120],
                ))

        # Custom rules: match against the full line (no comment stripping)
        for pattern, severity, category, rule_name, message, suggestion in applicable_custom_rules:
            if pattern.search(line):
                findings.append(Finding(
                    file=filepath,
                    line=line_num,
                    severity=severity,
                    category=category,
                    source=Source.STATIC,
                    rule=rule_name,
                    message=message,
                    suggestion=suggestion,
                    snippet=stripped[:120],
                ))
    return findings


def run_python_ast_checks(content: str, filepath: str) -> list[Finding]:
    """Run Python-specific AST analysis for structural issues.
    
    Refactored to reduce complexity by delegating to focused helper functions.
    """
    findings = []
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError as e:
        findings.append(Finding(
            file=filepath,
            line=e.lineno or 1,
            severity=Severity.CRITICAL,
            category=Category.BUG,
            source=Source.AST,
            rule="syntax-error",
            message=f"Syntax error: {e.msg}",
            suggestion="Fix the syntax error before other checks can run",
            snippet=e.text.strip()[:120] if e.text else None,
        ))
        return findings

    # Run focused checks
    _check_imports(tree, filepath, findings)
    _check_functions(tree, filepath, findings)
    _check_exception_handling(tree, filepath, findings)
    _check_shadowed_builtins(tree, filepath, findings)
    _check_type_comparisons(tree, filepath, findings)
    _check_global_usage(tree, filepath, findings)
    _check_mutable_defaults(tree, filepath, findings)
    _check_shadowed_builtin_params(tree, filepath, findings)

    return findings


def _check_imports(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for unused imports.

    Skips:
    - `from __future__ import ...` (directives, not symbol imports)
    - `import X as X` / `from Y import X as X` (explicit re-export pattern, PEP 484)
    - Imports inside `if TYPE_CHECKING:` blocks
    """
    imported_names = {}  # name -> line number
    re_exported_names = set()  # names explicitly re-exported via `as X` identity alias
    used_names = set()

    # Detect TYPE_CHECKING-guarded import lines
    type_checking_lines = _find_type_checking_lines(tree)

    for node in ast.walk(tree):
        # Track imports
        if isinstance(node, ast.Import):
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
            findings.append(Finding(
                file=filepath,
                line=lineno,
                severity=Severity.WARNING,
                category=Category.DEAD_CODE,
                source=Source.AST,
                rule="unused-import",
                message=f"Import '{name}' is never used",
                suggestion=f"Remove unused import '{name}'",
            ))


def _find_type_checking_lines(tree: ast.AST) -> set[int]:
    """Find line numbers of imports inside `if TYPE_CHECKING:` blocks."""
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            # Check for `if TYPE_CHECKING:` or `if typing.TYPE_CHECKING:`
            test = node.test
            is_type_checking = (
                (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
                or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
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


def _check_exception_handling(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for swallowed exceptions (except: pass)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                findings.append(Finding(
                    file=filepath,
                    line=node.lineno,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="exception-swallowed",
                    message="Exception caught and silently ignored (except: pass)",
                    suggestion="Log the exception or handle it explicitly",
                ))


def _check_shadowed_builtins(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for variables that shadow Python builtins."""
    _SHADOW_BUILTINS = {
        "list", "dict", "type", "str", "int", "float", "set", "tuple",
        "len", "range", "open", "input", "print", "sum", "min", "max",
        "id", "sorted", "next",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _SHADOW_BUILTINS:
                    findings.append(Finding(
                        file=filepath,
                        line=node.lineno,
                        severity=Severity.WARNING,
                        category=Category.BUG,
                        source=Source.AST,
                        rule="shadowed-builtin",
                        message=f"Assignment shadows builtin '{target.id}'",
                        suggestion=f"Rename variable to avoid shadowing builtin '{target.id}'",
                    ))


def _check_type_comparisons(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for type() == comparison instead of isinstance()."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    if (isinstance(node.left, ast.Call)
                            and isinstance(node.left.func, ast.Name)
                            and node.left.func.id == "type"):
                        findings.append(Finding(
                            file=filepath,
                            line=node.lineno,
                            severity=Severity.WARNING,
                            category=Category.BUG,
                            source=Source.AST,
                            rule="type-comparison",
                            message="Use isinstance() instead of type() comparison",
                            suggestion="Replace type(x) == Y with isinstance(x, Y)",
                        ))
                        break


def _check_global_usage(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for global keyword usage."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Global):
                    findings.append(Finding(
                        file=filepath,
                        line=stmt.lineno,
                        severity=Severity.INFO,
                        category=Category.STYLE,
                        source=Source.AST,
                        rule="global-keyword",
                        message=f"'global' keyword used for: {', '.join(stmt.names)}",
                        suggestion="Consider passing values as arguments or using a class",
                    ))


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
            if (isinstance(default, ast.Call)
                    and isinstance(default.func, ast.Name)
                    and default.func.id == "set"
                    and not default.args and not default.keywords):
                is_mutable = True
            if is_mutable:
                findings.append(Finding(
                    file=filepath,
                    line=node.lineno,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="mutable-default",
                    message=f"Mutable default argument in '{node.name}' — shared across all calls",
                    suggestion="Use None as default and create inside function body",
                ))
                break  # One report per function is enough


def _check_shadowed_builtin_params(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for function parameters that shadow Python builtins."""
    _SHADOW_BUILTINS = {
        "list", "dict", "type", "str", "int", "float", "set", "tuple",
        "len", "range", "open", "input", "print", "sum", "min", "max",
        "id", "sorted", "next", "map", "filter", "zip", "hash", "iter",
        "bool", "bytes", "complex", "frozenset", "object", "super",
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        all_args = (
            node.args.args + node.args.posonlyargs + node.args.kwonlyargs
        )
        for arg in all_args:
            if arg.arg in ("self", "cls"):
                continue
            if arg.arg in _SHADOW_BUILTINS:
                findings.append(Finding(
                    file=filepath,
                    line=arg.lineno if hasattr(arg, 'lineno') else node.lineno,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="shadowed-builtin-param",
                    message=f"Parameter '{arg.arg}' in '{node.name}' shadows builtin",
                    suggestion=f"Rename parameter to avoid shadowing builtin '{arg.arg}'",
                ))


def _count_branches(node: ast.AST) -> int:
    """Count branch nodes without descending into nested function definitions."""
    count = 0
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue  # Don't count branches inside nested functions
        if isinstance(child, (ast.If, ast.For, ast.While, ast.Try,
                              ast.ExceptHandler, ast.With)):
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
                findings.append(Finding(
                    file=filepath,
                    line=next_stmt.lineno,
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    source=Source.AST,
                    rule="unreachable-code",
                    message="Unreachable code after return/raise/break/continue",
                    suggestion="Remove dead code or restructure control flow",
                ))
                break  # Only report the first unreachable block

    # Overly complex functions (too many branches)
    # Use _count_branches to avoid counting nested function bodies
    branch_count = _count_branches(node)
    if branch_count > 15:
        findings.append(Finding(
            file=filepath,
            line=node.lineno,
            severity=Severity.INFO,
            category=Category.STYLE,
            rule="high-complexity",
            source=Source.AST,
            message=f"Function '{node.name}' has high cyclomatic complexity ({branch_count} branches)",
            suggestion="Consider breaking into smaller functions",
        ))

    # Too many arguments
    total_args = (
        len(node.args.args) + len(node.args.posonlyargs)
        + len(node.args.kwonlyargs)
    )
    # Don't count 'self' and 'cls'
    if node.args.args and node.args.args[0].arg in ("self", "cls"):
        total_args -= 1
    if total_args > 7:
        findings.append(Finding(
            file=filepath,
            line=node.lineno,
            severity=Severity.INFO,
            category=Category.STYLE,
            source=Source.AST,
            rule="too-many-args",
            message=f"Function '{node.name}' has {total_args} arguments",
            suggestion="Consider using a dataclass or config object to group parameters",
        ))


def analyze_file_static(filepath: str, content: str, language: str,
                        custom_rules=None) -> list[Finding]:
    """Run all static checks (regex + tree-sitter AST + Python AST fallback + semantic)."""
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
    semantics = extract_semantics(content, filepath, language)
    if semantics:
        from .semantic.scope import (
            check_unused_variables,
            check_variable_shadowing,
            check_uninitialized_variables,
        )
        from .semantic.taint import analyze_taint
        from .semantic.smells import check_god_class, check_feature_envy, check_long_method, check_semantic_clones

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
                from .semantic.taint import analyze_taint_pathsensitive
                from .semantic.resource import check_resource_leaks
                findings.extend(analyze_taint_pathsensitive(
                    semantics, source_bytes, config, filepath, cfgs))
                findings.extend(check_resource_leaks(
                    semantics, source_bytes, config, filepath, cfgs))
            else:
                # Fallback to flow-insensitive taint analysis
                findings.extend(analyze_taint(semantics, source_bytes, config, filepath))

        # v0.10.0: Type inference + null safety
        if config:
            try:
                from .semantic.types import infer_types
                from .semantic.nullsafety import check_null_safety
                type_map = infer_types(semantics, source_bytes, config, cfgs=cfgs if config else None)
                if type_map and type_map.types:
                    findings.extend(check_null_safety(
                        semantics, type_map, config, filepath, cfgs=cfgs if config else None))
            except (ValueError, OSError, AttributeError) as e:
                logger.debug("Type inference/null safety skipped: %s", e)

        findings.extend(check_god_class(semantics, filepath))
        findings.extend(check_feature_envy(semantics, filepath))
        findings.extend(check_long_method(semantics, filepath))
        findings.extend(check_semantic_clones({filepath: semantics}))

    # Deduplicate: same file + line + rule
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity (critical first), then line number
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    unique.sort(key=lambda f: (severity_order[f.severity], f.line))
    return unique
