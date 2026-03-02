"""Static analysis engine — regex matching + Python AST parsing."""

import ast

from .config import Finding, Severity, Category, Source
from .languages import get_rules_for_language


def run_regex_checks(content: str, filepath: str, language: str) -> list[Finding]:
    """Run regex-based pattern matching against file content."""
    findings = []
    rules = get_rules_for_language(language)
    lines = content.splitlines()

    # Language-aware comment prefixes
    comment_prefixes = {"#"}
    if language in ("javascript", "typescript", "go", "rust", "java",
                     "c", "cpp", "csharp", "swift", "kotlin", "pine"):
        comment_prefixes = {"//"}
    elif language == "python":
        comment_prefixes = {"#"}

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        is_comment = any(stripped.startswith(p) for p in comment_prefixes)
        # Skip lines that are purely string content (inside quotes)
        is_string_line = (
            (stripped.startswith('"') or stripped.startswith("'"))
            and not stripped.startswith('"""') and not stripped.startswith("'''")
        )

        for pattern, severity, category, rule_name, message, suggestion in rules:
            # Skip ALL regex rules on comment lines (except todo-marker which targets comments)
            if is_comment and rule_name != "todo-marker":
                continue
            # Skip security/bug patterns on string-only lines
            if is_string_line and category in (Category.SECURITY, Category.BUG):
                continue
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

    return findings


def _check_imports(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check for unused imports."""
    imported_names = {}  # name -> line number
    used_names = set()

    for node in ast.walk(tree):
        # Track imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imported_names[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
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
                root = root.value
            if isinstance(root, ast.Name):
                used_names.add(root.id)

    # Report unused imports
    for name, lineno in imported_names.items():
        if name.startswith("_"):  # Skip intentional underscore names
            continue
        if name not in used_names:
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


def _check_functions(tree: ast.AST, filepath: str, findings: list[Finding]):
    """Check all functions for common issues."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function(node, filepath, findings)


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


def analyze_file_static(filepath: str, content: str, language: str) -> list[Finding]:
    """Run all static checks (regex + AST if Python)."""
    findings = run_regex_checks(content, filepath, language)

    if language == "python":
        findings.extend(run_python_ast_checks(content, filepath))

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
