"""Python AST-based static checks — extracted from detector.py.

14 focused check functions and the run_python_ast_checks() orchestrator.
Each _check_* function appends findings to a shared list.

Called by: detector.py (via run_python_ast_checks)
Data in → Data out: (content, filepath) → list[Finding]
"""

from __future__ import annotations

import ast
import re

from .types import Category, Finding, Severity, Source


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


def _import_has_noqa(node: ast.AST, source_lines: list[str]) -> bool:
    """Check if any line of this import node has a # noqa or # type: comment."""
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    for ln in range(start, end + 1):
        if 0 < ln <= len(source_lines):
            line_text = source_lines[ln - 1]
            if "# noqa" in line_text or "# type:" in line_text:
                return True
    return False


def _collect_imports(
    tree: ast.AST, source_lines: list[str], type_checking_lines: set[int],
) -> tuple[dict[str, int], set[str]]:
    """Walk the AST and collect imported names and re-exported names.

    Returns (imported_names, re_exported_names) where imported_names maps
    name -> line number and re_exported_names is the set of identity-aliased names.
    """
    imported_names: dict[str, int] = {}
    re_exported_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if _import_has_noqa(node, source_lines):
                continue
            for alias in node.names:
                if alias.asname and alias.asname == alias.name:
                    re_exported_names.add(alias.name)
                    continue
                name = alias.asname or alias.name
                imported_names[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            if node.lineno in type_checking_lines:
                continue
            if _import_has_noqa(node, source_lines):
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.asname and alias.asname == alias.name:
                    re_exported_names.add(alias.name)
                    continue
                name = alias.asname or alias.name
                imported_names[name] = node.lineno

    return imported_names, re_exported_names


def _collect_used_names(tree: ast.AST) -> set[str]:
    """Walk the AST and collect all referenced names (Name nodes and attribute roots)."""
    used_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value  # type: ignore[assignment]  # narrowing through loop
            if isinstance(root, ast.Name):
                used_names.add(root.id)
    return used_names


def _check_imports(tree: ast.AST, filepath: str, findings: list[Finding], content: str = "") -> None:
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
    type_checking_lines = _find_type_checking_lines(tree)
    imported_names, _re_exported = _collect_imports(tree, source_lines, type_checking_lines)
    used_names = _collect_used_names(tree)

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


def _check_functions(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _is_broad_exception(node: ast.ExceptHandler) -> bool:
    """Check if an except handler catches all or very broad exceptions.

    Returns True for bare ``except:``, ``except Exception:``, and
    ``except BaseException:``.  Returns False for specific exception types
    like ``except ValueError:`` or ``except (KeyError, TypeError):``.
    """
    if node.type is None:
        # bare ``except:``
        return True
    exc = node.type
    # Single name
    if isinstance(exc, ast.Name) and exc.id in ("Exception", "BaseException"):
        return True
    # ``except (Exception,):`` edge case — tuple with broad type
    if isinstance(exc, ast.Tuple):
        return any(
            isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException")
            for elt in exc.elts
        )
    return False


def _is_optional_import_pattern(handler: ast.ExceptHandler) -> bool:
    """Detect ``try: import X / except ImportError: pass`` — optional dependency pattern.

    Returns True when the handler catches ImportError specifically and the body
    is effectively empty (pass).  Also matches common companions:

    - ``except (ImportError, ModuleNotFoundError): pass``
    - ``except (ImportError, AttributeError): pass``  — optional import with
      attribute fallback (e.g. ``from mod import attr`` where attr may not exist).

    The tuple form requires *every* element to be in the allowed set and at
    least one must be ``ImportError`` (so ``except AttributeError: pass`` alone
    is not suppressed by this function).
    """
    _IMPORT_ALLOWED = {"ImportError", "ModuleNotFoundError", "AttributeError"}

    if handler.type is None:
        return False
    exc = handler.type
    if isinstance(exc, ast.Name):
        if exc.id != "ImportError":
            return False
    elif isinstance(exc, ast.Tuple):
        names = {
            elt.id for elt in exc.elts if isinstance(elt, ast.Name)
        }
        if len(names) != len(exc.elts):
            return False  # non-Name element in tuple
        if not (names <= _IMPORT_ALLOWED and "ImportError" in names):
            return False
    else:
        return False

    # Body must be empty (pass, or string comment + pass)
    if not _is_empty_except(handler, ast.Pass):
        return False

    return True


def _is_stop_iteration_pattern(handler: ast.ExceptHandler) -> bool:
    """Detect ``except StopIteration: pass`` — standard iterator consumption.

    Returns True when the handler catches ``StopIteration`` specifically and
    the body is effectively empty (pass).
    """
    if handler.type is None:
        return False
    exc = handler.type
    if isinstance(exc, ast.Name) and exc.id == "StopIteration":
        return _is_empty_except(handler, ast.Pass)
    if isinstance(exc, ast.Tuple):
        names = {elt.id for elt in exc.elts if isinstance(elt, ast.Name)}
        if len(names) != len(exc.elts):
            return False
        if names == {"StopIteration"}:
            return _is_empty_except(handler, ast.Pass)
    return False


def _report_swallowed_pass(
    node: ast.ExceptHandler, filepath: str, findings: list[Finding], source_lines: list[str],
) -> None:
    """Report a swallowed exception with pass, adjusting severity based on comment presence."""
    has_comment = _has_explanatory_comment(node, source_lines)
    if has_comment:
        findings.append(
            Finding(
                file=filepath, line=node.lineno,
                severity=Severity.INFO, category=Category.BUG, source=Source.AST,
                rule="exception-swallowed",
                message="Exception caught and silently ignored (except: pass) — comment explains intent",
                suggestion="Acknowledged via comment; consider logging for observability",
            )
        )
    else:
        findings.append(
            Finding(
                file=filepath, line=node.lineno,
                severity=Severity.WARNING, category=Category.BUG, source=Source.AST,
                rule="exception-swallowed",
                message="Exception caught and silently ignored (except: pass)",
                suggestion="Log the exception or handle it explicitly",
            )
        )


def _continue_msg_suffix(has_comment: bool, is_specific: bool) -> str:
    """Compute the message suffix for swallowed-continue findings."""
    if has_comment and is_specific:
        return " — specific exception with comment"
    if has_comment:
        return " — comment explains intent"
    if is_specific:
        return " — specific exception in fallback pattern"
    return ""


def _report_swallowed_continue(
    node: ast.ExceptHandler, filepath: str, findings: list[Finding], source_lines: list[str],
) -> None:
    """Report a swallowed exception with continue, adjusting severity based on context."""
    has_comment = _has_explanatory_comment(node, source_lines)
    is_specific = not _is_broad_exception(node)
    if has_comment or is_specific:
        msg_suffix = _continue_msg_suffix(has_comment, is_specific)
        findings.append(
            Finding(
                file=filepath, line=node.lineno,
                severity=Severity.INFO, category=Category.BUG, source=Source.AST,
                rule="exception-swallowed-continue",
                message=f"Exception caught and silently continued (except: continue){msg_suffix}",
                suggestion="Acknowledged; consider logging for observability",
            )
        )
    else:
        findings.append(
            Finding(
                file=filepath, line=node.lineno,
                severity=Severity.WARNING, category=Category.BUG, source=Source.AST,
                rule="exception-swallowed-continue",
                message="Exception caught and silently continued (except: continue)",
                suggestion="Log the exception before continuing, or handle it explicitly",
            )
        )


def _check_exception_handling(
    tree: ast.AST, filepath: str, findings: list[Finding], content: str = ""
) -> None:
    """Check for swallowed exceptions (except: pass/continue).

    When the except body contains an explanatory comment (inline ``#`` comment
    or a string-expression "docstring"), the finding is downgraded to INFO
    severity instead of WARNING — the developer explicitly acknowledged the
    swallowed exception.

    For ``continue`` specifically: catching a **specific** exception (not bare
    ``except:`` or ``except Exception:``) with ``continue`` is a common
    dispatcher/fallback pattern (e.g., trying multiple template loaders).
    These are downgraded to INFO even without a comment.
    """
    source_lines = content.splitlines() if content else []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if _is_optional_import_pattern(node) or _is_stop_iteration_pattern(node):
            continue

        is_empty_pass = _is_empty_except(node, ast.Pass)
        is_empty_continue = (not is_empty_pass) and _is_empty_except(node, ast.Continue)

        if is_empty_pass:
            _report_swallowed_pass(node, filepath, findings, source_lines)
        elif is_empty_continue:
            _report_swallowed_continue(node, filepath, findings, source_lines)


# Builtins that should not be shadowed by variables or parameters
_SHADOW_BUILTINS = {
    "list",
    "dict",
    "str",
    "int",
    "float",
    "set",
    "tuple",
    "len",
    "open",
    "print",
    "sum",
    "min",
    "max",
    "sorted",
    "zip",
    "iter",
    "bool",
    "bytes",
    "complex",
    "frozenset",
    "exec",
    "eval",
}


def _check_shadowed_builtins(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_type_comparisons(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_global_usage(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_mutable_defaults(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_shadowed_builtin_params(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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
                  "os.system() is vulnerable to shell injection",  # doji:ignore(os-system)
                  "Use subprocess.run() with a list of arguments"),
    "os.popen": ("os-popen", Severity.WARNING, Category.SECURITY,
                 "os.popen() starts a shell process — vulnerable to injection",  # doji:ignore(os-popen)
                 "Use subprocess.run() with a list of arguments instead"),
    "pickle.loads": ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                     "pickle.loads() can execute arbitrary code during deserialization",  # doji:ignore(deserialization-unsafe,pickle-unsafe)
                     "Use json, msgpack, or a safe serialization format instead"),
    "pickle.load": ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                    "pickle.load() can execute arbitrary code during deserialization",  # doji:ignore(deserialization-unsafe,pickle-unsafe)
                    "Use json, msgpack, or a safe serialization format instead"),
    "yaml.load": ("yaml-unsafe", Severity.CRITICAL, Category.SECURITY,
                  "yaml.load() without SafeLoader can execute arbitrary code",  # doji:ignore(deserialization-unsafe)
                  "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"),  # doji:ignore(deserialization-unsafe)
    "marshal.loads": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                      "marshal.loads() can execute arbitrary code during deserialization",  # doji:ignore(deserialization-unsafe,unsafe-deserialization,marshal-loads-unsafe)
                      "Use json or msgpack for untrusted data"),
    "marshal.load": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                     "marshal.load() can execute arbitrary code during deserialization",  # doji:ignore(deserialization-unsafe,unsafe-deserialization,marshal-loads-unsafe)
                     "Use json or msgpack for untrusted data"),
    "shelve.open": ("unsafe-deserialization", Severity.CRITICAL, Category.SECURITY,
                    "shelve.open() is pickle-backed — can execute arbitrary code",  # doji:ignore(unsafe-deserialization,shelve-open-unsafe)
                    "Use json or msgpack for untrusted data"),
    "hashlib.md5": ("weak-hash", Severity.WARNING, Category.SECURITY,  # doji:ignore(weak-hash-md5,weak-hash)
                    "MD5 is a cryptographically weak hash algorithm",  # doji:ignore(weak-hash-md5,weak-hash)
                    "Use hashlib.sha256() or stronger for security-sensitive hashing"),
    "hashlib.sha1": ("weak-hash", Severity.WARNING, Category.SECURITY,  # doji:ignore(weak-hash-sha1,weak-hash)
                     "SHA1 is a cryptographically weak hash algorithm",  # doji:ignore(weak-hash-sha1,weak-hash)
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


def _build_import_alias_map(tree: ast.AST) -> dict[str, str]:
    """Build alias → canonical module name map from import statements."""
    alias_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname != alias.name:
                    alias_map[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.asname and alias.asname != alias.name:
                    alias_map[alias.asname] = f"{node.module}.{alias.name}"
    return alias_map


def _resolve_aliased_call(func: ast.expr, alias_map: dict[str, str]) -> tuple[str, str] | None:
    """Resolve a call's function node to (canonical_name, display_alias) via alias map.

    Returns None if the call doesn't use an alias or doesn't resolve to a dangerous call.
    """
    # Case 1: alias.method() — e.g. pkl.loads()
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        alias = func.value.id
        if alias in alias_map:
            canonical = f"{alias_map[alias]}.{func.attr}"
            if canonical in _DANGEROUS_CALLS:
                return canonical, alias
    # Case 2: bare alias() — e.g. xml_parse()
    elif isinstance(func, ast.Name) and func.id in alias_map:
        canonical = alias_map[func.id]
        if canonical in _DANGEROUS_CALLS:
            return canonical, func.id
    return None


def _check_aliased_dangerous_calls(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
    """Detect dangerous function calls through import aliases.

    Builds a map of alias → canonical module name from import statements,
    then walks all Call nodes to check if any resolve to a known dangerous call.
    Only fires for calls using non-canonical names (aliases), since the regex
    engine already catches canonical names like pickle.loads().
    """
    alias_map = _build_import_alias_map(tree)
    if not alias_map:
        return  # No aliases, regex covers everything

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        resolved = _resolve_aliased_call(node.func, alias_map)
        if resolved is None:
            continue
        canonical, display_alias = resolved
        rule, sev, cat, msg, sug = _DANGEROUS_CALLS[canonical]
        findings.append(Finding(
            file=filepath, line=node.lineno,
            severity=sev, category=cat, source=Source.AST,
            rule=rule,
            message=f"{msg} (via alias '{display_alias}')",
            suggestion=sug,
        ))


# ── Multiline shell=True detection (AST) ────────────────────────────────
# subprocess.run/Popen/call/check_output with shell=True on different lines.
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})


def _check_multiline_shell_true(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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
                       "os.system() via getattr — shell injection risk",  # doji:ignore(os-system)
                       "Use subprocess.run() with a list of arguments"),
    ("os", "popen"): ("os-popen", Severity.WARNING, Category.SECURITY,
                      "os.popen() via getattr — shell injection risk",  # doji:ignore(os-popen)
                      "Use subprocess.run() with a list of arguments"),
    ("pickle", "loads"): ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                          "pickle.loads() via getattr — arbitrary code execution",  # doji:ignore(deserialization-unsafe,pickle-unsafe)
                          "Use json or msgpack instead"),
    ("pickle", "load"): ("pickle-unsafe", Severity.CRITICAL, Category.SECURITY,
                         "pickle.load() via getattr — arbitrary code execution",  # doji:ignore(deserialization-unsafe,pickle-unsafe)
                         "Use json or msgpack instead"),
    ("subprocess", "Popen"): ("subprocess-audit", Severity.INFO, Category.SECURITY,
                              "subprocess.Popen via getattr — verify arguments",
                              "Ensure command is not user-controlled"),
}


def _check_getattr_dangerous(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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

def _check_async_shell(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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
                    message="asyncio.create_subprocess_shell() runs command through shell",  # doji:ignore(async-subprocess-shell)
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


def _check_sql_fstring(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_hardcoded_secret_defaults(tree: ast.AST, filepath: str, findings: list[Finding]) -> None:
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


def _check_function(node: ast.FunctionDef, filepath: str, findings: list[Finding]) -> None:
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
