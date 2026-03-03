"""Cross-language AST checks powered by tree-sitter.

Optional dependency — returns empty results when tree-sitter is not installed.
Install with: pip install wiz[ast]
"""

import re

from ..config import Finding, Severity, Category, Source
from .lang_config import get_config, LanguageConfig


def _get_named_children(node) -> list:
    """Get all named children of a node."""
    return [c for c in node.children if c.is_named]


def _get_node_text(node, source_bytes: bytes) -> str:
    """Extract the source text for a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk_tree(node):
    """Yield all nodes in the tree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from _walk_tree(child)


def _node_line(node) -> int:
    """Get 1-based line number for a node."""
    return node.start_point[0] + 1


# ─── Check: Unused Imports ─────────────────────────────────────────────────

def check_unused_imports(tree, source_bytes: bytes, config: LanguageConfig,
                         filepath: str) -> list[Finding]:
    """Detect imports where the imported name never appears elsewhere in the file."""
    if not config.import_node_types:
        return []

    findings = []
    root = tree.root_node

    for node in _walk_tree(root):
        if node.type not in config.import_node_types:
            continue

        import_text = _get_node_text(node, source_bytes)
        import_line = _node_line(node)
        import_start = node.start_byte
        import_end = node.end_byte

        # Extract imported names based on language patterns
        names = _extract_import_names(node, source_bytes, config)

        # Check each name: does it appear elsewhere in the source?
        source_before = source_bytes[:import_start]
        source_after = source_bytes[import_end:]
        rest_of_source = source_before + source_after

        for name in names:
            if name.startswith("_"):
                continue
            # Use word-boundary regex to avoid matching substrings
            # (e.g. "io" inside "collections")
            pattern = re.compile(rb'\b' + re.escape(name.encode("utf-8")) + rb'\b')
            if not pattern.search(rest_of_source):
                findings.append(Finding(
                    file=filepath,
                    line=import_line,
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    source=Source.AST,
                    rule="unused-import",
                    message=f"Import '{name}' is never used",
                    suggestion=f"Remove unused import '{name}'",
                ))

    return findings


def _extract_import_names(node, source_bytes: bytes,
                          config: LanguageConfig) -> list[str]:
    """Extract the names introduced by an import statement."""
    names = []
    lang = config.ts_language_name

    if lang == "python":
        if node.type == "import_statement":
            # `import os` / `import os, sys` / `import os as alias`
            for child in node.children:
                if child.type == "dotted_name":
                    text = _get_node_text(child, source_bytes)
                    names.append(text.split(".")[0])
                elif child.type == "aliased_import":
                    alias = child.child_by_field_name("alias")
                    if alias:
                        names.append(_get_node_text(alias, source_bytes))
                    else:
                        name_node = child.child_by_field_name("name")
                        if name_node:
                            names.append(_get_node_text(name_node, source_bytes).split(".")[0])
        elif node.type == "import_from_statement":
            # `from M import X, Y` / `from M import X as Z`
            module_node = node.child_by_field_name("module_name")
            for child in node.children:
                # Skip module name and keywords
                if child.type in ("from", "import", ","):
                    continue
                if module_node and child.id == module_node.id:
                    continue
                if child.type == "dotted_name":
                    text = _get_node_text(child, source_bytes)
                    if text != "*":
                        names.append(text.split(".")[-1])
                elif child.type == "identifier":
                    text = _get_node_text(child, source_bytes)
                    if text != "*":
                        names.append(text)
                elif child.type == "aliased_import":
                    alias = child.child_by_field_name("alias")
                    if alias:
                        names.append(_get_node_text(alias, source_bytes))
                    else:
                        name_node = child.child_by_field_name("name")
                        if name_node:
                            names.append(_get_node_text(name_node, source_bytes))

    elif lang in ("javascript", "typescript"):
        # import { X, Y } from "module"  or  import X from "module"
        for child in _walk_tree(node):
            if child.type == "import_specifier":
                alias = child.child_by_field_name("alias")
                if alias:
                    names.append(_get_node_text(alias, source_bytes))
                else:
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        names.append(_get_node_text(name_node, source_bytes))
            elif child.type == "identifier" and child.parent.type == "import_clause":
                names.append(_get_node_text(child, source_bytes))
            elif child.type == "namespace_import":
                # import * as X
                for sub in child.children:
                    if sub.type == "identifier":
                        names.append(_get_node_text(sub, source_bytes))

    elif lang == "go":
        # import "pkg" or import ( "pkg1"; "pkg2" )
        for child in _walk_tree(node):
            if child.type == "import_spec":
                # Check for alias
                name_node = child.child_by_field_name("name")
                path_node = child.child_by_field_name("path")
                if name_node:
                    text = _get_node_text(name_node, source_bytes)
                    if text != "." and text != "_":
                        names.append(text)
                elif path_node:
                    # Extract package name from path: "fmt" → fmt, "net/http" → http
                    path_text = _get_node_text(path_node, source_bytes).strip('"')
                    pkg_name = path_text.rsplit("/", 1)[-1]
                    names.append(pkg_name)

    elif lang == "java":
        # import com.example.Foo;
        for child in _walk_tree(node):
            if child.type == "scoped_identifier" and child.parent.type == "import_declaration":
                text = _get_node_text(child, source_bytes)
                # Use the last component: com.example.Foo → Foo
                names.append(text.rsplit(".", 1)[-1])
                break
            elif child.type == "identifier" and child.parent.type == "import_declaration":
                names.append(_get_node_text(child, source_bytes))

    elif lang == "c_sharp":
        # using System.Linq;
        for child in _walk_tree(node):
            if child.type in ("qualified_name", "identifier") and child.parent.type == "using_directive":
                text = _get_node_text(child, source_bytes)
                names.append(text.rsplit(".", 1)[-1])
                break

    elif lang == "rust":
        # use std::collections::HashMap;
        for child in _walk_tree(node):
            if child.type == "use_as_clause":
                alias = child.child_by_field_name("alias")
                if alias:
                    names.append(_get_node_text(alias, source_bytes))
                    break
            elif child.type == "identifier" and child.parent and child.parent.type in (
                "use_declaration", "scoped_identifier", "use_list",
            ):
                # Get the last identifier in the path
                pass
        # Simpler approach: get the full use path and extract the last component
        if not names:
            text = _get_node_text(node, source_bytes)
            # use std::collections::HashMap; → HashMap
            # use std::io::{Read, Write}; → harder, skip multi-imports for now
            if "::" in text and "{" not in text:
                last = text.rstrip(";").rsplit("::", 1)[-1].strip()
                if last and last != "*":
                    names.append(last)

    return names


# ─── Check: Unreachable Code ──────────────────────────────────────────────

def check_unreachable_code(tree, source_bytes: bytes, config: LanguageConfig,
                           filepath: str) -> list[Finding]:
    """Detect statements after return/break/continue/throw within a block."""
    findings = []
    terminal_types = set(
        config.return_node_types + config.break_node_types +
        config.continue_node_types + config.throw_node_types
    )
    if not terminal_types:
        return []

    block_types = set(config.block_node_types)
    # Also check function bodies directly for Python (indented block)
    if config.ts_language_name == "python":
        block_types.add("block")

    for node in _walk_tree(tree.root_node):
        if node.type not in block_types:
            continue

        named = _get_named_children(node)
        found_terminal = False
        for child in named:
            if found_terminal:
                # Skip comment nodes — they're not real code
                if child.type in config.comment_node_types:
                    continue
                findings.append(Finding(
                    file=filepath,
                    line=_node_line(child),
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    source=Source.AST,
                    rule="unreachable-code",
                    message="Unreachable code after return/raise/break/continue",
                    suggestion="Remove dead code or restructure control flow",
                ))
                break  # One report per block
            if child.type in terminal_types:
                found_terminal = True

    return findings


# ─── Check: Empty Catch/Except ────────────────────────────────────────────

def check_empty_catch(tree, source_bytes: bytes, config: LanguageConfig,
                      filepath: str) -> list[Finding]:
    """Detect catch/except blocks with empty or pass-only bodies."""
    if not config.catch_node_types:
        return []

    findings = []
    catch_types = set(config.catch_node_types)

    for node in _walk_tree(tree.root_node):
        if node.type not in catch_types:
            continue

        # Find the body of the catch block
        body = _get_catch_body(node, config)
        if body is None:
            continue

        # Check if body is empty or pass-only
        named = _get_named_children(body)
        # Filter out comments
        meaningful = [n for n in named
                      if n.type not in config.comment_node_types]

        is_empty = False
        if len(meaningful) == 0:
            is_empty = True
        elif (len(meaningful) == 1 and
              meaningful[0].type in config.pass_node_types):
            is_empty = True

        if is_empty:
            findings.append(Finding(
                file=filepath,
                line=_node_line(node),
                severity=Severity.WARNING,
                category=Category.BUG,
                source=Source.AST,
                rule="empty-exception-handler",
                message="Exception caught and silently ignored",
                suggestion="Log the exception or handle it explicitly",
            ))

    return findings


def _get_catch_body(node, config: LanguageConfig):
    """Get the body node of a catch/except clause."""
    if config.catch_body_field:
        return node.child_by_field_name(config.catch_body_field)
    # Python: except_clause children are: "except" [type] ["as" name] ":" block
    for child in node.children:
        if child.type in config.block_node_types:
            return child
    return None


# ─── Check: Shadowed Builtins ─────────────────────────────────────────────

def check_shadowed_builtins(tree, source_bytes: bytes, config: LanguageConfig,
                            filepath: str) -> list[Finding]:
    """Detect function parameters that shadow language builtins."""
    if not config.builtin_names or not config.function_node_types:
        return []

    findings = []
    func_types = set(config.function_node_types)

    for node in _walk_tree(tree.root_node):
        if node.type not in func_types:
            continue

        func_name = _get_function_name(node, source_bytes)
        params = _get_parameter_names(node, source_bytes, config)

        for param_name, param_line in params:
            if param_name in ("self", "cls"):
                continue
            if param_name in config.builtin_names:
                findings.append(Finding(
                    file=filepath,
                    line=param_line,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="shadowed-builtin",
                    message=f"Parameter '{param_name}' in '{func_name}' shadows builtin",
                    suggestion=f"Rename parameter to avoid shadowing builtin '{param_name}'",
                ))

    return findings


# ─── Check: Function Complexity ───────────────────────────────────────────

def check_function_complexity(tree, source_bytes: bytes, config: LanguageConfig,
                              filepath: str) -> list[Finding]:
    """Flag functions with cyclomatic complexity > 15."""
    if not config.function_node_types:
        return []

    findings = []
    func_types = set(config.function_node_types)
    branch_types = set(config.branch_node_types)

    for node in _walk_tree(tree.root_node):
        if node.type not in func_types:
            continue

        func_name = _get_function_name(node, source_bytes)
        complexity = _count_complexity(node, branch_types, func_types)

        if complexity > 15:
            findings.append(Finding(
                file=filepath,
                line=_node_line(node),
                severity=Severity.INFO,
                category=Category.STYLE,
                source=Source.AST,
                rule="high-complexity",
                message=f"Function '{func_name}' has high cyclomatic complexity ({complexity} branches)",
                suggestion="Consider breaking into smaller functions",
            ))

    return findings


def _count_complexity(node, branch_types: set, func_types: set) -> int:
    """Count branching nodes without descending into nested functions."""
    count = 0
    for child in node.children:
        if child.type in func_types:
            continue  # Don't count branches in nested functions
        if child.type in branch_types:
            # For binary_expression, only count && and ||
            if child.type == "binary_expression":
                op = child.child_by_field_name("operator")
                if op:
                    op_text = op.type
                    if op_text not in ("&&", "||", "and", "or"):
                        count += _count_complexity(child, branch_types, func_types)
                        continue
            count += 1
        count += _count_complexity(child, branch_types, func_types)
    return count


# ─── Check: Too Many Arguments ────────────────────────────────────────────

def check_too_many_args(tree, source_bytes: bytes, config: LanguageConfig,
                        filepath: str) -> list[Finding]:
    """Flag functions with more than 7 parameters."""
    if not config.function_node_types:
        return []

    findings = []
    func_types = set(config.function_node_types)

    for node in _walk_tree(tree.root_node):
        if node.type not in func_types:
            continue

        func_name = _get_function_name(node, source_bytes)
        params = _get_parameter_names(node, source_bytes, config)

        # Exclude self/cls
        real_params = [(n, l) for n, l in params if n not in ("self", "cls")]

        if len(real_params) > 7:
            findings.append(Finding(
                file=filepath,
                line=_node_line(node),
                severity=Severity.INFO,
                category=Category.STYLE,
                source=Source.AST,
                rule="too-many-args",
                message=f"Function '{func_name}' has {len(real_params)} arguments",
                suggestion="Consider using a dataclass or config object to group parameters",
            ))

    return findings


# ─── Check: Mutable Default Arguments ─────────────────────────────────────

def check_mutable_defaults(tree, source_bytes: bytes, config: LanguageConfig,
                           filepath: str) -> list[Finding]:
    """Detect mutable default parameter values (list/dict/set literals)."""
    if not config.default_value_node_types or not config.function_node_types:
        return []

    findings = []
    func_types = set(config.function_node_types)
    mutable_types = set(config.default_value_node_types)

    for node in _walk_tree(tree.root_node):
        if node.type not in func_types:
            continue

        func_name = _get_function_name(node, source_bytes)
        if _has_mutable_default(node, mutable_types, config):
            findings.append(Finding(
                file=filepath,
                line=_node_line(node),
                severity=Severity.WARNING,
                category=Category.BUG,
                source=Source.AST,
                rule="mutable-default",
                message=f"Mutable default argument in '{func_name}' — shared across all calls",
                suggestion="Use None as default and create inside function body",
            ))

    return findings


def _has_mutable_default(func_node, mutable_types: set,
                         config: LanguageConfig) -> bool:
    """Check if any parameter of a function has a mutable default value."""
    param_types = set(config.parameter_node_types)

    for child in _walk_tree(func_node):
        # Look for default_parameter / typed_default_parameter nodes
        if child.type in ("default_parameter", "typed_default_parameter"):
            value = child.child_by_field_name("value")
            if value and value.type in mutable_types:
                return True
        # For assignment_pattern (JS/TS destructured defaults)
        elif child.type == "assignment_pattern":
            right = child.child_by_field_name("right")
            if right and right.type in mutable_types:
                return True

    return False


# ─── Helpers ──────────────────────────────────────────────────────────────

def _get_function_name(node, source_bytes: bytes) -> str:
    """Extract function name from a function node."""
    name_node = node.child_by_field_name("name")
    if name_node:
        return _get_node_text(name_node, source_bytes)
    # Arrow functions / anonymous: use the variable they're assigned to
    if node.parent and node.parent.type in ("variable_declarator", "assignment_expression"):
        name_node = node.parent.child_by_field_name("name")
        if name_node:
            return _get_node_text(name_node, source_bytes)
    return "<anonymous>"


def _get_parameter_names(node, source_bytes: bytes,
                         config: LanguageConfig) -> list[tuple[str, int]]:
    """Extract (param_name, line_number) pairs from a function's parameter list."""
    params = []
    param_list_types = set(config.parameter_node_types)

    for child in node.children:
        if child.type not in param_list_types:
            continue

        for param in _walk_tree(child):
            # Python: identifier nodes that are direct children of parameters,
            #         or inside typed_parameter, default_parameter, etc.
            if param.type == "identifier":
                parent_type = param.parent.type if param.parent else ""
                if parent_type in (
                    "parameters", "formal_parameters", "parameter_list",
                    "typed_parameter", "default_parameter",
                    "typed_default_parameter", "parameter",
                    "formal_parameter", "required_parameter",
                    # Also handle the case where identifier is the name field
                ):
                    name = _get_node_text(param, source_bytes)
                    # Avoid grabbing type annotations as parameter names
                    if param.parent and param.parent.type in ("typed_parameter", "typed_default_parameter"):
                        name_field = param.parent.child_by_field_name("name")
                        if name_field and param.id == name_field.id:
                            params.append((name, _node_line(param)))
                    elif param.parent and param.parent.type in ("parameter", "formal_parameter", "required_parameter"):
                        name_field = param.parent.child_by_field_name("name")
                        if name_field and param.id == name_field.id:
                            params.append((name, _node_line(param)))
                    elif parent_type in ("parameters", "formal_parameters", "parameter_list"):
                        # Direct child identifier = simple parameter name
                        params.append((name, _node_line(param)))
                    elif parent_type == "default_parameter":
                        name_field = param.parent.child_by_field_name("name")
                        if name_field and param.id == name_field.id:
                            params.append((name, _node_line(param)))

    return params


# ─── Main Entry Point ─────────────────────────────────────────────────────

ALL_CHECKS = [
    check_unused_imports,
    check_unreachable_code,
    check_empty_catch,
    check_shadowed_builtins,
    check_function_complexity,
    check_too_many_args,
    check_mutable_defaults,
]


def run_tree_sitter_checks(content: str, filepath: str,
                           language: str) -> list[Finding]:
    """Run all tree-sitter AST checks. Returns [] if tree-sitter not installed."""
    config = get_config(language)
    if config is None:
        return []

    try:
        from tree_sitter_language_pack import get_language, get_parser
    except ImportError:
        return []

    try:
        parser = get_parser(config.ts_language_name)
    except Exception:
        return []  # Language not available in installed pack

    source_bytes = content.encode("utf-8")
    tree = parser.parse(source_bytes)

    findings = []
    for check_fn in ALL_CHECKS:
        findings.extend(check_fn(tree, source_bytes, config, filepath))

    return findings
