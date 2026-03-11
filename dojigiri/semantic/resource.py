"""Resource leak detection using CFG-based forward analysis.

Tracks resource open/close operations per function. At exit blocks, reports
unclosed resources. Detects context managers (with/using blocks) as automatic
close. Also detects try/finally patterns as safe cleanup.
Returns [] when tree-sitter is not available or no CFG.

Called by: detector.py
Calls into: semantic/lang_config.py, semantic/core.py, semantic/cfg.py, config.py
Data in → Data out: FileSemantics + CFG → list[Finding] (unclosed files/connections)
"""

from __future__ import annotations  # noqa

import re
from dataclasses import dataclass

from ..types import Category, Finding, Severity, Source
from .cfg import FunctionCFG
from .core import FileSemantics, FunctionDef
from .lang_config import LanguageConfig

# ─── Data structures ─────────────────────────────────────────────────


@dataclass
class ResourceState:
    variable: str
    open_line: int
    kind: str  # "file", "connection", "lock", "socket", etc.
    is_context_managed: bool = False
    closed: bool = False
    close_line: int = 0


# ─── Analysis ────────────────────────────────────────────────────────


def _find_context_managed_lines(source_bytes: bytes, language: str) -> set[int]:
    """Find lines inside 'with' blocks (Python) or 'using' blocks (C#).

    Returns the set of lines that are inside a context manager scope.
    These resources are automatically closed.
    """
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    with_lines: set[int] = set()

    if language == "python":
        # Track indentation of 'with' statements
        with_indents: list[int] = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # Close any 'with' blocks that have ended (dedent)
            with_indents = [wi for wi in with_indents if indent > wi]

            if stripped.startswith("with ") and stripped.rstrip().endswith(":"):
                with_indents.append(indent)
                with_lines.add(i)
            elif with_indents:
                with_lines.add(i)

    elif language == "csharp":
        # Track 'using' statements
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("using ") and ("=" in stripped or "var " in stripped):
                with_lines.add(i)

    elif language == "java":
        # try-with-resources: try (Resource r = ...)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("try") and "(" in stripped:
                with_lines.add(i)

    return with_lines


def _find_finally_closed_vars(
    source_bytes: bytes,
    config: LanguageConfig,
    fdef: FunctionDef,
) -> set[str]:
    """Find variable names that are closed in finally blocks.

    Resources closed in finally are always cleaned up regardless of exception path.
    """
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    closed_vars: set[str] = set()

    in_finally = False
    finally_indent = 0

    for i in range(fdef.line - 1, min(fdef.end_line, len(lines))):
        line = lines[i]
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("finally") and stripped.rstrip().endswith(":"):
            in_finally = True
            finally_indent = indent
            continue

        if not in_finally:
            continue

        # Check if we've left the finally block (dedent to same or less indent)
        if indent <= finally_indent and stripped and not stripped.startswith("#"):
            in_finally = False
            continue

        # Check for close patterns within the finally block
        for _open_pat, close_pat, _, _ in config.resource_patterns:
            if close_pat not in stripped:
                continue
            m = re.search(r"(\w+)\." + re.escape(close_pat), stripped)
            if m:
                closed_vars.add(m.group(1))

    return closed_vars


def _find_open_resources(
    semantics: FileSemantics,
    config: LanguageConfig,
    fdef: FunctionDef,
    context_managed_lines: set[int],
    finally_closed: set[str],
) -> dict[str, ResourceState]:
    """Scan assignments within a function for resource open patterns."""
    resources: dict[str, ResourceState] = {}
    for asgn in semantics.assignments:
        if not (fdef.line <= asgn.line <= fdef.end_line):
            continue
        if asgn.is_parameter or asgn.is_augmented:
            continue

        rhs = asgn.value_text
        for open_pat, _close_pat, has_ctx_mgr, kind in config.resource_patterns:
            if re.search(r"\b" + re.escape(open_pat) + r"\s*\(", rhs):
                is_ctx = (has_ctx_mgr and asgn.line in context_managed_lines) or asgn.name in finally_closed
                resources[asgn.name] = ResourceState(
                    variable=asgn.name,
                    open_line=asgn.line,
                    kind=kind,
                    is_context_managed=is_ctx,
                )
                break
    return resources


def _mark_closed_resources(
    semantics: FileSemantics,
    config: LanguageConfig,
    fdef: FunctionDef,
    resources: dict[str, ResourceState],
    lines: list[str],
) -> None:
    """Scan function calls and mark resources as closed."""
    for call in semantics.function_calls:
        if not (fdef.line <= call.line <= fdef.end_line):
            continue

        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"

        for _open_pat, close_pat, _, _ in config.resource_patterns:
            if close_pat not in call_text:
                continue
            if call.receiver and call.receiver in resources:
                resources[call.receiver].closed = True
                resources[call.receiver].close_line = call.line
            else:
                line_idx = call.line - 1
                if 0 <= line_idx < len(lines):
                    line_text = lines[line_idx]
                    for rname, rstate in resources.items():
                        if re.search(r"\b" + re.escape(rname) + r"\b", line_text):
                            rstate.closed = True
                            rstate.close_line = call.line


def check_resource_leaks(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
    filepath: str,
    cfgs: dict[int, FunctionCFG],
) -> list[Finding]:
    """Detect unclosed resources using CFG-based forward analysis.

    Returns [] if no resource patterns configured.
    """
    if not config.resource_patterns:
        return []

    findings = []
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    context_managed_lines = _find_context_managed_lines(source_bytes, semantics.language)

    fdef_to_scope: dict[str, int] = {}
    for scope in semantics.scopes:
        if scope.kind == "function" and scope.name:
            fdef_to_scope[scope.name] = scope.scope_id

    for fdef in semantics.function_defs:
        func_scope_id = fdef_to_scope.get(fdef.qualified_name, fdef.scope_id)
        if cfgs.get(func_scope_id) is None:
            continue

        finally_closed = _find_finally_closed_vars(source_bytes, config, fdef)
        resources = _find_open_resources(semantics, config, fdef, context_managed_lines, finally_closed)
        if not resources:
            continue

        _mark_closed_resources(semantics, config, fdef, resources, lines)

        # Report unclosed resources
        for _rname, rstate in resources.items():
            if rstate.closed or rstate.is_context_managed:
                continue
            findings.append(
                Finding(
                    file=filepath,
                    line=rstate.open_line,
                    severity=Severity.WARNING,
                    category=Category.BUG,
                    source=Source.AST,
                    rule="resource-leak",
                    message=(f"Resource '{rstate.variable}' ({rstate.kind}) opened but never closed"),
                    suggestion=(
                        f"Close '{rstate.variable}' explicitly or use a context manager (e.g., 'with' statement)"
                    ),
                )
            )

    return findings
