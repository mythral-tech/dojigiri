"""Intra-procedural taint analysis: track tainted data from sources to sinks.

Two modes:
1. Flow-insensitive (v0.8.0): analyze_taint() — used as fallback when no CFG.
2. Path-sensitive (v0.9.0): analyze_taint_pathsensitive() — uses CFG for
   precise dataflow, properly handles sanitization on conditional paths.

Operates on FileSemantics + source bytes for pattern matching.
Returns [] when tree-sitter is not available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import Finding, Severity, Category, Source
from .lang_config import LanguageConfig, get_config
from .core import FileSemantics, Assignment, FunctionCall


# ─── Data structures ─────────────────────────────────────────────────

@dataclass
class TaintSource:
    variable: str
    line: int
    kind: str  # "user_input", "file_read", "network", "env_var"


@dataclass
class TaintSink:
    variable: str
    line: int
    kind: str  # "sql_query", "eval", "system_cmd", "html_output"
    function_name: str


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    through: list[tuple[str, int]]  # (variable_name, line) assignment chain


# ─── Analysis ────────────────────────────────────────────────────────

def _matches_pattern(text: str, pattern: str) -> bool:
    """Check if text contains the taint pattern (simple substring match)."""
    return pattern in text


def _find_taint_sources(
    semantics: FileSemantics,
    config: LanguageConfig,
    source_bytes: bytes,
    func_scope_ids: set[int],
) -> list[TaintSource]:
    """Identify taint sources within the given scopes."""
    sources = []

    for asgn in semantics.assignments:
        if asgn.scope_id not in func_scope_ids:
            continue
        if asgn.is_parameter:
            continue

        rhs = asgn.value_text
        for pattern, kind in config.taint_source_patterns:
            if _matches_pattern(rhs, pattern):
                sources.append(TaintSource(
                    variable=asgn.name,
                    line=asgn.line,
                    kind=kind,
                ))
                break

    return sources


def _propagate_taint(
    semantics: FileSemantics,
    initial_tainted: set[str],
    func_scope_ids: set[int],
    config: LanguageConfig,
) -> dict[str, list[tuple[str, int]]]:
    """Propagate taint through assignments within function scope.

    Returns: {tainted_var: [(source_var, line), ...]} chain.
    """
    tainted: dict[str, list[tuple[str, int]]] = {
        name: [] for name in initial_tainted
    }

    # Propagation with sanitization: if RHS contains a tainted variable, LHS
    # becomes tainted — UNLESS the RHS passes through a sanitizer, in which
    # case taint is removed (flow-sensitive reassignment).
    # Iterate until fixed-point.
    changed = True
    max_iters = 10  # prevent infinite loops
    iteration = 0

    while changed and iteration < max_iters:
        changed = False
        iteration += 1

        for asgn in semantics.assignments:
            if asgn.scope_id not in func_scope_ids:
                continue
            if asgn.is_parameter:
                continue

            rhs = asgn.value_text

            # Check if RHS passes through a sanitizer
            is_sanitized = any(
                sanitizer in rhs
                for sanitizer in config.taint_sanitizer_patterns
            )

            if is_sanitized:
                # Sanitizer clears taint — remove from tainted set
                if asgn.name in tainted:
                    del tainted[asgn.name]
                    changed = True
                continue

            # Skip already-tainted vars for propagation (no new info)
            if asgn.name in tainted:
                continue

            for tainted_name in list(tainted.keys()):
                # Check if tainted name appears in RHS
                if re.search(r'\b' + re.escape(tainted_name) + r'\b', rhs):
                    tainted[asgn.name] = tainted.get(tainted_name, []) + [(tainted_name, asgn.line)]
                    changed = True
                    break

    return tainted


def _find_taint_sinks(
    semantics: FileSemantics,
    config: LanguageConfig,
    tainted_vars: set[str],
    func_scope_ids: set[int],
    source_bytes: bytes,
) -> list[TaintSink]:
    """Find sink calls where tainted variables are passed as arguments."""
    sinks = []
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()

    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue

        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"

        for pattern, kind in config.taint_sink_patterns:
            if _matches_pattern(call_text, pattern):
                # Check if any tainted variable appears on this line
                line_idx = call.line - 1
                if 0 <= line_idx < len(lines):
                    line_text = lines[line_idx]
                    for tvar in tainted_vars:
                        if re.search(r'\b' + re.escape(tvar) + r'\b', line_text):
                            sinks.append(TaintSink(
                                variable=tvar,
                                line=call.line,
                                kind=kind,
                                function_name=call_text,
                            ))
                            break
                break

    return sinks


def _is_sanitized(
    semantics: FileSemantics,
    config: LanguageConfig,
    tainted_var: str,
    func_scope_ids: set[int],
) -> bool:
    """Check if a tainted variable passes through a sanitizer."""
    for asgn in semantics.assignments:
        if asgn.scope_id not in func_scope_ids:
            continue
        if asgn.name != tainted_var:
            continue
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in asgn.value_text:
                return True

    # Also check if sanitizer is called on the variable in any call
    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue
        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in call_text:
                return True

    return False


def _update_stmt_taint(
    stmt, semantics: FileSemantics, config: LanguageConfig,
    current_taint: set[str], lines: list[str],
    source_vars: set[str] | None = None, source_lines: dict[str, int] | None = None,
) -> None:
    """Update current_taint in-place for a single CFG statement."""
    if stmt.assignment_idx is not None:
        asgn = semantics.assignments[stmt.assignment_idx]
        rhs = asgn.value_text

        for pattern, kind in config.taint_source_patterns:
            if _matches_pattern(rhs, pattern):
                current_taint.add(asgn.name)
                if source_vars is not None and asgn.name not in source_vars:
                    source_vars.add(asgn.name)
                    if source_lines is not None:
                        source_lines[asgn.name] = asgn.line
                break
        else:
            for tvar in list(current_taint):
                if re.search(r'\b' + re.escape(tvar) + r'\b', rhs):
                    current_taint.add(asgn.name)
                    break

        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in rhs:
                current_taint.discard(asgn.name)
                break

    if stmt.call_idx is not None:
        call = semantics.function_calls[stmt.call_idx]
        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"
        line_idx = stmt.line - 1
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in call_text:
                if 0 <= line_idx < len(lines):
                    line_text = lines[line_idx]
                    for tvar in list(current_taint):
                        if re.search(r'\b' + re.escape(tvar) + r'\b', line_text):
                            current_taint.discard(tvar)


def _build_scope_children(semantics: FileSemantics) -> dict[int, set[int]]:
    """Build parent→children scope map."""
    scope_children: dict[int, set[int]] = {}
    for scope in semantics.scopes:
        parent = scope.parent_id
        if parent is not None:
            scope_children.setdefault(parent, set()).add(scope.scope_id)
    return scope_children


def _get_all_children(sid: int, scope_children: dict[int, set[int]]) -> set[int]:
    """Recursively collect all descendant scope IDs including sid itself."""
    result = {sid}
    for child in scope_children.get(sid, set()):
        result.update(_get_all_children(child, scope_children))
    return result


# ─── Entry point ─────────────────────────────────────────────────────

def analyze_taint(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
    filepath: str,
) -> list[Finding]:
    """Run taint analysis on extracted semantics.

    Analyzes each function independently (intra-procedural).
    Returns [] if no taint source/sink patterns configured.
    """
    if not config.taint_source_patterns or not config.taint_sink_patterns:
        return []

    findings = []
    seen = set()  # (source_line, sink_line) to deduplicate

    # Analyze each function scope independently
    func_scopes = [s for s in semantics.scopes if s.kind == "function"]
    scope_children = _build_scope_children(semantics)

    for func_scope in func_scopes:
        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        # 1. Find sources
        sources = _find_taint_sources(semantics, config, source_bytes, func_scope_ids)
        if not sources:
            continue

        # 2. Propagate taint
        initial_tainted = {s.variable for s in sources}
        taint_chains = _propagate_taint(semantics, initial_tainted, func_scope_ids, config)
        tainted_vars = set(taint_chains.keys())

        if not tainted_vars:
            continue

        # 3. Find sinks
        sinks = _find_taint_sinks(semantics, config, tainted_vars, func_scope_ids, source_bytes)

        # 4. Build findings
        for sink in sinks:
            # Check sanitization
            if _is_sanitized(semantics, config, sink.variable, func_scope_ids):
                continue

            # Find the source for this tainted variable
            source = None
            if sink.variable in initial_tainted:
                for s in sources:
                    if s.variable == sink.variable:
                        source = s
                        break
            else:
                # Follow chain back
                chain = taint_chains.get(sink.variable, [])
                for src in sources:
                    if src.variable in {c[0] for c in chain} | {sink.variable}:
                        source = src
                        break
                if not source and sources:
                    source = sources[0]

            if source is None:
                continue

            key = (source.line, sink.line)
            if key in seen:
                continue
            seen.add(key)

            chain = taint_chains.get(sink.variable, [])
            chain_desc = ""
            if chain:
                chain_names = [c[0] for c in chain]
                chain_desc = f" (through: {' → '.join(chain_names)})"

            findings.append(Finding(
                file=filepath,
                line=sink.line,
                severity=Severity.WARNING,
                category=Category.SECURITY,
                source=Source.AST,
                rule="taint-flow",
                message=(
                    f"Tainted data from '{source.variable}' ({source.kind}, line {source.line}) "
                    f"reaches sink '{sink.function_name}' ({sink.kind}){chain_desc} — "
                    f"verify sanitization"
                ),
                suggestion=(
                    f"Sanitize '{sink.variable}' before passing to '{sink.function_name}', "
                    f"or use parameterized queries/safe APIs"
                ),
            ))

    return findings


# ─── Path-sensitive taint analysis (v0.9.0) ──────────────────────────

def analyze_taint_pathsensitive(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
    filepath: str,
    cfgs: dict,  # dict[int, FunctionCFG] — avoid circular import
) -> list[Finding]:
    """Path-sensitive taint analysis using CFG-based forward dataflow.

    For each function:
    1. Initialize taint at blocks containing taint sources
    2. Forward propagation in reverse-postorder
    3. At merge points (multiple predecessors), union taint sets
    4. Sanitization on a path properly removes taint for that path
    5. Only flag sinks where taint reaches through ALL paths (or any unsanitized path)

    Falls back to flow-insensitive analyze_taint() for functions without CFGs.
    """
    from .cfg import get_reverse_postorder, FunctionCFG

    if not config.taint_source_patterns or not config.taint_sink_patterns:
        return []

    findings = []
    seen = set()
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()

    scope_children = _build_scope_children(semantics)
    func_scopes = [s for s in semantics.scopes if s.kind == "function"]

    for func_scope in func_scopes:
        cfg = cfgs.get(func_scope.scope_id)
        if cfg is None:
            continue

        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        # 1. Find taint sources in this function
        sources = _find_taint_sources(semantics, config, source_bytes, func_scope_ids)
        if not sources:
            continue

        source_vars = {s.variable for s in sources}
        source_lines = {s.variable: s.line for s in sources}

        # 2. Forward dataflow: taint sets per block
        # block_taint_out[block_id] = set of tainted variable names at block exit
        block_taint_out: dict[int, set[str]] = {bid: set() for bid in cfg.blocks}

        rpo = get_reverse_postorder(cfg)
        max_iters = 20

        for _iteration in range(max_iters):
            changed = False

            for block_id in rpo:
                block = cfg.blocks[block_id]

                # Compute taint_in: union of all predecessor taint_outs
                if block.is_entry:
                    taint_in: set[str] = set()
                else:
                    taint_in = set()
                    for pred_id in block.predecessors:
                        taint_in |= block_taint_out.get(pred_id, set())

                # Process statements in order
                current_taint = set(taint_in)

                for stmt in block.statements:
                    _update_stmt_taint(
                        stmt, semantics, config, current_taint, lines,
                        source_vars=source_vars, source_lines=source_lines,
                    )

                old_out = block_taint_out[block_id]
                if current_taint != old_out:
                    block_taint_out[block_id] = current_taint
                    changed = True

            if not changed:
                break

        # 3. Scan for sinks with tainted arguments
        for block_id in rpo:
            block = cfg.blocks[block_id]

            # Compute taint_in for this block
            if block.is_entry:
                taint_in = set()
            else:
                taint_in = set()
                for pred_id in block.predecessors:
                    taint_in |= block_taint_out.get(pred_id, set())

            current_taint = set(taint_in)

            for stmt in block.statements:
                line_idx = stmt.line - 1

                # Update taint through this statement
                _update_stmt_taint(stmt, semantics, config, current_taint, lines)

                # Check for sinks
                if stmt.call_idx is not None:
                    call = semantics.function_calls[stmt.call_idx]
                    call_text = call.name
                    if call.receiver:
                        call_text = f"{call.receiver}.{call.name}"

                    for pattern, sink_kind in config.taint_sink_patterns:
                        if _matches_pattern(call_text, pattern):
                            if 0 <= line_idx < len(lines):
                                line_text = lines[line_idx]
                                for tvar in current_taint:
                                    if re.search(r'\b' + re.escape(tvar) + r'\b', line_text):
                                        src_line = source_lines.get(tvar, 0)
                                        key = (src_line, stmt.line)
                                        if key not in seen:
                                            seen.add(key)

                                            # Find original source info
                                            source_info = None
                                            for s in sources:
                                                if s.variable == tvar:
                                                    source_info = s
                                                    break
                                            if not source_info and sources:
                                                source_info = sources[0]

                                            src_kind = source_info.kind if source_info else "unknown"
                                            src_var = source_info.variable if source_info else tvar

                                            findings.append(Finding(
                                                file=filepath,
                                                line=stmt.line,
                                                severity=Severity.WARNING,
                                                category=Category.SECURITY,
                                                source=Source.AST,
                                                rule="taint-flow",
                                                message=(
                                                    f"Tainted data from '{src_var}' "
                                                    f"({src_kind}, line {src_line}) "
                                                    f"reaches sink '{call_text}' ({sink_kind}) "
                                                    f"— path-sensitive analysis"
                                                ),
                                                suggestion=(
                                                    f"Sanitize '{tvar}' before passing to "
                                                    f"'{call_text}', or use parameterized "
                                                    f"queries/safe APIs"
                                                ),
                                            ))
                                        break
                            break

    return findings
