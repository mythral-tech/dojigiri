"""Intra-procedural taint analysis: track tainted data from sources to sinks.

Two modes:
1. Flow-insensitive (v0.8.0): analyze_taint() — used as fallback when no CFG.
2. Path-sensitive (v0.9.0): analyze_taint_pathsensitive() — uses CFG for
   precise dataflow, properly handles sanitization on conditional paths.

Operates on FileSemantics + source bytes for pattern matching.
Returns [] when tree-sitter is not available.

Called by: detector.py
Calls into: config.py, semantic/lang_config.py, semantic/core.py, semantic/cfg.py
Data in → Data out: FileSemantics + CFG → list[Finding] (injection vulnerabilities)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..types import Category, Finding, Severity, Source
from .core import FileSemantics, ScopeInfo
from .lang_config import LanguageConfig

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
    scope_id: int = 0


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    through: list[tuple[str, int]]  # (variable_name, line) assignment chain


# ─── Branch sibling detection ─────────────────────────────────────────


@dataclass
class _BranchRange:
    """A branch body (if/elif/else) with its line range."""
    start_line: int
    end_line: int


@dataclass
class _ConditionalBody:
    """Any conditional body (if-branch, loop body) where execution is not guaranteed."""
    start_line: int
    end_line: int
    kind: str  # "branch" or "loop"


def _collect_branch_siblings(tree_root) -> list[list[_BranchRange]]:
    """Walk the AST and collect groups of sibling branch ranges.

    Each group is a list of _BranchRange representing mutually exclusive
    branches of the same conditional (e.g. if-body, elif-body, else-body).

    Works with the cached tree-sitter root node from FileSemantics._tree_root.
    """
    if tree_root is None:
        return []

    groups: list[list[_BranchRange]] = []

    def _walk(node):
        # Python: if_statement has consequence (block) and alternative (elif/else)
        # JS: if_statement has consequence (statement_block) and alternative
        if node.type == "if_statement":
            branches: list[_BranchRange] = []
            _collect_if_branches(node, branches)
            if len(branches) >= 2:
                groups.append(branches)

        for child in node.children:
            # Don't recurse into branches we already processed as part of
            # elif chains — those are handled by _collect_if_branches
            if child.type not in ("elif_clause", "else_clause"):
                _walk(child)

    def _collect_if_branches(node, branches: list[_BranchRange]):
        """Recursively collect all branches of an if/elif/else chain."""
        # Find the consequence block (the "then" body)
        consequence = node.child_by_field_name("consequence")
        if consequence:
            branches.append(_BranchRange(
                start_line=consequence.start_point[0] + 1,
                end_line=consequence.end_point[0] + 1,
            ))

        # Find the alternative (elif or else)
        alternative = node.child_by_field_name("alternative")
        if alternative:
            if alternative.type in ("elif_clause", "else_clause", "else"):
                # For elif: recurse to get its branches
                if alternative.type == "elif_clause":
                    _collect_if_branches(alternative, branches)
                else:
                    # else clause — find the body block
                    body = alternative.child_by_field_name("body") or alternative.child_by_field_name("consequence")
                    if body:
                        branches.append(_BranchRange(
                            start_line=body.start_point[0] + 1,
                            end_line=body.end_point[0] + 1,
                        ))
                    else:
                        # Fallback: use the else clause itself (minus the keyword)
                        for child in alternative.children:
                            if child.type in ("block", "statement_block"):
                                branches.append(_BranchRange(
                                    start_line=child.start_point[0] + 1,
                                    end_line=child.end_point[0] + 1,
                                ))
                                break
            elif alternative.type == "if_statement":
                # JS-style else if: else { if ... }
                _collect_if_branches(alternative, branches)

    _walk(tree_root)
    return groups


def _collect_conditional_bodies(tree_root) -> list[_ConditionalBody]:
    """Walk the AST and collect ALL conditional bodies: if-branches, loop bodies.

    Any code region where execution is not guaranteed gets a _ConditionalBody
    entry. This includes:
    - if/elif consequence blocks (may not execute if condition is false)
    - for/while loop bodies (may execute 0 times)

    Used to determine if a sanitizer is in a conditional context that a sink
    is outside of — meaning the sanitizer may not have executed.
    """
    if tree_root is None:
        return []

    bodies: list[_ConditionalBody] = []

    def _walk(node):
        if node.type == "if_statement":
            # Collect the consequence (then-body) as conditional
            consequence = node.child_by_field_name("consequence")
            if consequence:
                bodies.append(_ConditionalBody(
                    start_line=consequence.start_point[0] + 1,
                    end_line=consequence.end_point[0] + 1,
                    kind="branch",
                ))
            # Collect elif bodies
            alternative = node.child_by_field_name("alternative")
            if alternative and alternative.type == "elif_clause":
                _walk_elif(alternative)
            elif alternative and alternative.type in ("else_clause", "else"):
                # else body is also conditional (only runs if all prior conditions false)
                body = alternative.child_by_field_name("body") or alternative.child_by_field_name("consequence")
                if body:
                    bodies.append(_ConditionalBody(
                        start_line=body.start_point[0] + 1,
                        end_line=body.end_point[0] + 1,
                        kind="branch",
                    ))
                else:
                    for child in alternative.children:
                        if child.type in ("block", "statement_block"):
                            bodies.append(_ConditionalBody(
                                start_line=child.start_point[0] + 1,
                                end_line=child.end_point[0] + 1,
                                kind="branch",
                            ))
                            break

        elif node.type in ("for_statement", "while_statement"):
            # Loop bodies may execute 0 times
            body = node.child_by_field_name("body")
            if body:
                bodies.append(_ConditionalBody(
                    start_line=body.start_point[0] + 1,
                    end_line=body.end_point[0] + 1,
                    kind="loop",
                ))

        for child in node.children:
            _walk(child)

    def _walk_elif(node):
        """Process elif clause bodies."""
        consequence = node.child_by_field_name("consequence")
        if consequence:
            bodies.append(_ConditionalBody(
                start_line=consequence.start_point[0] + 1,
                end_line=consequence.end_point[0] + 1,
                kind="branch",
            ))
        alternative = node.child_by_field_name("alternative")
        if alternative and alternative.type == "elif_clause":
            _walk_elif(alternative)
        elif alternative and alternative.type in ("else_clause", "else"):
            body = alternative.child_by_field_name("body") or alternative.child_by_field_name("consequence")
            if body:
                bodies.append(_ConditionalBody(
                    start_line=body.start_point[0] + 1,
                    end_line=body.end_point[0] + 1,
                    kind="branch",
                ))

    _walk(tree_root)
    return bodies


def _are_in_sibling_branches(
    line_a: int,
    line_b: int,
    branch_groups: list[list[_BranchRange]],
) -> bool:
    """Check if two lines are in different (sibling) branches of the same conditional."""
    for group in branch_groups:
        branch_of_a = None
        branch_of_b = None
        for i, br in enumerate(group):
            if br.start_line <= line_a <= br.end_line:
                branch_of_a = i
            if br.start_line <= line_b <= br.end_line:
                branch_of_b = i
        if branch_of_a is not None and branch_of_b is not None and branch_of_a != branch_of_b:
            return True
    return False


def _is_in_conditional_body_not_containing(
    sanitizer_line: int,
    other_line: int,
    conditional_bodies: list[_ConditionalBody],
) -> bool:
    """Check if sanitizer_line is inside a conditional body that does NOT contain other_line.

    This handles:
    - Sanitizer in a loop body, sink outside the loop → sanitizer may not execute
    - Sanitizer in a nested if (if A: if B: sanitize), sink outside → sanitizer may not execute
    - Arbitrary nesting depth: checks ALL conditional bodies containing the sanitizer

    Returns True if the sanitizer is in at least one conditional body that the
    sink/other_line is NOT in — meaning the sanitizer's execution is not guaranteed
    from the perspective of the sink.
    """
    for body in conditional_bodies:
        if body.start_line <= sanitizer_line <= body.end_line:
            if not (body.start_line <= other_line <= body.end_line):
                return True
    return False


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
                sources.append(
                    TaintSource(
                        variable=asgn.name,
                        line=asgn.line,
                        kind=kind,
                    )
                )
                break

    return sources


def _propagate_taint(
    semantics: FileSemantics,
    initial_tainted: set[str],
    func_scope_ids: set[int],
    config: LanguageConfig,
    branch_groups: list[list[_BranchRange]] | None = None,
    conditional_bodies: list[_ConditionalBody] | None = None,
) -> dict[str, list[tuple[str, int]]]:
    """Propagate taint through assignments within function scope.

    Returns: {tainted_var: [(source_var, line), ...]} chain.

    Branch-aware (v0.10): sanitizers inside a conditional branch do NOT
    clear taint globally — they might not execute on all paths.  A sanitizer
    only clears taint if it is NOT inside any branch or loop body.
    """
    tainted: dict[str, list[tuple[str, int]]] = {name: [] for name in initial_tainted}

    # Propagation with sanitization: if RHS contains a tainted variable, LHS
    # becomes tainted — UNLESS the RHS passes through a sanitizer, in which
    # case taint is removed (flow-sensitive reassignment).
    # Sort by line to ensure source-order propagation (assignments may not
    # be in source order in the semantics list).
    # Iterate until fixed-point.
    scoped_assignments = sorted(
        [a for a in semantics.assignments if a.scope_id in func_scope_ids and not a.is_parameter],
        key=lambda a: a.line,
    )
    changed = True
    max_iters = 10  # prevent infinite loops
    iteration = 0

    while changed and iteration < max_iters:
        changed = False
        iteration += 1

        for asgn in scoped_assignments:
            rhs = asgn.value_text

            # Check if RHS passes through a sanitizer
            is_sanitized = any(sanitizer in rhs for sanitizer in config.taint_sanitizer_patterns)

            if is_sanitized:
                # Branch/loop-aware: only clear taint if the sanitizer is NOT
                # inside any conditional body (branch or loop).  A sanitizer
                # inside an if/else/for/while body might not execute on all paths.
                in_conditional = False
                if conditional_bodies:
                    for body in conditional_bodies:
                        if body.start_line <= asgn.line <= body.end_line:
                            in_conditional = True
                            break
                # Fallback to legacy branch_groups check
                if not in_conditional and branch_groups:
                    for group in branch_groups:
                        for br in group:
                            if br.start_line <= asgn.line <= br.end_line:
                                in_conditional = True
                                break
                        if in_conditional:
                            break
                if not in_conditional:
                    # Sanitizer at top level of function — clears taint
                    if asgn.name in tainted:
                        del tainted[asgn.name]
                        changed = True
                # If sanitizer is in a conditional body, don't clear taint globally.
                continue

            # Skip already-tainted vars for propagation (no new info)
            if asgn.name in tainted:
                continue

            for tainted_name in list(tainted.keys()):
                # Check if tainted name appears in RHS
                if re.search(r"\b" + re.escape(tainted_name) + r"\b", rhs):
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
                        if re.search(r"\b" + re.escape(tvar) + r"\b", line_text):
                            sinks.append(
                                TaintSink(
                                    variable=tvar,
                                    line=call.line,
                                    kind=kind,
                                    function_name=call_text,
                                    scope_id=call.scope_id,
                                )
                            )
                            break
                break

    return sinks


def _is_ancestor_scope(
    ancestor_id: int,
    descendant_id: int,
    scope_map: dict[int, ScopeInfo],
) -> bool:
    """Check if ancestor_id is an ancestor of (or equal to) descendant_id in the scope tree."""
    current = descendant_id
    visited: set[int] = set()
    while current in scope_map:
        if current in visited:
            break
        if current == ancestor_id:
            return True
        visited.add(current)
        parent = scope_map[current].parent_id
        if parent is None:
            break
        current = parent
    return False


def _build_scope_map(semantics: FileSemantics) -> dict[int, ScopeInfo]:
    """Build scope_id → ScopeInfo lookup."""
    return {s.scope_id: s for s in semantics.scopes}


def _is_sanitized(
    semantics: FileSemantics,
    config: LanguageConfig,
    tainted_var: str,
    func_scope_ids: set[int],
    sink_line: int = 0,
    sink_scope_id: int | None = None,
    scope_map: dict[int, ScopeInfo] | None = None,
    branch_groups: list[list[_BranchRange]] | None = None,
    conditional_bodies: list[_ConditionalBody] | None = None,
) -> bool:
    """Check if a tainted variable passes through a sanitizer before *sink_line*.

    Only sanitization that occurs *before* the sink counts — a sanitizer
    applied after the dangerous call is irrelevant.

    Branch-aware (v0.10): a sanitizer in a sibling branch of the sink does
    NOT suppress the finding.  Uses both scope dominance (for block-scoped
    languages) and AST branch ranges (for Python and others without block
    scoping).

    Loop/nesting-aware (v0.11): a sanitizer inside any conditional body
    (branch or loop) that the sink is NOT in is treated as conditional —
    it may not have executed.  This handles:
    - Sanitizers inside for/while loops (0 iterations possible)
    - Sanitizers in nested branches (if A: if B: sanitize)
    """
    for asgn in semantics.assignments:
        if asgn.scope_id not in func_scope_ids:
            continue
        if asgn.name != tainted_var:
            continue
        if sink_line and asgn.line >= sink_line:
            continue
        # Scope dominance check (block-scoped languages like JS/Go/Rust)
        if sink_scope_id is not None and scope_map is not None:
            if not _is_ancestor_scope(asgn.scope_id, sink_scope_id, scope_map):
                continue
        # Branch sibling check (all languages, especially Python)
        if branch_groups and sink_line:
            if _are_in_sibling_branches(asgn.line, sink_line, branch_groups):
                continue
        # Conditional body check: sanitizer in a branch/loop body that the
        # sink is NOT in → sanitizer may not have executed
        if conditional_bodies and sink_line:
            if _is_in_conditional_body_not_containing(asgn.line, sink_line, conditional_bodies):
                continue
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in asgn.value_text:
                return True

    # Also check if sanitizer is called on the variable in any call
    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue
        if sink_line and call.line >= sink_line:
            continue
        # Scope dominance check for call-based sanitizers
        if sink_scope_id is not None and scope_map is not None:
            if not _is_ancestor_scope(call.scope_id, sink_scope_id, scope_map):
                continue
        # Branch sibling check for call-based sanitizers
        if branch_groups and sink_line:
            if _are_in_sibling_branches(call.line, sink_line, branch_groups):
                continue
        # Conditional body check for call-based sanitizers
        if conditional_bodies and sink_line:
            if _is_in_conditional_body_not_containing(call.line, sink_line, conditional_bodies):
                continue
        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in call_text:
                return True

    return False


def _process_assignment_taint(
    asgn,
    config: LanguageConfig,
    current_taint: set[str],
    source_vars: set[str] | None = None,
    source_lines: dict[str, int] | None = None,
) -> None:
    """Process a single assignment for taint propagation/sanitization."""
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
            if re.search(r"\b" + re.escape(tvar) + r"\b", rhs):
                current_taint.add(asgn.name)
                break

    for sanitizer in config.taint_sanitizer_patterns:
        if sanitizer in rhs:
            current_taint.discard(asgn.name)
            break


def _process_call_taint(
    call,
    config: LanguageConfig,
    current_taint: set[str],
    line_idx: int,
    lines: list[str],
) -> None:
    """Process a single call for sanitizer detection."""
    call_text = call.name
    if call.receiver:
        call_text = f"{call.receiver}.{call.name}"
    for sanitizer in config.taint_sanitizer_patterns:
        if sanitizer in call_text:
            if 0 <= line_idx < len(lines):
                line_text = lines[line_idx]
                for tvar in list(current_taint):
                    if re.search(r"\b" + re.escape(tvar) + r"\b", line_text):
                        current_taint.discard(tvar)


def _update_stmt_taint(
    stmt,
    semantics: FileSemantics,
    config: LanguageConfig,
    current_taint: set[str],
    lines: list[str],
    source_vars: set[str] | None = None,
    source_lines: dict[str, int] | None = None,
) -> None:
    """Update current_taint in-place for a single CFG statement.

    Handles multiple assignments/calls on the same line via extra_*_idxs.
    """
    # Process all assignments on this line (primary + extras)
    asgn_idxs = []
    if stmt.assignment_idx is not None:
        asgn_idxs.append(stmt.assignment_idx)
    asgn_idxs.extend(getattr(stmt, "extra_assignment_idxs", []))

    for aidx in asgn_idxs:
        asgn = semantics.assignments[aidx]
        _process_assignment_taint(asgn, config, current_taint, source_vars, source_lines)

    # Process all calls on this line (primary + extras)
    call_idxs = []
    if stmt.call_idx is not None:
        call_idxs.append(stmt.call_idx)
    call_idxs.extend(getattr(stmt, "extra_call_idxs", []))

    line_idx = stmt.line - 1
    for cidx in call_idxs:
        call = semantics.function_calls[cidx]
        _process_call_taint(call, config, current_taint, line_idx, lines)


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
    scope_map = _build_scope_map(semantics)

    # Build branch sibling ranges from the AST for scope-aware sanitization
    tree_root = getattr(semantics, "_tree_root", None)
    branch_groups = _collect_branch_siblings(tree_root)
    conditional_bodies = _collect_conditional_bodies(tree_root)

    for func_scope in func_scopes:
        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        # 1. Find sources
        sources = _find_taint_sources(semantics, config, source_bytes, func_scope_ids)
        if not sources:
            continue

        # 2. Propagate taint (branch-aware: sanitizers in conditional branches
        #    don't clear taint globally)
        initial_tainted = {s.variable for s in sources}
        taint_chains = _propagate_taint(
            semantics, initial_tainted, func_scope_ids, config,
            branch_groups=branch_groups,
            conditional_bodies=conditional_bodies,
        )
        tainted_vars = set(taint_chains.keys())

        if not tainted_vars:
            continue

        # 3. Find sinks
        sinks = _find_taint_sinks(semantics, config, tainted_vars, func_scope_ids, source_bytes)

        # 4. Build findings
        for sink in sinks:
            # Check sanitization (scope-aware: sanitizer must dominate sink scope)
            if _is_sanitized(
                semantics, config, sink.variable, func_scope_ids,
                sink_line=sink.line, sink_scope_id=sink.scope_id,
                scope_map=scope_map, branch_groups=branch_groups,
                conditional_bodies=conditional_bodies,
            ):
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

            findings.append(
                Finding(
                    file=filepath,
                    line=sink.line,
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    source=Source.AST,
                    rule="taint-flow",
                    message=(
                        f"Tainted data from '{source.variable}' ({source.kind}, line {source.line}) "
                        f"reaches sink '{sink.function_name}' ({sink.kind}){chain_desc} — "
                        "verify sanitization"
                    ),
                    suggestion=(
                        f"Sanitize '{sink.variable}' before passing to '{sink.function_name}', "
                        "or use parameterized queries/safe APIs"
                    ),
                )
            )

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
    from .cfg import get_reverse_postorder

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
                        stmt,
                        semantics,
                        config,
                        current_taint,
                        lines,
                        source_vars=source_vars,
                        source_lines=source_lines,
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

                # Check for sinks (all calls on this line)
                sink_call_idxs = []
                if stmt.call_idx is not None:
                    sink_call_idxs.append(stmt.call_idx)
                sink_call_idxs.extend(getattr(stmt, "extra_call_idxs", []))

                for _cidx in sink_call_idxs:
                    call = semantics.function_calls[_cidx]
                    call_text = call.name
                    if call.receiver:
                        call_text = f"{call.receiver}.{call.name}"

                    for pattern, sink_kind in config.taint_sink_patterns:
                        if _matches_pattern(call_text, pattern):
                            if 0 <= line_idx < len(lines):
                                line_text = lines[line_idx]
                                for tvar in current_taint:
                                    if re.search(r"\b" + re.escape(tvar) + r"\b", line_text):
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

                                            findings.append(
                                                Finding(
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
                                                        "— path-sensitive analysis"
                                                    ),
                                                    suggestion=(
                                                        f"Sanitize '{tvar}' before passing to "
                                                        f"'{call_text}', or use parameterized "
                                                        "queries/safe APIs"
                                                    ),
                                                )
                                            )
                                        break
                            break

    return findings
