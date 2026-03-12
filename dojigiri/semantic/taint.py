"""Taint analysis: track tainted data from sources to sinks.

Two modes:
1. Flow-insensitive (v0.8.0): analyze_taint() — used as fallback when no CFG.
2. Path-sensitive (v0.9.0): analyze_taint_pathsensitive() — uses CFG for
   precise dataflow, properly handles sanitization on conditional paths.

Both modes support same-file inter-procedural analysis (v1.2.0): a pre-pass
builds method summaries capturing whether each function propagates taint from
parameters to return values.  Calls to methods that always return constants
or don't propagate taint are resolved without false-positive taint flow.

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

# ─── Sink kind → rule name mapping ────────────────────────────────────
# Maps taint sink kinds to specific rule names that align with CWE categories.
# Language-specific overrides take precedence over generic mappings.
_GENERIC_SINK_RULES: dict[str, str] = {
    "sql_query": "sql-injection",
    "system_cmd": "os-system",
    "file_path": "path-traversal",
    "eval": "eval-usage",
    "html_output": "xss",
    "ssrf": "ssrf",
    "llm_input": "llm-prompt-injection",
}
_JAVA_SINK_RULES: dict[str, str] = {
    "sql_query": "java-sql-injection",
    "system_cmd": "java-cmdi",
    "ldap_query": "java-ldap-injection",
    "xpath_query": "java-xpath-injection",
    "file_path": "java-path-traversal",
    "http_response": "java-xss",
    "http_redirect": "java-xss",
    "http_header": "java-xss",
    "http_cookie": "java-insecure-cookie",
    "trust_boundary": "java-trust-boundary",
}
_LANG_SINK_RULES: dict[str, dict[str, str]] = {
    "java": _JAVA_SINK_RULES,
}


def _resolve_taint_rule(sink_kind: str, language: str = "") -> str:
    """Get the CWE-aligned rule name for a taint sink kind."""
    lang_map = _LANG_SINK_RULES.get(language, {})
    return lang_map.get(sink_kind) or _GENERIC_SINK_RULES.get(sink_kind, "taint-flow")

# ─── Data structures ─────────────────────────────────────────────────


@dataclass
class TaintSource:
    variable: str
    line: int
    kind: str  # "user_input", "file_read", "network", "env_var", "llm_output"


@dataclass
class TaintSink:
    variable: str
    line: int
    kind: str  # "sql_query", "eval", "system_cmd", "html_output", "llm_input"
    function_name: str
    scope_id: int = 0


@dataclass
class TaintPath:
    source: TaintSource
    sink: TaintSink
    through: list[tuple[str, int]]  # (variable_name, line) assignment chain


@dataclass
class TaintSummary:
    """Summary of a method's taint behavior for inter-procedural analysis."""

    propagates_taint: bool  # Does tainted param reach return?
    sanitizes: bool  # Does the method apply sanitizers?
    safe_return: bool  # Does it always return a constant/literal?


@dataclass
class TaintContext:
    """Shared context for taint analysis functions, reducing parameter passing."""

    semantics: FileSemantics
    config: LanguageConfig
    lines: list[str]
    filepath: str
    method_summaries: dict[str, TaintSummary] | None = None
    source_vars: set[str] | None = None
    source_lines: dict[str, int] | None = None


# ─── Collection-aware taint tracking ─────────────────────────────────
# Reduces false positives when tainted data enters a collection (Map/List)
# under a specific key/index but is read back under a different key/index.

# Regex patterns for Java Map operations
_RE_MAP_PUT = re.compile(r"(\w+)\s*\.\s*put\s*\(\s*\"([^\"]+)\"")
_RE_MAP_GET = re.compile(r"(\w+)\s*\.\s*get\s*\(\s*\"([^\"]+)\"")
# Regex patterns for Java List operations
_RE_LIST_ADD = re.compile(r"(\w+)\s*\.\s*add\s*\(")
_RE_LIST_CLEAR = re.compile(r"(\w+)\s*\.\s*(?:clear|removeAll)\s*\(")


@dataclass
class _CollectionTaintState:
    """Tracks per-key taint state for collections (Maps and Lists).

    map_taint: {collection_var: {key: is_tainted}} for Map key tracking.
    list_has_taint: {collection_var: True} for List taint tracking.
    """
    map_taint: dict[str, dict[str, bool]]
    list_has_taint: dict[str, bool]

    @staticmethod
    def empty() -> _CollectionTaintState:
        return _CollectionTaintState(map_taint={}, list_has_taint={})

    def copy(self) -> _CollectionTaintState:
        return _CollectionTaintState(
            map_taint={k: dict(v) for k, v in self.map_taint.items()},
            list_has_taint=dict(self.list_has_taint),
        )

    def merge(self, other: _CollectionTaintState) -> _CollectionTaintState:
        """Union merge for CFG join points (conservative: any-tainted wins)."""
        merged_map: dict[str, dict[str, bool]] = {}
        for coll_var in set(self.map_taint) | set(other.map_taint):
            keys_self = self.map_taint.get(coll_var, {})
            keys_other = other.map_taint.get(coll_var, {})
            merged_keys = dict(keys_self)
            for k, v in keys_other.items():
                merged_keys[k] = merged_keys.get(k, False) or v
            merged_map[coll_var] = merged_keys
        merged_list: dict[str, bool] = {}
        for coll_var in set(self.list_has_taint) | set(other.list_has_taint):
            merged_list[coll_var] = (
                self.list_has_taint.get(coll_var, False)
                or other.list_has_taint.get(coll_var, False)
            )
        return _CollectionTaintState(map_taint=merged_map, list_has_taint=merged_list)


def _track_collection_put(
    full_line: str,
    tainted_vars: set[str],
    coll_state: _CollectionTaintState,
) -> None:
    """Detect map.put/list.add and update collection taint state."""
    for m in _RE_MAP_PUT.finditer(full_line):
        coll_var = m.group(1)
        key = m.group(2)
        put_start = m.end()
        remainder = full_line[put_start:]
        is_value_tainted = any(
            re.search(r"\b" + re.escape(tv) + r"\b", remainder)
            for tv in tainted_vars
        )
        coll_state.map_taint.setdefault(coll_var, {})[key] = is_value_tainted

    for m in _RE_LIST_ADD.finditer(full_line):
        coll_var = m.group(1)
        add_start = m.end()
        depth = 1
        end = add_start
        while end < len(full_line) and depth > 0:
            if full_line[end] == "(":
                depth += 1
            elif full_line[end] == ")":
                depth -= 1
            end += 1
        arg_text = full_line[add_start:end]
        if any(re.search(r"\b" + re.escape(tv) + r"\b", arg_text) for tv in tainted_vars):
            coll_state.list_has_taint[coll_var] = True

    for m in _RE_LIST_CLEAR.finditer(full_line):
        coll_state.list_has_taint.pop(m.group(1), None)


def _check_collection_get_taint(
    rhs: str,
    coll_state: _CollectionTaintState,
) -> bool | None:
    """Check if map.get/list.get in RHS refers to a tainted slot.

    Returns True (tainted), False (not tainted), or None (no collection op found).
    """
    mg = _RE_MAP_GET.search(rhs)
    if mg:
        coll_var = mg.group(1)
        key = mg.group(2)
        if coll_var in coll_state.map_taint:
            return coll_state.map_taint[coll_var].get(key, False)
        return None

    list_get_m = re.search(r"(\w+)\s*\.\s*get\s*\(", rhs)
    if list_get_m:
        coll_var = list_get_m.group(1)
        if coll_var in coll_state.list_has_taint:
            return coll_state.list_has_taint[coll_var]
        return None

    return None


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

    def _walk(node: object) -> None:
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

    def _collect_if_branches(node: object, branches: list[_BranchRange]) -> None:
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


def _collect_else_body(alternative, bodies: list[_ConditionalBody]) -> None:
    """Collect an else clause body as a conditional branch."""
    body = alternative.child_by_field_name("body") or alternative.child_by_field_name("consequence")
    if body:
        bodies.append(_ConditionalBody(
            start_line=body.start_point[0] + 1,
            end_line=body.end_point[0] + 1,
            kind="branch",
        ))
        return
    for child in alternative.children:
        if child.type in ("block", "statement_block"):
            bodies.append(_ConditionalBody(
                start_line=child.start_point[0] + 1,
                end_line=child.end_point[0] + 1,
                kind="branch",
            ))
            break


def _collect_if_body(node, bodies: list[_ConditionalBody], walk_elif_fn) -> None:
    """Collect if-statement consequence and alternative bodies."""
    consequence = node.child_by_field_name("consequence")
    if consequence:
        bodies.append(_ConditionalBody(
            start_line=consequence.start_point[0] + 1,
            end_line=consequence.end_point[0] + 1,
            kind="branch",
        ))
    alternative = node.child_by_field_name("alternative")
    if alternative and alternative.type == "elif_clause":
        walk_elif_fn(alternative)
    elif alternative and alternative.type in ("else_clause", "else"):
        _collect_else_body(alternative, bodies)


def _collect_body_as(node, bodies: list[_ConditionalBody], kind: str) -> None:
    """Collect a node's body field as a conditional body of the given kind."""
    body = node.child_by_field_name("body")
    if body:
        bodies.append(_ConditionalBody(
            start_line=body.start_point[0] + 1,
            end_line=body.end_point[0] + 1,
            kind=kind,
        ))


def _collect_conditional_bodies(tree_root) -> list[_ConditionalBody]:
    """Walk the AST and collect ALL conditional bodies: if-branches, loop bodies, try bodies.

    Any code region where execution is not guaranteed gets a _ConditionalBody
    entry. This includes:
    - if/elif consequence blocks (may not execute if condition is false)
    - for/while loop bodies (may execute 0 times)
    - try block bodies (a line may throw before a subsequent line executes)

    Used to determine if a sanitizer is in a conditional context that a sink
    is outside of — meaning the sanitizer may not have executed.
    """
    if tree_root is None:
        return []

    bodies: list[_ConditionalBody] = []

    def _walk_elif(node: object) -> None:
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
            _collect_else_body(alternative, bodies)

    def _walk(node: object) -> None:
        if node.type == "if_statement":
            _collect_if_body(node, bodies, _walk_elif)
        elif node.type in ("for_statement", "while_statement"):
            _collect_body_as(node, bodies, "loop")
        elif node.type == "try_statement":
            _collect_body_as(node, bodies, "try")

        for child in node.children:
            _walk(child)

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


def _is_in_conditional_body_not_containing_any(
    sanitizer_line: int,
    other_lines: set[int],
    conditional_bodies: list[_ConditionalBody],
) -> bool:
    """Check if sanitizer_line is in a conditional body that excludes ALL other_lines.

    Returns True if the sanitizer is in at least one conditional body where
    NONE of the other_lines are contained — meaning the sanitizer's execution
    is not guaranteed from the perspective of any sink.

    If other_lines is empty, falls back to checking if the sanitizer is in
    any conditional body at all (conservative).
    """
    if not other_lines:
        # No sink info available — conservative: any conditional body blocks clearance
        for body in conditional_bodies:
            if body.start_line <= sanitizer_line <= body.end_line:
                return True
        return False

    for body in conditional_bodies:
        if body.start_line <= sanitizer_line <= body.end_line:
            # Check if ANY sink line is outside this body
            if any(not (body.start_line <= ol <= body.end_line) for ol in other_lines):
                return True
    return False


# ─── Constant propagation ─────────────────────────────────────────────

# Ternary pattern: condition ? true_expr : false_expr
_TERNARY_RE = re.compile(
    r"^(.*?)\s*\?\s*(.*?)\s*:\s*(.*)$",
)

# Integer literal pattern
_INT_LITERAL_RE = re.compile(r"^-?\d+$")

# String literal pattern (double or single quoted)
_STRING_LITERAL_RE = re.compile(r'^"[^"]*"$|^\'[^\']*\'$')

# Arithmetic token pattern for safe evaluation
_ARITH_TOKEN_RE = re.compile(r"(-?\d+|[+\-*/%()]|\s+)")


def _safe_eval_arithmetic(expr: str) -> int | None:
    """Safely evaluate a pure integer arithmetic expression.

    Supports: +, -, *, /, %, parentheses, integer literals.
    Returns None if the expression contains anything unexpected.
    Uses regex tokenization -- never calls eval().
    """
    expr = expr.strip()
    if not expr:
        return None

    # Tokenize and verify every character is accounted for
    tokens = _ARITH_TOKEN_RE.findall(expr)
    reconstructed = "".join(tokens)
    if reconstructed.replace(" ", "") != expr.replace(" ", ""):
        return None

    meaningful = [t.strip() for t in tokens if t.strip()]
    if not meaningful:
        return None

    try:
        result, pos = _parse_expr(meaningful, 0)
        if pos != len(meaningful):
            return None
        return result
    except (ValueError, ZeroDivisionError, IndexError):
        return None


def _parse_expr(tokens: list[str], pos: int) -> tuple[int, int]:
    """Parse additive expression: term ((+|-) term)*"""
    left, pos = _parse_term(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ("+", "-"):
        op = tokens[pos]
        pos += 1
        right, pos = _parse_term(tokens, pos)
        if op == "+":
            left = left + right
        else:
            left = left - right
    return left, pos


def _parse_term(tokens: list[str], pos: int) -> tuple[int, int]:
    """Parse multiplicative expression: factor ((*|/|%) factor)*"""
    left, pos = _parse_factor(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ("*", "/", "%"):
        op = tokens[pos]
        pos += 1
        right, pos = _parse_factor(tokens, pos)
        if op == "*":
            left = left * right
        elif op == "/":
            if right == 0:
                raise ZeroDivisionError
            left = left // right
        else:
            if right == 0:
                raise ZeroDivisionError
            left = left % right
    return left, pos


def _parse_factor(tokens: list[str], pos: int) -> tuple[int, int]:
    """Parse factor: integer | '(' expr ')' | unary minus"""
    if pos >= len(tokens):
        raise ValueError("unexpected end")

    if tokens[pos] == "-":
        pos += 1
        val, pos = _parse_factor(tokens, pos)
        return -val, pos

    if tokens[pos] == "(":
        pos += 1
        val, pos = _parse_expr(tokens, pos)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ValueError("missing )")
        return val, pos + 1

    try:
        return int(tokens[pos]), pos + 1
    except ValueError:
        raise ValueError(f"unexpected token: {tokens[pos]}")  # noqa — not a secret


def _evaluate_constant_condition(
    rhs: str,
    assignments: list,
    func_scope_ids: set[int],
) -> bool | None:
    """Try to evaluate a condition expression to a constant boolean.

    Substitutes known constant variables into the expression, then
    evaluates arithmetic and comparisons.

    Returns True if always true, False if always false, None if unresolvable.
    """
    constants: dict[str, int] = {}
    for asgn in assignments:
        if asgn.scope_id not in func_scope_ids:
            continue
        if asgn.is_parameter:
            continue
        val_text = asgn.value_text.strip()
        if _INT_LITERAL_RE.match(val_text):
            constants[asgn.name] = int(val_text)

    return _eval_condition_with_constants(rhs, constants)


def _eval_condition_with_constants(
    condition: str,
    constants: dict[str, int],
) -> bool | None:
    """Evaluate a condition string given known integer constants.

    Handles: arithmetic (+, -, *, /, %), comparisons (>, <, >=, <=, ==, !=).
    Returns True/False if fully resolvable, None otherwise.
    """
    condition = condition.strip()
    if not condition:
        return None

    # Strip outer parens if the whole expression is wrapped
    if condition.startswith("(") and condition.endswith(")"):
        depth = 0
        all_wrapped = True
        for i, ch in enumerate(condition):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth == 0 and i < len(condition) - 1:
                all_wrapped = False
                break
        if all_wrapped:
            inner = _eval_condition_with_constants(condition[1:-1], constants)
            if inner is not None:
                return inner

    comp_match = _find_toplevel_comparison(condition)
    if comp_match is None:
        return None

    left_str, op, right_str = comp_match

    left_str = _substitute_constants(left_str, constants)
    right_str = _substitute_constants(right_str, constants)

    left_val = _safe_eval_arithmetic(left_str)
    right_val = _safe_eval_arithmetic(right_str)

    if left_val is None or right_val is None:
        return None

    if op == ">":
        return left_val > right_val
    elif op == "<":
        return left_val < right_val
    elif op == ">=":
        return left_val >= right_val
    elif op == "<=":
        return left_val <= right_val
    elif op == "==":
        return left_val == right_val
    elif op == "!=":
        return left_val != right_val

    return None


def _find_toplevel_comparison(expr: str) -> tuple[str, str, str] | None:
    """Find a comparison operator at the top level (not inside parentheses)."""
    depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            two_char = expr[i:i + 2]
            if two_char in (">=", "<=", "!=", "=="):
                return (expr[:i].strip(), two_char, expr[i + 2:].strip())
            if ch in (">", "<"):
                if i + 1 < len(expr) and expr[i + 1] == "=":
                    pass
                else:
                    return (expr[:i].strip(), ch, expr[i + 1:].strip())
        i += 1
    return None


def _substitute_constants(expr: str, constants: dict[str, int]) -> str:
    """Replace known constant variable names with their integer values."""
    for name, value in constants.items():
        expr = re.sub(r"\b" + re.escape(name) + r"\b", str(value), expr)
    return expr


def _extract_ternary(rhs: str) -> tuple[str, str, str] | None:
    """Extract (condition, true_expr, false_expr) from a ternary expression.

    Handles nested parens in the condition. Returns None if not a ternary.
    Supports cast-wrapped ternary like: (type) (cond ? true : false)
    """
    text = rhs.strip()

    # Strip a leading cast like "(int)" or "(String)"
    cast_match = re.match(r"^\(\s*\w+\s*\)\s*", text)
    if cast_match:
        text = text[cast_match.end():]

    # Try the regex first for simple cases
    m = _TERNARY_RE.match(text)
    if m:
        cond, true_expr, false_expr = m.group(1), m.group(2), m.group(3)
        depth = 0
        for ch in cond:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        if depth == 0:
            return (cond.strip(), true_expr.strip(), false_expr.strip())

    # Manual parse for complex cases with nested parens
    depth = 0
    q_pos = -1
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "?" and depth == 0:
            q_pos = i
            break

    if q_pos < 0:
        return None

    cond = text[:q_pos].strip()
    rest = text[q_pos + 1:]

    depth = 0
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ":" and depth == 0:
            true_expr = rest[:i].strip()
            false_expr = rest[i + 1:].strip()
            return (cond, true_expr, false_expr)

    return None


def _rhs_has_tainted_var(rhs: str, tainted_names: list[str]) -> str | None:
    """Check if any tainted variable name appears in the RHS text.

    Returns the first matching tainted variable name, or None.
    """
    for tainted_name in tainted_names:
        if re.search(r"\b" + re.escape(tainted_name) + r"\b", rhs):
            return tainted_name
    return None


# ─── Analysis ────────────────────────────────────────────────────────


def _matches_pattern(text: str, pattern: str) -> bool:
    """Check if text contains the taint pattern (simple substring match)."""
    return pattern in text


def _matches_sink_pattern(call_text: str, pattern: str) -> bool:
    """Check if a call matches a sink pattern.

    For method-only patterns starting with '.' (e.g. '.Get'), requires the
    pattern to appear at the end of call_text — prevents '.Head' from
    matching 'w.Header().Set' where 'Head' is just a substring.
    """
    if pattern.startswith("."):
        return call_text.endswith(pattern)
    return pattern in call_text


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


def _handle_sanitizer_in_propagation(
    asgn,
    tainted: dict[str, list[tuple[str, int]]],
    branch_groups: list[list[_BranchRange]] | None,
    conditional_bodies: list[_ConditionalBody] | None,
    sink_lines: set[int] | None,
) -> bool:
    """Handle sanitizer logic during taint propagation. Returns True if taint was cleared."""
    in_conditional_excluding_sinks = False
    if conditional_bodies:
        in_conditional_excluding_sinks = _is_in_conditional_body_not_containing_any(
            asgn.line, sink_lines or set(), conditional_bodies,
        )
    # Fallback to legacy branch_groups check
    if not in_conditional_excluding_sinks and not conditional_bodies and branch_groups:
        for group in branch_groups:
            for br in group:
                if br.start_line <= asgn.line <= br.end_line:
                    in_conditional_excluding_sinks = True
                    break
            if in_conditional_excluding_sinks:
                break
    if not in_conditional_excluding_sinks:
        if asgn.name in tainted:
            del tainted[asgn.name]
            return True
    return False


def _try_ternary_propagation(
    asgn,
    rhs: str,
    tainted: dict[str, list[tuple[str, int]]],
    constant_vars: dict[str, int],
) -> bool | None:
    """Try constant-propagation ternary resolution. Returns True/False if handled, None if not."""
    ternary = _extract_ternary(rhs)
    if ternary is None:
        return None

    cond, true_expr, false_expr = ternary
    cond_result = _eval_condition_with_constants(cond, constant_vars)
    if cond_result is True:
        tainted_name = _rhs_has_tainted_var(true_expr, list(tainted.keys()))
        if tainted_name is not None:
            tainted[asgn.name] = tainted.get(tainted_name, []) + [(tainted_name, asgn.line)]
            return True
        return False
    elif cond_result is False:
        tainted_name = _rhs_has_tainted_var(false_expr, list(tainted.keys()))
        if tainted_name is not None:
            tainted[asgn.name] = tainted.get(tainted_name, []) + [(tainted_name, asgn.line)]
            return True
        return False
    return None


def _try_rhs_propagation(
    asgn,
    rhs: str,
    tainted: dict[str, list[tuple[str, int]]],
    src_lines: list[str],
    coll_state: _CollectionTaintState,
    method_summaries: dict[str, TaintSummary] | None,
) -> bool:
    """Try collection-aware and direct RHS taint propagation. Returns True if taint changed."""
    # Collection-aware: track put/add operations on this line
    line_idx = asgn.line - 1
    if 0 <= line_idx < len(src_lines):
        _track_collection_put(src_lines[line_idx], set(tainted.keys()), coll_state)

    # Collection-aware: check if RHS is a collection.get("key") call
    coll_result = _check_collection_get_taint(rhs, coll_state)
    if coll_result is False:
        return False
    if coll_result is True:
        for tainted_name in list(tainted.keys()):
            tainted[asgn.name] = tainted.get(tainted_name, []) + [(tainted_name, asgn.line)]
            return True
        return False

    for tainted_name in list(tainted.keys()):
        if re.search(r"\b" + re.escape(tainted_name) + r"\b", rhs):
            if method_summaries:
                called = _extract_called_method(rhs)
                if called and called in method_summaries:
                    summary = method_summaries[called]
                    if summary.safe_return or not summary.propagates_taint:
                        break
            tainted[asgn.name] = tainted.get(tainted_name, []) + [(tainted_name, asgn.line)]
            return True

    return False


def _propagate_taint(
    semantics: FileSemantics,
    initial_tainted: set[str],
    func_scope_ids: set[int],
    config: LanguageConfig,
    branch_groups: list[list[_BranchRange]] | None = None,
    conditional_bodies: list[_ConditionalBody] | None = None,
    sink_lines: set[int] | None = None,
    source_bytes: bytes = b"",
    method_summaries: dict[str, TaintSummary] | None = None,
) -> dict[str, list[tuple[str, int]]]:
    """Propagate taint through assignments within function scope.

    Returns: {tainted_var: [(source_var, line), ...]} chain.

    Branch-aware (v0.10): sanitizers inside a conditional branch do NOT
    clear taint globally — they might not execute on all paths.  A sanitizer
    only clears taint if it is NOT inside any conditional body that excludes
    all sink lines (i.e., the sanitizer is guaranteed to run before the sink).

    If the sanitizer is in a conditional body and ALL known sinks for that
    variable are in the SAME conditional body, the sanitizer IS guaranteed
    to run before the sink on that path, so taint is cleared.
    """
    tainted: dict[str, list[tuple[str, int]]] = {name: [] for name in initial_tainted}

    coll_state = _CollectionTaintState.empty()
    src_lines = source_bytes.decode("utf-8", errors="replace").splitlines() if source_bytes else []

    scoped_assignments = sorted(
        [a for a in semantics.assignments if a.scope_id in func_scope_ids and not a.is_parameter],
        key=lambda a: a.line,
    )

    constant_vars: dict[str, int] = {}
    for asgn in scoped_assignments:
        val = asgn.value_text.strip()
        if _INT_LITERAL_RE.match(val):
            constant_vars[asgn.name] = int(val)

    changed = True
    max_iters = 10
    iteration = 0

    while changed and iteration < max_iters:
        changed = False
        iteration += 1

        for asgn in scoped_assignments:
            rhs = asgn.value_text

            # Check if RHS passes through a sanitizer
            is_sanitized = any(sanitizer in rhs for sanitizer in config.taint_sanitizer_patterns)

            if is_sanitized:
                if _handle_sanitizer_in_propagation(
                    asgn, tainted, branch_groups, conditional_bodies, sink_lines,
                ):
                    changed = True
                continue

            if asgn.name in tainted:
                continue

            # Constant propagation: ternary resolution
            ternary_result = _try_ternary_propagation(asgn, rhs, tainted, constant_vars)
            if ternary_result is not None:
                if ternary_result:
                    changed = True
                continue

            # Collection-aware and direct RHS propagation
            if _try_rhs_propagation(asgn, rhs, tainted, src_lines, coll_state, method_summaries):
                changed = True

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

    # Build set of (variable, line) pairs where the variable is being assigned
    # (LHS), so we can exclude LHS matches from sink detection — a variable
    # being assigned on a line is not being *passed* to a sink on that line.
    assigned_on_line: set[tuple[str, int]] = set()
    for asgn in semantics.assignments:
        if asgn.scope_id in func_scope_ids and not asgn.is_parameter:
            assigned_on_line.add((asgn.name, asgn.line))

    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue

        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"

        _match_call_to_sink(call, call_text, config, lines, tainted_vars, assigned_on_line, sinks)

    return sinks


def _match_call_to_sink(call: object, call_text: str, config: object, lines: list[str], tainted_vars: list[str], assigned_on_line: set, sinks: list) -> None:
    """Check if a function call matches any sink pattern with tainted args."""
    for pattern, kind in config.taint_sink_patterns:
        if not _matches_sink_pattern(call_text, pattern):
            continue

        line_idx = call.line - 1
        if not (0 <= line_idx < len(lines)):
            break

        line_text = lines[line_idx]
        tvar = _find_tainted_arg_at_sink(
            tainted_vars, call, pattern, line_text, assigned_on_line,
        )
        if tvar is not None:
            sinks.append(TaintSink(
                variable=tvar, line=call.line, kind=kind,
                function_name=call_text, scope_id=call.scope_id,
            ))
        break


def _find_tainted_arg_at_sink(tainted_vars: list[str], call: object, pattern: str, line_text: str, assigned_on_line: set) -> str | None:
    """Find the first tainted variable that appears as an argument at a sink call."""
    for tvar in tainted_vars:
        if (tvar, call.line) in assigned_on_line:
            continue
        if pattern.startswith(".") and call.receiver:
            receiver_root = call.receiver.split(".")[0].split("(")[0]
            if tvar == receiver_root:
                continue
        if re.search(r"\b" + re.escape(tvar) + r"\b", line_text):
            return tvar
    return None


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


def _sanitizer_dominates_sink(
    sanitizer_line: int,
    sanitizer_scope_id: int,
    sink_line: int,
    sink_scope_id: int | None,
    scope_map: dict[int, ScopeInfo] | None,
    branch_groups: list[list[_BranchRange]] | None,
    conditional_bodies: list[_ConditionalBody] | None,
) -> bool:
    """Return True if a sanitizer at the given location dominates the sink (guaranteed to run before it)."""
    if sink_line and sanitizer_line >= sink_line:
        return False
    if sink_scope_id is not None and scope_map is not None:
        if not _is_ancestor_scope(sanitizer_scope_id, sink_scope_id, scope_map):
            return False
    if branch_groups and sink_line:
        if _are_in_sibling_branches(sanitizer_line, sink_line, branch_groups):
            return False
    if conditional_bodies and sink_line:
        if _is_in_conditional_body_not_containing(sanitizer_line, sink_line, conditional_bodies):
            return False
    return True


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
    # Check assignment-based sanitizers
    for asgn in semantics.assignments:
        if asgn.scope_id not in func_scope_ids:
            continue
        if asgn.name != tainted_var:
            continue
        if not _sanitizer_dominates_sink(
            asgn.line, asgn.scope_id, sink_line, sink_scope_id,
            scope_map, branch_groups, conditional_bodies,
        ):
            continue
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in asgn.value_text:
                return True

    # Check call-based sanitizers
    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue
        if not _sanitizer_dominates_sink(
            call.line, call.scope_id, sink_line, sink_scope_id,
            scope_map, branch_groups, conditional_bodies,
        ):
            continue
        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"
        for sanitizer in config.taint_sanitizer_patterns:
            if sanitizer in call_text:
                return True

    return False


def _check_taint_source_match(
    asgn,
    rhs: str,
    config: LanguageConfig,
    current_taint: set[str],
    source_vars: set[str] | None,
    source_lines: dict[str, int] | None,
) -> bool:
    """Check if RHS matches a taint source pattern. Returns True if matched."""
    for pattern, kind in config.taint_source_patterns:
        if _matches_pattern(rhs, pattern):
            current_taint.add(asgn.name)
            if source_vars is not None and asgn.name not in source_vars:
                source_vars.add(asgn.name)
                if source_lines is not None:
                    source_lines[asgn.name] = asgn.line
            return True
    return False


def _propagate_taint_through_rhs(
    asgn,
    rhs: str,
    current_taint: set[str],
    coll_state: _CollectionTaintState | None,
    constant_vars: dict[str, int] | None,
    method_summaries: dict[str, TaintSummary] | None,
) -> None:
    """Propagate taint through ternary, collection, or direct RHS references."""
    # Constant propagation: check ternary before normal propagation
    if constant_vars is not None:
        ternary = _extract_ternary(rhs)
        if ternary is not None:
            cond, true_expr, false_expr = ternary
            cond_result = _eval_condition_with_constants(cond, constant_vars)
            if cond_result is True:
                if _rhs_has_tainted_var(true_expr, list(current_taint)) is not None:
                    current_taint.add(asgn.name)
                return
            elif cond_result is False:
                if _rhs_has_tainted_var(false_expr, list(current_taint)) is not None:
                    current_taint.add(asgn.name)
                return

    # Collection-aware: check if RHS is a collection.get("key") call
    if coll_state is not None:
        coll_result = _check_collection_get_taint(rhs, coll_state)
        if coll_result is False:
            return  # untainted key -- don't propagate
        elif coll_result is True:
            current_taint.add(asgn.name)
            return

    # Direct RHS variable reference
    for tvar in list(current_taint):
        if re.search(r"\b" + re.escape(tvar) + r"\b", rhs):
            if method_summaries:
                called = _extract_called_method(rhs)
                if called and called in method_summaries:
                    summary = method_summaries[called]
                    if summary.safe_return or not summary.propagates_taint:
                        break
            current_taint.add(asgn.name)
            break


def _process_assignment_taint(
    asgn,
    config: LanguageConfig,
    current_taint: set[str],
    source_vars: set[str] | None = None,
    source_lines: dict[str, int] | None = None,
    coll_state: _CollectionTaintState | None = None,
    src_lines: list[str] | None = None,
    method_summaries: dict[str, TaintSummary] | None = None,
    constant_vars: dict[str, int] | None = None,
) -> None:
    """Process a single assignment for taint propagation/sanitization.

    Constant propagation (v1.2): if the RHS is a ternary expression with a
    resolvable condition, only check the branch that actually executes.
    """
    rhs = asgn.value_text

    # Track integer constants for constant propagation
    if constant_vars is not None:
        val = rhs.strip()
        if _INT_LITERAL_RE.match(val):
            constant_vars[asgn.name] = int(val)

    # Collection-aware: track put/add on this line
    if coll_state is not None and src_lines is not None:
        line_idx = asgn.line - 1
        if 0 <= line_idx < len(src_lines):
            _track_collection_put(src_lines[line_idx], current_taint, coll_state)

    if not _check_taint_source_match(asgn, rhs, config, current_taint, source_vars, source_lines):
        _propagate_taint_through_rhs(asgn, rhs, current_taint, coll_state, constant_vars, method_summaries)

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
    ctx: TaintContext,
    current_taint: set[str],
    coll_state: _CollectionTaintState | None = None,
    constant_vars: dict[str, int] | None = None,
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
        asgn = ctx.semantics.assignments[aidx]
        _process_assignment_taint(asgn, ctx.config, current_taint, ctx.source_vars, ctx.source_lines,
                                    coll_state=coll_state, src_lines=ctx.lines,
                                    method_summaries=ctx.method_summaries, constant_vars=constant_vars)

    # Process all calls on this line (primary + extras)
    call_idxs = []
    if stmt.call_idx is not None:
        call_idxs.append(stmt.call_idx)
    call_idxs.extend(getattr(stmt, "extra_call_idxs", []))

    line_idx = stmt.line - 1
    for cidx in call_idxs:
        call = ctx.semantics.function_calls[cidx]
        _process_call_taint(call, ctx.config, current_taint, line_idx, ctx.lines)


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


# ─── Inter-procedural method summaries ────────────────────────────────


def _all_returns_are_literals(
    semantics: FileSemantics,
    func_scope_ids: set[int],
    lines: list[str],
    start_line: int,
    end_line: int,
) -> bool:
    """Check if every return statement in the function returns a literal value."""
    literal_return_re = re.compile(
        r"""^\s*return\s+
        (?:
            "(?:[^"\\]|\\.)*"          # double-quoted string
            |'(?:[^'\\]|\\.)*'         # single-quoted string
            |-?\d+(?:\.\d+)?           # number
            |true|false|null|none|nil  # boolean/null constants
            |True|False|None           # Python capitalized
        )\s*;?\s*$""",
        re.VERBOSE | re.IGNORECASE,
    )

    found_any_return = False
    for line_num in range(start_line, min(end_line + 1, len(lines) + 1)):
        line_idx = line_num - 1
        if 0 <= line_idx < len(lines):
            line_text = lines[line_idx].strip()
            if line_text.startswith("return ") or line_text in ("return;", "return"):
                found_any_return = True
                if line_text in ("return;", "return"):
                    continue
                if not literal_return_re.match(line_text):
                    return False

    return found_any_return


def _taint_reaches_return(
    semantics: FileSemantics,
    tainted_vars: set[str],
    func_scope_ids: set[int],
    lines: list[str],
    start_line: int,
    end_line: int,
) -> bool:
    """Check if any tainted variable appears in a return statement."""
    if not tainted_vars:
        return False

    for line_num in range(start_line, min(end_line + 1, len(lines) + 1)):
        line_idx = line_num - 1
        if 0 <= line_idx < len(lines):
            line_text = lines[line_idx].strip()
            if line_text.startswith("return "):
                return_expr = line_text[len("return "):]
                for tvar in tainted_vars:
                    if re.search(r"\b" + re.escape(tvar) + r"\b", return_expr):
                        return True

    return False


def _extract_called_method(rhs: str) -> str | None:
    """Extract method name from a call expression.

    'test.doSomething(request, param)' -> 'doSomething'
    'obj.method(x)' -> 'method'
    'doSomething(x)' -> 'doSomething'
    """
    m = re.search(r"\.(\w+)\s*\(", rhs)
    if m:
        return m.group(1)
    m = re.search(r"\b(\w+)\s*\(", rhs)
    if m:
        name = m.group(1)
        if name not in ("if", "for", "while", "switch", "catch", "new", "return", "typeof", "instanceof"):
            return name
    return None


def _build_method_summaries(
    semantics: FileSemantics,
    config: LanguageConfig,
    source_bytes: bytes,
) -> dict[str, TaintSummary]:
    """Pre-pass: summarize each function's taint behavior for inter-procedural analysis.

    For each function in the file, determine whether tainted parameters flow
    through to return values.  Only analyzes same-file methods.
    """
    summaries: dict[str, TaintSummary] = {}
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()

    func_scopes = [s for s in semantics.scopes if s.kind == "function"]
    scope_children = _build_scope_children(semantics)

    for func_scope in func_scopes:
        func_name = func_scope.name
        if not func_name:
            continue

        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        # Collect parameters for this function
        params: set[str] = set()
        for asgn in semantics.assignments:
            if asgn.scope_id in func_scope_ids and asgn.is_parameter:
                params.add(asgn.name)

        if not params:
            safe_ret = _all_returns_are_literals(
                semantics, func_scope_ids, lines, func_scope.start_line, func_scope.end_line,
            )
            summaries[func_name] = TaintSummary(
                propagates_taint=False, sanitizes=False, safe_return=safe_ret,
            )
            continue

        # Run a mini taint propagation treating all params as tainted
        initial_tainted = set(params)
        taint_chains = _propagate_taint(
            semantics, initial_tainted, func_scope_ids, config,
        )
        tainted_at_end = set(taint_chains.keys())

        propagates = _taint_reaches_return(
            semantics, tainted_at_end, func_scope_ids, lines,
            func_scope.start_line, func_scope.end_line,
        )

        sanitizes = False
        for asgn in semantics.assignments:
            if asgn.scope_id not in func_scope_ids or asgn.is_parameter:
                continue
            if any(san in asgn.value_text for san in config.taint_sanitizer_patterns):
                sanitizes = True
                break

        safe_ret = _all_returns_are_literals(
            semantics, func_scope_ids, lines, func_scope.start_line, func_scope.end_line,
        )

        summaries[func_name] = TaintSummary(
            propagates_taint=propagates, sanitizes=sanitizes, safe_return=safe_ret,
        )

    return summaries


# ─── Entry point ─────────────────────────────────────────────────────


def _collect_potential_sink_lines(
    semantics: FileSemantics,
    config: LanguageConfig,
    func_scope_ids: set[int],
) -> set[int]:
    """Collect line numbers of potential taint sinks in the given scopes."""
    sink_lines: set[int] = set()
    for call in semantics.function_calls:
        if call.scope_id not in func_scope_ids:
            continue
        call_text = call.name
        if call.receiver:
            call_text = f"{call.receiver}.{call.name}"
        for pattern, _kind in config.taint_sink_patterns:
            if _matches_sink_pattern(call_text, pattern):
                sink_lines.add(call.line)
                break
    return sink_lines


def _resolve_sink_source(
    sink: TaintSink,
    sources: list[TaintSource],
    initial_tainted: set[str],
    taint_chains: dict[str, list[tuple[str, int]]],
) -> TaintSource | None:
    """Find the originating taint source for a sink variable."""
    if sink.variable in initial_tainted:
        for s in sources:
            if s.variable == sink.variable:
                return s
        return None
    chain = taint_chains.get(sink.variable, [])
    for src in sources:
        if src.variable in {c[0] for c in chain} | {sink.variable}:
            return src
    return sources[0] if sources else None


def _build_taint_finding(
    sink: TaintSink,
    source: TaintSource,
    taint_chains: dict[str, list[tuple[str, int]]],
    config: LanguageConfig,
    filepath: str,
) -> Finding:
    """Build a Finding from a confirmed taint flow."""
    chain = taint_chains.get(sink.variable, [])
    chain_desc = ""
    if chain:
        chain_names = [c[0] for c in chain]
        chain_desc = f" (through: {' → '.join(chain_names)})"

    rule_name = _resolve_taint_rule(sink.kind, config.ts_language_name)
    return Finding(
        file=filepath,
        line=sink.line,
        severity=Severity.WARNING,
        category=Category.SECURITY,
        source=Source.AST,
        rule=rule_name,
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


def analyze_taint(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
    filepath: str,
) -> list[Finding]:
    """Run taint analysis with inter-procedural method summaries.

    Analyzes each function with same-file method summary resolution.
    When a called method doesn't propagate taint (e.g., always returns
    a literal), taint is not propagated through that call.
    Returns [] if no taint source/sink patterns configured.
    """
    if not config.taint_source_patterns or not config.taint_sink_patterns:
        return []

    findings = []
    seen: set[tuple[int, int]] = set()

    func_scopes = [s for s in semantics.scopes if s.kind == "function"]
    scope_children = _build_scope_children(semantics)
    scope_map = _build_scope_map(semantics)

    tree_root = getattr(semantics, "_tree_root", None)
    branch_groups = _collect_branch_siblings(tree_root)
    conditional_bodies = _collect_conditional_bodies(tree_root)
    method_summaries = _build_method_summaries(semantics, config, source_bytes)

    for func_scope in func_scopes:
        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        sources = _find_taint_sources(semantics, config, source_bytes, func_scope_ids)
        if not sources:
            continue

        potential_sink_lines = _collect_potential_sink_lines(semantics, config, func_scope_ids)

        initial_tainted = {s.variable for s in sources}
        taint_chains = _propagate_taint(
            semantics, initial_tainted, func_scope_ids, config,
            branch_groups=branch_groups,
            conditional_bodies=conditional_bodies,
            sink_lines=potential_sink_lines,
            source_bytes=source_bytes,
            method_summaries=method_summaries,
        )
        tainted_vars = set(taint_chains.keys())
        if not tainted_vars:
            continue

        sinks = _find_taint_sinks(semantics, config, tainted_vars, func_scope_ids, source_bytes)

        for sink in sinks:
            if _is_sanitized(
                semantics, config, sink.variable, func_scope_ids,
                sink_line=sink.line, sink_scope_id=sink.scope_id,
                scope_map=scope_map, branch_groups=branch_groups,
                conditional_bodies=conditional_bodies,
            ):
                continue

            source = _resolve_sink_source(sink, sources, initial_tainted, taint_chains)
            if source is None:
                continue

            key = (source.line, sink.line)
            if key in seen:
                continue
            seen.add(key)

            findings.append(_build_taint_finding(sink, source, taint_chains, config, filepath))

    return findings


# ─── Path-sensitive taint analysis (v0.9.0) ──────────────────────────


def _compute_block_taint_in(
    block,
    block_taint_out: dict[int, set[str]],
    block_coll_out: dict[int, _CollectionTaintState],
) -> tuple[set[str], _CollectionTaintState]:
    """Compute taint_in and coll_in for a block by unioning predecessor outputs."""
    if block.is_entry:
        return set(), _CollectionTaintState.empty()
    taint_in: set[str] = set()
    coll_in = _CollectionTaintState.empty()
    for pred_id in block.predecessors:
        taint_in |= block_taint_out.get(pred_id, set())
        coll_in = coll_in.merge(block_coll_out.get(pred_id, _CollectionTaintState.empty()))
    return taint_in, coll_in


def _run_forward_dataflow(
    cfg,
    rpo: list[int],
    ctx: TaintContext,
) -> tuple[dict[int, set[str]], dict[int, _CollectionTaintState], dict[str, int]]:
    """Run forward dataflow to compute per-block taint sets. Returns (block_taint_out, block_coll_out, constant_vars)."""
    block_coll_out: dict[int, _CollectionTaintState] = {
        bid: _CollectionTaintState.empty() for bid in cfg.blocks
    }
    block_taint_out: dict[int, set[str]] = {bid: set() for bid in cfg.blocks}
    ps_constant_vars: dict[str, int] = {}

    max_iters = 20
    for _iteration in range(max_iters):
        changed = False

        for block_id in rpo:
            block = cfg.blocks[block_id]
            taint_in, coll_in = _compute_block_taint_in(block, block_taint_out, block_coll_out)

            current_taint = set(taint_in)
            current_coll = coll_in.copy()

            for stmt in block.statements:
                _update_stmt_taint(
                    stmt, ctx, current_taint,
                    coll_state=current_coll, constant_vars=ps_constant_vars,
                )

            old_out = block_taint_out[block_id]
            if current_taint != old_out:
                block_taint_out[block_id] = current_taint
                changed = True
            block_coll_out[block_id] = current_coll

        if not changed:
            break

    return block_taint_out, block_coll_out, ps_constant_vars


def _find_source_info(sources: list[TaintSource], tvar: str) -> TaintSource | None:
    """Find the taint source info for a variable, falling back to first source."""
    for s in sources:
        if s.variable == tvar:
            return s
    return sources[0] if sources else None


def _check_tainted_var_at_sink(
    tvar: str, stmt, call_text: str, sink_kind: str, pattern: str,
    line_text: str, sources: list[TaintSource],
    ps_assigned_on_line: set[tuple[str, int]], call_receiver: str | None,
    seen: set, ctx: TaintContext,
) -> Finding | None:
    """Check if a tainted variable reaches a sink on this line. Returns Finding or None."""
    if (tvar, stmt.line) in ps_assigned_on_line:
        return None
    if pattern.startswith(".") and call_receiver:
        receiver_root = call_receiver.split(".")[0].split("(")[0]
        if tvar == receiver_root:
            return None
    if not re.search(r"\b" + re.escape(tvar) + r"\b", line_text):
        return None

    source_lines = ctx.source_lines or {}
    src_line = source_lines.get(tvar, 0)
    key = (src_line, stmt.line)
    if key in seen:
        return None
    seen.add(key)

    source_info = _find_source_info(sources, tvar)
    src_kind = source_info.kind if source_info else "unknown"
    src_var = source_info.variable if source_info else tvar
    ps_rule = _resolve_taint_rule(sink_kind, ctx.config.ts_language_name)

    return Finding(
        file=ctx.filepath,
        line=stmt.line,
        severity=Severity.WARNING,
        category=Category.SECURITY,
        source=Source.AST,
        rule=ps_rule,
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


def _scan_blocks_for_sinks(
    cfg,
    rpo: list[int],
    ctx: TaintContext,
    sources: list[TaintSource],
    block_taint_out: dict[int, set[str]],
    block_coll_out: dict[int, _CollectionTaintState],
    ps_constant_vars: dict[str, int],
    ps_assigned_on_line: set[tuple[str, int]],
    seen: set,
) -> list[Finding]:
    """Scan CFG blocks for taint sinks with tainted arguments."""
    findings = []

    for block_id in rpo:
        block = cfg.blocks[block_id]
        taint_in, coll_in = _compute_block_taint_in(block, block_taint_out, block_coll_out)

        current_taint = set(taint_in)
        current_coll = coll_in.copy()

        for stmt in block.statements:
            line_idx = stmt.line - 1

            _update_stmt_taint(stmt, ctx, current_taint,
                               coll_state=current_coll, constant_vars=ps_constant_vars)

            sink_call_idxs = []
            if stmt.call_idx is not None:
                sink_call_idxs.append(stmt.call_idx)
            sink_call_idxs.extend(getattr(stmt, "extra_call_idxs", []))

            for _cidx in sink_call_idxs:
                call = ctx.semantics.function_calls[_cidx]
                call_text = f"{call.receiver}.{call.name}" if call.receiver else call.name

                for pattern, sink_kind in ctx.config.taint_sink_patterns:
                    if not _matches_sink_pattern(call_text, pattern):
                        continue
                    if not (0 <= line_idx < len(ctx.lines)):
                        break

                    line_text = ctx.lines[line_idx]
                    for tvar in current_taint:
                        f = _check_tainted_var_at_sink(
                            tvar, stmt, call_text, sink_kind, pattern,
                            line_text, sources,
                            ps_assigned_on_line, call.receiver,
                            seen, ctx,
                        )
                        if f:
                            findings.append(f)
                            break
                    break

    return findings


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

    method_summaries = _build_method_summaries(semantics, config, source_bytes)

    for func_scope in func_scopes:
        cfg = cfgs.get(func_scope.scope_id)
        if cfg is None:
            continue

        func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

        # 1. Find taint sources
        sources = _find_taint_sources(semantics, config, source_bytes, func_scope_ids)
        if not sources:
            continue

        source_vars = {s.variable for s in sources}
        source_lines_map = {s.variable: s.line for s in sources}

        ctx = TaintContext(
            semantics=semantics, config=config, lines=lines, filepath=filepath,
            method_summaries=method_summaries, source_vars=source_vars,
            source_lines=source_lines_map,
        )

        rpo = get_reverse_postorder(cfg)

        # 2. Forward dataflow
        block_taint_out, block_coll_out, ps_constant_vars = _run_forward_dataflow(
            cfg, rpo, ctx,
        )

        # Build LHS-assignment exclusion set
        ps_assigned_on_line: set[tuple[str, int]] = set()
        for asgn in semantics.assignments:
            if asgn.scope_id in func_scope_ids and not asgn.is_parameter:
                ps_assigned_on_line.add((asgn.name, asgn.line))

        # 3. Scan for sinks
        findings.extend(_scan_blocks_for_sinks(
            cfg, rpo, ctx, sources,
            block_taint_out, block_coll_out, ps_constant_vars,
            ps_assigned_on_line, seen,
        ))

    return findings
