"""Null safety checks: detect attribute/method access on potentially nullable values.

Uses type inference results to find cases where:
1. A variable typed as nullable (Optional, None-returning pattern) is accessed
   without a None check
2. A method is called on a nullable return value without guarding

Supports conditional narrowing: suppresses inside `if x is not None:` bodies.
Returns [] when type info is unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Finding, Severity, Category, Source
from .lang_config import LanguageConfig
from .core import FileSemantics, FunctionDef
from .types import FileTypeMap, TypeInfo, InferredType


# ─── Narrowing detection ─────────────────────────────────────────────

# ─── Guard pattern tables ─────────────────────────────────────────
# Built programmatically from (template, description) tuples.
# Each template uses {var} for the captured variable name.

def _build_patterns(templates: list[str]) -> list[re.Pattern]:
    """Build compiled regex patterns from templates with {var} placeholder."""
    VAR = r'(\w+)'
    SELF_VAR = r'self\.(\w+)'
    result = []
    for tmpl in templates:
        # Expand {self_var} and {var} placeholders
        pattern = tmpl.replace('{self_var}', SELF_VAR).replace('{var}', VAR)
        result.append(re.compile(pattern))
    return result


# Guard patterns: `if x is not None:` / `if (x !== null)` — block body is guarded
_GUARD_PATTERNS = _build_patterns([
    r'if\s+{self_var}\s+is\s+not\s+None\b',      # Python: if self.x is not None
    r'if\s+{var}\s+is\s+not\s+None\s*:',          # Python: if x is not None:
    r'if\s+{var}\s+is\s+not\s+None\b',            # Python: if x is not None and ...
    r'if\s+{var}\s*!=\s*None\s*:',                 # Python: if x != None:
    r'if\s+{self_var}\s*:',                        # Python: if self.x:
    r'if\s+{var}\s*:',                             # Python: if x:
    r'if\s*\(\s*{var}\s*!==?\s*null\s*\)',         # JS/TS/Java/C#: if (x !== null)
    r'if\s*\(\s*{var}\s*!=\s*null\s*\)',           # JS/TS/Java/C#: if (x != null)
    r'if\s*\(\s*{var}\s*\)',                       # JS/TS: if (x)
])

# Early-exit patterns: `if x is None: raise/return` — continuation is guarded
_EARLY_EXIT_PATTERNS = _build_patterns([
    r'if\s+{self_var}\s+is\s+None\s*:',           # Python: if self.x is None:
    r'if\s+{var}\s+is\s+None\s*:',                # Python: if x is None:
    r'if\s+not\s+{self_var}\s*:',                  # Python: if not self.x:
    r'if\s+not\s+{var}\s*:',                       # Python: if not x:
    r'if\s*\(\s*{var}\s*===?\s*null\s*\)',         # JS/TS: if (x === null)
    r'if\s*\(\s*!\s*{var}\s*\)',                   # JS/TS: if (!x)
])

# Assert patterns: `assert x is not None` — everything after is guarded
_ASSERT_PATTERNS = _build_patterns([
    r'assert\s+{self_var}\s+is\s+not\s+None',
    r'assert\s+{var}\s+is\s+not\s+None',
    r'assert\s+isinstance\s*\(\s*{self_var}\s*,',
    r'assert\s+isinstance\s*\(\s*{var}\s*,',
    r'assert\s+{self_var}\b',
    r'assert\s+{var}\b',
])

# Inline guard patterns: short-circuit and ternary on same line
_INLINE_GUARD_RE = [
    re.compile(r'\bself\.(\w+)\s+and\s+self\.\1\.'),   # self.x and self.x.attr
    re.compile(r'\b(\w+)\s+and\s+\1\.'),                # x and x.attr
    re.compile(r'\b(\w+)\b.*\bif\s+\1\b.*\belse\b'),   # x if x else default
]


def _find_guarded_lines(
    source_bytes: bytes,
    language: str,
) -> dict[str, set[int]]:
    """Find lines where a variable is guarded by a None check.

    Returns {variable_name: {set of guarded line numbers}}.

    Detects patterns:
    1. Block guards: `if x is not None:` / `if (x !== null)` / `if x:` —
       all indented lines inside the block are guarded.
    2. Early-exit guards: `if x is None: raise/return` — all lines AFTER
       the block are guarded (None eliminated on continuation path).
    3. Assert guards: `assert x is not None` / `assert isinstance(x, T)` —
       all lines after the assert are guarded.
    4. Inline guards: `x and x.attr` (short-circuit), `x if x else d` (ternary)
       — suppress findings on the same line.
    """
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    guarded: dict[str, set[int]] = {}

    # Track if/guard blocks by variable
    active_guards: list[tuple[str, int, int]] = []  # (var_name, guard_indent, start_line)
    # Track early-exit guards: after the if-block ends, all subsequent lines are guarded
    early_exit_guards: list[tuple[str, int, int, bool]] = []  # (var_name, guard_indent, start_line, has_exit)
    # Track assert-based guards: all lines after assert are guarded
    assert_guarded_from: dict[str, int] = {}  # var_name -> line number

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        lineno = i + 1

        # Close any guards that have ended (dedent)
        active_guards = [
            (var, gi, sl) for var, gi, sl in active_guards
            if indent > gi or not stripped  # blank lines don't end blocks
        ]

        # Check if early-exit guards have finished their block — if so,
        # all subsequent lines are guarded (None eliminated by early exit)
        new_early_exits = []
        for var, gi, sl, has_exit in early_exit_guards:
            if indent <= gi and stripped:
                # Block ended — only guard if body contained an exit statement
                if has_exit:
                    assert_guarded_from.setdefault(var, lineno)
            else:
                # Still inside the block — check if this line has an exit
                if not has_exit and stripped.startswith(
                    ("raise", "return", "continue", "break", "throw")
                ):
                    has_exit = True
                new_early_exits.append((var, gi, sl, has_exit))
        early_exit_guards = new_early_exits

        # Mark current line as guarded for active block guards
        for var_name, _, _ in active_guards:
            guarded.setdefault(var_name, set()).add(lineno)

        # Mark current line as guarded for assert/early-exit continuation
        for var_name, from_line in assert_guarded_from.items():
            if lineno >= from_line:
                guarded.setdefault(var_name, set()).add(lineno)

        # Check inline guard patterns (same-line suppression)
        for pattern in _INLINE_GUARD_RE:
            m = pattern.search(stripped)
            if m:
                var_name = m.group(1)
                guarded.setdefault(var_name, set()).add(lineno)

        # Detect assert guards
        if stripped.startswith("assert "):
            for pattern in _ASSERT_PATTERNS:
                m = pattern.match(stripped)
                if m:
                    var_name = m.group(1)
                    # All lines after this assert are guarded
                    assert_guarded_from.setdefault(var_name, lineno + 1)
                    break

        # Detect early-exit patterns: if x is None: raise/return
        for pattern in _EARLY_EXIT_PATTERNS:
            m = pattern.match(stripped)
            if m:
                var_name = m.group(1)
                # Track as potential early-exit; body must contain raise/return
                early_exit_guards.append((var_name, indent, lineno, False))
                # Also look for single-line: `if x is None: raise ValueError`
                after_colon = stripped.split(":", 1)
                if len(after_colon) > 1:
                    body = after_colon[1].strip()
                    if body.startswith(("raise", "return", "continue", "break", "throw")):
                        # Single-line early exit — everything after is guarded
                        assert_guarded_from.setdefault(var_name, lineno + 1)
                        # Remove from early_exit_guards since it's handled
                        early_exit_guards = [
                            (v, g, s, h) for v, g, s, h in early_exit_guards
                            if not (v == var_name and s == lineno)
                        ]
                break

        # Detect block guard patterns (if x is not None:)
        for pattern in _GUARD_PATTERNS:
            m = pattern.match(stripped)
            if m:
                var_name = m.group(1)
                active_guards.append((var_name, indent, lineno))
                break

    return guarded


def _resolve_nullable_in_scope(
    var_name: str,
    scope_id: int,
    nullable_vars: dict[tuple[str, int], TypeInfo],
    semantics: FileSemantics,
) -> TypeInfo | None:
    """Look up a variable in nullable_vars, walking parent scopes if needed."""
    tinfo = nullable_vars.get((var_name, scope_id))
    if tinfo is not None:
        return tinfo
    for scope in semantics.scopes:
        if scope.scope_id == scope_id:
            parent = scope.parent_id
            while parent is not None:
                tinfo = nullable_vars.get((var_name, parent))
                if tinfo:
                    return tinfo
                for s in semantics.scopes:
                    if s.scope_id == parent:
                        parent = s.parent_id
                        break
                else:
                    break
            break
    return None


# ─── Null safety check ───────────────────────────────────────────────

def check_null_safety(
    semantics: FileSemantics,
    type_map: FileTypeMap,
    config: LanguageConfig,
    filepath: str,
    cfgs: dict | None = None,
) -> list[Finding]:
    """Check for attribute/method access on nullable values.

    Checks:
    1. Attribute access on nullable: `x = dict.get(k); x.strip()`
    2. Method call on nullable return: `m = re.match(...); m.group(1)`
    3. Missing None check before use

    Suppresses findings within None-guard blocks (conditional narrowing).
    """
    if not type_map.types:
        return []

    findings = []
    seen = set()

    # Collect nullable variables
    nullable_vars: dict[tuple[str, int], TypeInfo] = {}
    for key, tinfo in type_map.types.items():
        if tinfo.nullable or tinfo.inferred_type in (InferredType.NONE, InferredType.OPTIONAL):
            nullable_vars[key] = tinfo

    if not nullable_vars:
        return []

    # We need source bytes for narrowing detection — reconstruct from file
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source_bytes = f.read().encode("utf-8")
    except (OSError, IOError):
        return []

    # Find guarded lines
    guarded_lines = _find_guarded_lines(source_bytes, semantics.language)

    # Check each reference to a nullable variable
    for ref in semantics.references:
        if ref.context != "attribute_access":
            continue

        tinfo = _resolve_nullable_in_scope(ref.name, ref.scope_id, nullable_vars, semantics)  # type: ignore[assignment]  # None handled on next line
        if tinfo is None:
            continue

        # Check if this line is guarded
        if ref.name in guarded_lines and ref.line in guarded_lines[ref.name]:
            continue

        dedup_key = (filepath, ref.line, ref.name)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Determine what pattern caused nullability
        source_desc = ""
        if tinfo.source == "return_type":
            source_desc = " (from nullable return value)"
        elif tinfo.source == "literal" and tinfo.inferred_type == InferredType.NONE:
            source_desc = " (assigned None)"
        elif tinfo.source == "annotation":
            source_desc = " (typed as Optional)"

        findings.append(Finding(
            file=filepath,
            line=ref.line,
            severity=Severity.WARNING,
            category=Category.BUG,
            source=Source.AST,
            rule="null-dereference",
            message=(
                f"Attribute access on '{ref.name}' which may be None{source_desc}"
            ),
            suggestion=(
                f"Add a None check before accessing attributes on '{ref.name}' "
                f"(e.g., 'if {ref.name} is not None:')"
            ),
        ))

    # Also check function calls on nullable variables
    for call in semantics.function_calls:
        if call.receiver is None:
            continue

        tinfo = _resolve_nullable_in_scope(call.receiver, call.scope_id, nullable_vars, semantics)  # type: ignore[assignment]  # None handled on next line
        if tinfo is None:
            continue

        # Check if this line is guarded
        if call.receiver in guarded_lines and call.line in guarded_lines[call.receiver]:
            continue

        dedup_key = (filepath, call.line, call.receiver)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append(Finding(
            file=filepath,
            line=call.line,
            severity=Severity.WARNING,
            category=Category.BUG,
            source=Source.AST,
            rule="null-dereference",
            message=(
                f"Method '{call.name}' called on '{call.receiver}' which may be None"
            ),
            suggestion=(
                f"Add a None check before calling methods on '{call.receiver}' "
                f"(e.g., 'if {call.receiver} is not None:')"
            ),
        ))

    return findings
