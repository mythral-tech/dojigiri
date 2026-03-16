"""Null safety checks: detect attribute/method access on potentially nullable values.

Uses type inference results to find cases where:
1. A variable typed as nullable (Optional, None-returning pattern) is accessed
   without a None check
2. A method is called on a nullable return value without guarding

Supports conditional narrowing: suppresses inside `if x is not None:` bodies.
Also tracks variable reassignment to non-None values (e.g., `x = x or default`).
Returns [] when type info is unavailable.

Called by: detector.py
Calls into: semantic/lang_config.py, semantic/core.py, semantic/types.py, semantic/cfg.py, config.py
Data in → Data out: FileSemantics + FileTypeMap → list[Finding]
"""

from __future__ import annotations  # noqa

import re

from ..types import Category, Finding, Severity, Source
from .core import FileSemantics
from .lang_config import LanguageConfig
from .types import FileTypeMap, InferredType, TypeInfo

# ─── Narrowing detection ─────────────────────────────────────────────

# ─── Guard pattern tables ─────────────────────────────────────────
# Built programmatically from (template, description) tuples.
# Each template uses {var} for the captured variable name.


def _build_patterns(templates: list[str]) -> list[re.Pattern]:
    """Build compiled regex patterns from templates with {var} placeholder."""
    VAR = r"(\w+)"
    SELF_VAR = r"self\.(\w+)"
    result = []
    for tmpl in templates:
        # Expand {self_var} and {var} placeholders
        pattern = tmpl.replace("{self_var}", SELF_VAR).replace("{var}", VAR)
        result.append(re.compile(pattern))
    return result


# Guard patterns: `if x is not None:` / `if (x !== null)` — block body is guarded
_GUARD_PATTERNS = _build_patterns(
    [
        r"if\s+{self_var}\s+is\s+not\s+None\b",  # Python: if self.x is not None
        r"if\s+{var}\s+is\s+not\s+None\s*:",  # Python: if x is not None:
        r"if\s+{var}\s+is\s+not\s+None\b",  # Python: if x is not None and ...
        r"if\s+{var}\s*!=\s*None\s*:",  # Python: if x != None:
        r"if\s+{self_var}\s*:",  # Python: if self.x:
        r"if\s+{var}\s*:",  # Python: if x:
        r"if\s*\(\s*{var}\s*!==?\s*null\s*\)",  # JS/TS/Java/C#: if (x !== null)
        r"if\s*\(\s*{var}\s*!=\s*null\s*\)",  # JS/TS/Java/C#: if (x != null)
        r"if\s*\(\s*{var}\s*\)",  # JS/TS: if (x)
        r"elif\s+{self_var}\s+is\s+not\s+None\b",  # Python: elif self.x is not None
        r"elif\s+{var}\s+is\s+not\s+None\b",  # Python: elif x is not None
        r"elif\s+{self_var}\s*:",  # Python: elif self.x:
        r"elif\s+{var}\s*:",  # Python: elif x:
    ]
)

# isinstance guards: `if isinstance(x, SomeType):` — block body is guarded
_ISINSTANCE_GUARD_RE = [
    re.compile(r"if\s+isinstance\s*\(\s*self\.(\w+)\s*,"),
    re.compile(r"if\s+isinstance\s*\(\s*(\w+)\s*,"),
    re.compile(r"elif\s+isinstance\s*\(\s*self\.(\w+)\s*,"),
    re.compile(r"elif\s+isinstance\s*\(\s*(\w+)\s*,"),
]

# hasattr guards: `if hasattr(obj, 'attr'):` — block body is guarded for the object
_HASATTR_GUARD_RE = [
    re.compile(r"if\s+hasattr\s*\(\s*(\w+)\s*,"),
    re.compile(r"elif\s+hasattr\s*\(\s*(\w+)\s*,"),
]

# Early-exit patterns: `if x is None: raise/return` — continuation is guarded
_EARLY_EXIT_PATTERNS = _build_patterns(
    [
        r"if\s+{self_var}\s+is\s+None\s*:",  # Python: if self.x is None:
        r"if\s+{var}\s+is\s+None\s*:",  # Python: if x is None:
        r"if\s+{var}\s*==\s*None\s*:",  # Python: if x == None:
        r"if\s+not\s+{self_var}\s*:",  # Python: if not self.x:
        r"if\s+not\s+{var}\s*:",  # Python: if not x:
        r"if\s*\(\s*{var}\s*===?\s*null\s*\)",  # JS/TS: if (x === null)
        r"if\s*\(\s*!\s*{var}\s*\)",  # JS/TS: if (!x)
    ]
)

# Assert patterns: `assert x is not None` — everything after is guarded
_ASSERT_PATTERNS = _build_patterns(
    [
        r"assert\s+{self_var}\s+is\s+not\s+None",
        r"assert\s+{var}\s+is\s+not\s+None",
        r"assert\s+isinstance\s*\(\s*{self_var}\s*,",
        r"assert\s+isinstance\s*\(\s*{var}\s*,",
        r"assert\s+{self_var}\b",
        r"assert\s+{var}\b",
    ]
)

# Inline guard patterns: short-circuit and ternary on same line
_INLINE_GUARD_RE = [
    re.compile(r"\bself\.(\w+)\s+and\s+self\.\1\."),  # self.x and self.x.attr
    re.compile(r"\b(\w+)\s+and\s+\1\."),  # x and x.attr
    re.compile(r"\b(\w+)\b.*\bif\s+\1\b.*\belse\b"),  # x if x else default
]

# Reassignment patterns: variable reassigned to a non-None value, clearing nullability
# These detect `x = x or default`, `x = something`, etc.
_REASSIGN_PATTERNS = [
    re.compile(r"self\.(\w+)\s*=\s*self\.\1\s+or\s+\S"),  # self.x = self.x or default
    re.compile(r"(\w+)\s*=\s*\1\s+or\s+\S"),  # x = x or default
    re.compile(r"self\.(\w+)\s*=\s*(?!None\b)\S"),  # self.x = <non-None>
    re.compile(r"(\w+)\s*=\s*(?!None\b|.*\.get\(|.*\.find\(|.*re\.match\(|.*re\.search\()\S"),  # x = <non-None, non-nullable-pattern>
]

# Assignment LHS patterns: detect `self.x = ...` to suppress false positives
# on the attribute name appearing as attribute_access context
_ASSIGNMENT_LHS_PATTERNS = [
    re.compile(r"self\.(\w+)\s*="),  # self.x = ...
    re.compile(r"(\w+)\s*=(?!=)"),  # x = ... (but not x == ...)
]


def _guard_var(guarded: dict[str, set[int]], var_name: str, lineno: int) -> None:
    """Mark a variable as guarded on a specific line."""
    guarded.setdefault(var_name, set()).add(lineno)


def _check_inline_and_lhs_guards(
    stripped: str, lineno: int, guarded: dict[str, set[int]],
) -> None:
    """Check inline guard patterns and assignment LHS patterns for same-line suppression."""
    for pattern in _INLINE_GUARD_RE:
        m = pattern.search(stripped)
        if m:
            _guard_var(guarded, m.group(1), lineno)

    for pattern in _ASSIGNMENT_LHS_PATTERNS:
        m = pattern.search(stripped)
        if m:
            _guard_var(guarded, m.group(1), lineno)


def _check_reassignment_guards(
    stripped: str, lineno: int, guarded: dict[str, set[int]],
    assert_guarded_from: dict[str, int],
) -> None:
    """Detect reassignment to non-None values — guards all subsequent lines."""
    for pattern in _REASSIGN_PATTERNS:
        m = pattern.match(stripped)
        if m:
            var_name = m.group(1)
            assert_guarded_from.setdefault(var_name, lineno)
            _guard_var(guarded, var_name, lineno)
            break


def _check_assert_guards(
    stripped: str, lineno: int, assert_guarded_from: dict[str, int],
) -> None:
    """Detect assert guards — all lines after assert are guarded."""
    if not stripped.startswith("assert "):
        return
    for pattern in _ASSERT_PATTERNS:
        m = pattern.match(stripped)
        if m:
            assert_guarded_from.setdefault(m.group(1), lineno + 1)
            break


def _check_early_exit_guards(
    stripped: str, indent: int, lineno: int, guarded: dict[str, set[int]],
    early_exit_guards: list[tuple[str, int, int, bool]],
    assert_guarded_from: dict[str, int],
) -> None:
    """Detect early-exit patterns: `if x is None: raise/return`."""
    for pattern in _EARLY_EXIT_PATTERNS:
        m = pattern.match(stripped)
        if not m:
            continue

        var_name = m.group(1)
        _guard_var(guarded, var_name, lineno)
        early_exit_guards.append((var_name, indent, lineno, False))

        # Single-line early exit: `if x is None: raise ValueError`
        after_colon = stripped.split(":", 1)
        if len(after_colon) > 1:
            body = after_colon[1].strip()
            if body.startswith(("raise", "return", "continue", "break", "throw")):
                assert_guarded_from.setdefault(var_name, lineno + 1)
                early_exit_guards[:] = [
                    (v, g, s, h) for v, g, s, h in early_exit_guards
                    if not (v == var_name and s == lineno)
                ]
        break


def _check_block_guards(
    stripped: str, indent: int, lineno: int, guarded: dict[str, set[int]],
    active_guards: list[tuple[str, int, int]],
) -> None:
    """Detect block guard patterns: `if x is not None:`, `isinstance()`, `hasattr()`."""
    for pattern in _GUARD_PATTERNS:
        m = pattern.match(stripped)
        if m:
            var_name = m.group(1)
            active_guards.append((var_name, indent, lineno))
            _guard_var(guarded, var_name, lineno)
            return

    for pattern in _ISINSTANCE_GUARD_RE:
        m = pattern.match(stripped)
        if m:
            var_name = m.group(1)
            active_guards.append((var_name, indent, lineno))
            _guard_var(guarded, var_name, lineno)
            return

    for pattern in _HASATTR_GUARD_RE:
        m = pattern.match(stripped)
        if m:
            var_name = m.group(1)
            active_guards.append((var_name, indent, lineno))
            _guard_var(guarded, var_name, lineno)
            return


# Lines with type: ignore comments are developer-acknowledged nullable accesses
_TYPE_IGNORE_RE = re.compile(r"#\s*type:\s*ignore")


def _find_guarded_lines(
    source_bytes: bytes,
    language: str,
) -> dict[str, set[int]]:
    """Find lines where a variable is guarded by a None check.

    Returns {variable_name: {set of guarded line numbers}}.
    Also treats `# type: ignore` as developer acknowledgment of nullability.
    """
    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    guarded: dict[str, set[int]] = {}

    # Pre-scan: lines with # type: ignore guard ALL variables on that line
    for i, line in enumerate(lines):
        if _TYPE_IGNORE_RE.search(line):
            # Extract any attribute-access variable names on this line
            for m in re.finditer(r"(?:self\.)?(\w+)\.", line):
                _guard_var(guarded, m.group(1), i + 1)

    active_guards: list[tuple[str, int, int]] = []
    early_exit_guards: list[tuple[str, int, int, bool]] = []
    assert_guarded_from: dict[str, int] = {}

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        lineno = i + 1

        # Close any guards that have ended (dedent)
        active_guards = [
            (var, gi, sl) for var, gi, sl in active_guards
            if indent > gi or not stripped
        ]

        # Process early-exit guard block endings
        new_early_exits = []
        for var, gi, sl, has_exit in early_exit_guards:
            if indent <= gi and stripped:
                if has_exit:
                    assert_guarded_from.setdefault(var, lineno)
            else:
                if not has_exit and stripped.startswith(("raise", "return", "continue", "break", "throw")):
                    has_exit = True
                new_early_exits.append((var, gi, sl, has_exit))
        early_exit_guards = new_early_exits

        # Mark current line as guarded for active block guards
        for var_name, _, _ in active_guards:
            _guard_var(guarded, var_name, lineno)

        # Mark current line as guarded for assert/early-exit continuation
        for var_name, from_line in assert_guarded_from.items():
            if lineno >= from_line:
                _guard_var(guarded, var_name, lineno)

        # Run all guard detectors
        _check_inline_and_lhs_guards(stripped, lineno, guarded)
        _check_reassignment_guards(stripped, lineno, guarded, assert_guarded_from)
        _check_assert_guards(stripped, lineno, assert_guarded_from)
        _check_early_exit_guards(stripped, indent, lineno, guarded, early_exit_guards, assert_guarded_from)
        _check_block_guards(stripped, indent, lineno, guarded, active_guards)

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


def _find_self_assigned_attrs(
    semantics: FileSemantics,
    nullable_vars: dict[tuple[str, int], TypeInfo],
) -> set[tuple[str, int]]:
    """Identify nullable vars assigned via self/this/cls attribute access (e.g. `self.x = None`)."""
    _self_keywords = {"self", "this", "cls"}
    self_assigned_attrs: set[tuple[str, int]] = set()

    _nullable_assign_lines: dict[tuple[str, int], set[int]] = {}
    for a in semantics.assignments:
        vt = getattr(a, "value_text", "")
        if vt == "None" or vt == "null" or vt == "nil":
            _nullable_assign_lines.setdefault((a.name, a.scope_id), set()).add(a.line)

    for key in nullable_vars:
        name, scope_id = key
        alines = _nullable_assign_lines.get(key, set())
        if not alines:
            continue
        for ref in semantics.references:
            if (
                ref.name == name
                and ref.scope_id == scope_id
                and ref.context == "attribute_access"
                and ref.receiver in _self_keywords
                and ref.line in alines
            ):
                self_assigned_attrs.add(key)
                break

    return self_assigned_attrs


def _resolve_key_in_scope_chain(
    name: str,
    scope_id: int,
    nullable_vars: dict[tuple[str, int], TypeInfo],
    semantics: FileSemantics,
) -> tuple[str, int] | None:
    """Resolve a (name, scope_id) key by walking up the scope chain."""
    if (name, scope_id) in nullable_vars:
        return (name, scope_id)
    for scope in semantics.scopes:
        if scope.scope_id != scope_id:
            continue
        parent = scope.parent_id
        while parent is not None:
            if (name, parent) in nullable_vars:
                return (name, parent)
            for s in semantics.scopes:
                if s.scope_id == parent:
                    parent = s.parent_id
                    break
            else:
                break
        break
    return None


def _source_description(tinfo: TypeInfo) -> str:
    """Build a human-readable source description for a nullable type."""
    if tinfo.source == "return_type":
        return " (from nullable return value)"
    if tinfo.source == "literal" and tinfo.inferred_type == InferredType.NONE:
        return " (assigned None)"
    if tinfo.source == "annotation":
        return " (typed as Optional)"
    return ""


def _check_nullable_attr_refs(
    semantics: FileSemantics,
    nullable_vars: dict[tuple[str, int], TypeInfo],
    self_assigned_attrs: set[tuple[str, int]],
    guarded_lines: dict,
    filepath: str,
    seen: set,
) -> list[Finding]:
    """Check attribute-access references on nullable variables."""
    findings = []

    for ref in semantics.references:
        if ref.context != "attribute_access":
            continue

        # If there's a receiver, check if this is a non-self-assigned attr
        if ref.receiver is not None:
            resolved_key = _resolve_key_in_scope_chain(
                ref.name, ref.scope_id, nullable_vars, semantics,
            )
            if resolved_key is not None and resolved_key not in self_assigned_attrs:
                continue

        tinfo = _resolve_nullable_in_scope(ref.name, ref.scope_id, nullable_vars, semantics)  # type: ignore[assignment]  # None handled on next line
        if tinfo is None:
            continue

        if ref.name in guarded_lines and ref.line in guarded_lines[ref.name]:
            continue

        dedup_key = (filepath, ref.line, ref.name)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        source_desc = _source_description(tinfo)
        findings.append(
            Finding(
                file=filepath,
                line=ref.line,
                severity=Severity.WARNING,
                category=Category.BUG,
                source=Source.AST,
                rule="null-dereference",
                message=(f"Attribute access on '{ref.name}' which may be None{source_desc}"),
                suggestion=(
                    f"Add a None check before accessing attributes on '{ref.name}' (e.g., 'if {ref.name} is not None:')"
                ),
            )
        )

    return findings


def _check_nullable_call_refs(
    semantics: FileSemantics,
    nullable_vars: dict[tuple[str, int], TypeInfo],
    guarded_lines: dict,
    filepath: str,
    seen: set,
) -> list[Finding]:
    """Check method calls on nullable receiver variables."""
    findings = []

    for call in semantics.function_calls:
        if call.receiver is None:
            continue

        tinfo = _resolve_nullable_in_scope(call.receiver, call.scope_id, nullable_vars, semantics)  # type: ignore[assignment]  # None handled on next line
        if tinfo is None:
            continue

        if call.receiver in guarded_lines and call.line in guarded_lines[call.receiver]:
            continue

        dedup_key = (filepath, call.line, call.receiver)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        findings.append(
            Finding(
                file=filepath,
                line=call.line,
                severity=Severity.WARNING,
                category=Category.BUG,
                source=Source.AST,
                rule="null-dereference",
                message=(f"Method '{call.name}' called on '{call.receiver}' which may be None"),
                suggestion=(
                    f"Add a None check before calling methods on '{call.receiver}' "
                    f"(e.g., 'if {call.receiver} is not None:')"
                ),
            )
        )

    return findings


def check_null_safety(
    semantics: FileSemantics,
    type_map: FileTypeMap,
    config: LanguageConfig,
    filepath: str,
    cfgs: dict | None = None,
    source_bytes: bytes | None = None,
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

    # Collect nullable variables
    nullable_vars: dict[tuple[str, int], TypeInfo] = {}
    for key, tinfo in type_map.types.items():
        if tinfo.nullable or tinfo.inferred_type in (InferredType.NONE, InferredType.OPTIONAL):
            nullable_vars[key] = tinfo

    if not nullable_vars:
        return []

    self_assigned_attrs = _find_self_assigned_attrs(semantics, nullable_vars)

    # Use provided source bytes, fall back to disk read
    if source_bytes is None:
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source_bytes = f.read().encode("utf-8")
        except OSError:
            return []

    guarded_lines = _find_guarded_lines(source_bytes, semantics.language)
    seen: set = set()

    findings = _check_nullable_attr_refs(
        semantics, nullable_vars, self_assigned_attrs, guarded_lines, filepath, seen,
    )
    findings.extend(_check_nullable_call_refs(
        semantics, nullable_vars, guarded_lines, filepath, seen,
    ))

    return findings
