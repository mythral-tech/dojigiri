"""Architectural smell detection: god classes, feature envy, near-duplicates, long methods.

Semantic similarity with normalized signatures (variable names stripped).
Uses structural hashing with multiset Jaccard on call sequences + count-based
scope/assignment comparison. Returns [] when tree-sitter is not available.

Called by: detector.py, analyzer.py (cross-file clones)
Calls into: semantic/core.py, config.py
Data in → Data out: FileSemantics (or dict of them for cross-file) → list[Finding]
"""

from __future__ import annotations  # noqa

from collections import Counter
from dataclasses import dataclass

from ..types import Category, Finding, Severity, Source
from .core import FileSemantics, FunctionDef

# ─── Check: God Class ────────────────────────────────────────────────


def check_god_class(
    semantics: FileSemantics,
    filepath: str,
    method_threshold: int = 20,
    attribute_threshold: int = 15,
) -> list[Finding]:
    """Flag classes with too many methods AND attributes.

    A true god class has excessive responsibility on *both* axes: it manages
    too much state (attributes) AND exposes too many behaviors (methods).

    Classes that exceed only one threshold are typically not god classes:
    - Many methods + few attributes → service/facade class (intentional API surface)
    - Many attributes + few methods → data/config class (intentional data carrier)

    Previous heuristic (OR logic, low thresholds) produced heavy false positives
    on framework base classes (Flask App, FastAPI router), data models, and
    config objects.
    """
    findings = []

    # Collect method names per class so we can exclude them from attribute counts.
    # The extractor counts `def method_name` at class scope as an assignment,
    # which inflates attribute_names with method names.
    class_method_names: dict[str, set[str]] = {}
    for fdef in semantics.function_defs:
        if fdef.parent_class:
            class_method_names.setdefault(fdef.parent_class, set()).add(fdef.name)

    for cdef in semantics.class_defs:
        # True attributes = attribute_names minus method names
        method_names = class_method_names.get(cdef.name, set())
        true_attrs = [a for a in cdef.attribute_names if a not in method_names]

        methods_over = cdef.method_count > method_threshold
        attrs_over = len(true_attrs) > attribute_threshold

        # Require BOTH thresholds exceeded — a class that's large on only
        # one axis is a service class or data class, not a god class.
        if methods_over and attrs_over:
            reasons = [
                f"{cdef.method_count} methods (>{method_threshold})",
                f"{len(true_attrs)} attributes (>{attribute_threshold})",
            ]
            findings.append(
                Finding(
                    file=filepath,
                    line=cdef.line,
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    source=Source.AST,
                    rule="god-class",
                    message=f"Class '{cdef.name}' is overly large: {', '.join(reasons)}",
                    suggestion=f"Consider splitting '{cdef.name}' into smaller, focused classes",
                )
            )

    return findings


# ─── Check: Feature Envy ─────────────────────────────────────────────

# Dunder methods that by definition operate on external objects, not self.
# Descriptors (__get__, __set__, __delete__), metaclass hooks, etc.
_DUNDER_SKIP = frozenset({
    "__init__",
    "__get__", "__set__", "__delete__", "__set_name__",
    "__init_subclass__", "__class_getitem__",
    "__enter__", "__exit__", "__aenter__", "__aexit__",
    "__getattr__", "__getattribute__", "__setattr__", "__delattr__",
    "__instancecheck__", "__subclasscheck__",
})

# Minimum method body size (lines) to meaningfully assess feature envy.
_MIN_METHOD_LINES = 5

# Builder/mapper/factory prefixes — these methods deliberately access external
# objects because constructing/transforming is their entire purpose.
_BUILDER_PREFIXES = (
    "build_", "create_", "make_", "from_", "to_",
    "_encode_", "_decode_", "_convert_", "_transform_",
    "_serialize_", "_deserialize_",
)

# Maximum effective body lines for delegation suppression.
_MAX_DELEGATION_LINES = 3


def _is_nested_function(fdef: FunctionDef, all_funcs: list[FunctionDef]) -> bool:
    """Return True if fdef is defined inside another function's body."""
    for other in all_funcs:
        if other is fdef:
            continue
        # fdef is nested if its line range is fully contained within another function
        if other.line < fdef.line and fdef.end_line <= other.end_line:
            return True
    return False


def _has_decorator_wiring(fdef: FunctionDef, semantics: FileSemantics) -> bool:
    """Return True if the method has decorator-style call patterns.

    Detects methods decorated with framework registration patterns like
    @app.route, @blueprint.route — these do cross-object wiring by design.
    We check if there are function calls on the line(s) immediately before
    the def statement (where decorators live).
    """
    # Decorators appear on lines just before the function definition
    for call in semantics.function_calls:
        if fdef.line - 3 <= call.line < fdef.line and call.receiver is not None:
            # A call with a receiver right before the def = decorator like @app.route(...)
            return True
    return False


def _extract_import_names(tokens: list[str]) -> list[str]:
    """Extract bound names from a tokenized import statement.

    Handles ``as`` aliases: ``import foo as bar`` yields ``bar``,
    ``import foo`` yields ``foo`` (top-level module only).
    """
    names: list[str] = []
    i = 0
    while i < len(tokens):
        if i + 1 < len(tokens) and tokens[i + 1] == "as":
            if i + 2 < len(tokens):
                names.append(tokens[i + 2].rstrip(","))
            i += 3
        else:
            names.append(tokens[i].rstrip(",").split(".")[0])
            i += 1
    return names


def _collect_import_names_in_range(
    source_lines: list[str],
    start_line: int,
    end_line: int,
) -> set[str]:
    """Collect names introduced by import statements within a line range."""
    result: set[str] = set()
    for ln in range(start_line, min(end_line + 1, len(source_lines))):
        line = source_lines[ln] if ln < len(source_lines) else ""
        stripped = line.strip()
        if stripped.startswith("import "):
            result.update(_extract_import_names(stripped.split()[1:]))
        elif stripped.startswith("from ") and " import " in stripped:
            after_import = stripped.split(" import ", 1)[1]
            tokens = after_import.replace(",", " ").split()
            result.update(_extract_import_names(tokens))
    return result


def _excluded_receivers(semantics: FileSemantics, fdef: FunctionDef) -> frozenset[str]:
    """Build the set of receiver names to exclude from external ref counting.

    Excludes:
    - Import names (``import foo`` / ``from bar import foo`` → ``foo.x`` is
      a module access, not feature envy)
    - Local variable names assigned within the method body (``url = urlsplit(self.x)``
      → ``url.path`` is derived from self, not a foreign object)
    - Parameter names (already the method's own inputs, accessing their attrs
      is the method's job)
    """
    excluded: set[str] = set()

    # 1. Import names visible at module level
    if semantics.source_lines:
        excluded.update(_collect_import_names_in_range(
            semantics.source_lines, fdef.line, fdef.end_line,
        ))

    # 2. Local variable names assigned within the method
    for asgn in semantics.assignments:
        if fdef.line <= asgn.line <= fdef.end_line and not asgn.is_parameter:
            excluded.add(asgn.name)

    # Note: we do NOT exclude parameter names — a method that heavily
    # accesses a parameter's attributes IS feature envy.  The parameter
    # is a foreign object; the method should probably live on that class.

    return frozenset(excluded)


def _should_suppress_envy(fdef: FunctionDef, semantics: FileSemantics) -> bool:
    """Return True if this method should be suppressed from feature envy check."""
    if fdef.name in _DUNDER_SKIP:
        return True
    if fdef.end_line - fdef.line + 1 < _MIN_METHOD_LINES:
        return True
    if _is_nested_function(fdef, semantics.function_defs):
        return True
    if _has_decorator_wiring(fdef, semantics):
        return True
    if not fdef.params or fdef.params[0] not in ("self", "cls"):
        return True
    if any(fdef.name.startswith(prefix) for prefix in _BUILDER_PREFIXES):
        return True
    if _count_effective_lines(semantics, fdef) <= _MAX_DELEGATION_LINES:
        return True
    return False


def _count_ref_types(
    semantics: FileSemantics,
    fdef: FunctionDef,
    self_kw: str,
    excluded: frozenset[str],
) -> tuple[int, int]:
    """Count internal vs external attribute references in a method.

    Returns (internal_refs, external_refs).
    """
    internal = 0
    external = 0
    for ref in semantics.references:
        if not (fdef.line <= ref.line <= fdef.end_line):
            continue
        if ref.context != "attribute_access":
            continue
        if ref.receiver == self_kw:
            internal += 1
        elif ref.receiver is not None and ref.receiver not in excluded:
            external += 1
    return internal, external


def check_feature_envy(
    semantics: FileSemantics,
    filepath: str,
    external_ratio: float = 3.0,
    min_external: int = 5,
) -> list[Finding]:
    """Flag methods that use more external state than internal state.

    A method has feature envy when it accesses another object's attributes
    more than its own class's attributes.

    Suppressed for:
    - Dunder/protocol methods (descriptors, context managers, metaclass hooks)
    - Methods shorter than 5 lines (too small to meaningfully assess)
    - Inner/nested functions (cross-scope access is intentional)
    - Methods with framework decorator patterns (@app.route, etc.)
    """
    findings = []

    # Build set of attribute names per class
    class_attrs: dict[str, set[str]] = {}
    for cdef in semantics.class_defs:
        class_attrs[cdef.name] = set(cdef.attribute_names)
    for fdef in semantics.function_defs:
        if fdef.parent_class:
            class_attrs.setdefault(fdef.parent_class, set()).add(fdef.name)

    for fdef in semantics.function_defs:
        if not fdef.parent_class:
            continue
        if _should_suppress_envy(fdef, semantics):
            continue

        self_kw = fdef.params[0] if fdef.params else "self"
        excluded = _excluded_receivers(semantics, fdef)
        internal_refs, external_refs = _count_ref_types(semantics, fdef, self_kw, excluded)

        if external_refs > internal_refs * external_ratio and external_refs >= min_external:
            findings.append(
                Finding(
                    file=filepath,
                    line=fdef.line,
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    source=Source.AST,
                    rule="feature-envy",
                    message=(
                        f"Method '{fdef.name}' in '{fdef.parent_class}' accesses "
                        f"{external_refs} external vs {internal_refs} internal attributes"
                    ),
                    suggestion=(
                        f"Consider moving '{fdef.name}' to the class it references most, "
                        "or extract the external access into a helper"
                    ),
                )
            )

    return findings


# ─── Check: Long Method ──────────────────────────────────────────────


def _find_body_start(source: list[str], fdef_line: int, fdef_end: int) -> int:
    """Find the first line of the function body (after the signature colon).

    Scans from the ``def`` line forward to find where the signature ends
    (the line where paren depth returns to 0 and ends with ``:``), then
    returns the next line number.  This correctly skips multi-line
    parameter lists — including ``Annotated[Type, Doc(...)]`` patterns
    with colons inside string literals — so they are never counted as
    body lines.

    Falls back to ``fdef_line + 1`` if the colon cannot be located (e.g.
    source is truncated).
    """
    depth = 0  # paren/bracket nesting
    in_triple_quote = None  # Track """ or '''
    end = min(fdef_end, len(source) - 1)

    for lineno in range(fdef_line, end + 1):
        line = source[lineno] if lineno < len(source) else ""
        # Process character by character, tracking strings and depth
        i = 0
        while i < len(line):
            if in_triple_quote:
                # Look for closing triple quote
                if line[i:i + 3] == in_triple_quote:
                    in_triple_quote = None
                    i += 3
                    continue
                i += 1
                continue

            ch = line[i]
            # Check for triple quotes first (before single-quote check)
            if ch in ('"', "'") and line[i:i + 3] in ('"""', "'''"):
                in_triple_quote = line[i:i + 3]
                i += 3
                continue
            # Skip single-quoted strings
            if ch in ('"', "'"):
                closer = ch
                i += 1
                while i < len(line) and line[i] != closer:
                    if line[i] == '\\':
                        i += 1
                    i += 1
                i += 1  # skip closing quote
                continue
            # Track depth
            if ch in ('(', '[', '{'):
                depth += 1
            elif ch in (')', ']', '}'):
                depth -= 1
            # Check for signature colon at depth 0
            elif ch == ':' and depth == 0:
                # The signature colon should be at/near the end of the line
                rest = line[i + 1:].strip()
                if not rest or rest.startswith('#'):
                    return lineno + 1
            elif ch == '#':
                break  # rest is comment
            i += 1

    # Fallback: assume single-line signature
    return fdef_line + 1


def _count_effective_lines(
    semantics: FileSemantics,
    fdef: FunctionDef,
) -> int:
    """Count effective lines of logic in a function body.

    Only counts lines in the function **body** (after the signature colon).
    The entire signature — including multi-line parameter lists with
    ``Annotated[Type, Doc(...)]`` patterns — is excluded.

    Additionally subtracts from the body:
    - Blank lines
    - Comment-only lines (# ...)
    - Docstring lines (first expression statement if it's a string literal)
    - Pure type-annotation lines (e.g. ``param: Annotated[...]``)

    Falls back to raw line count if source_lines are unavailable.
    """
    total = fdef.end_line - fdef.line + 1
    source = semantics.source_lines
    if not source:
        return total

    # Body starts after the full signature (may span multiple lines)
    body_start = _find_body_start(source, fdef.line, fdef.end_line)
    body_end = min(fdef.end_line, len(source) - 1)

    # Signature lines (def ... params ... :) are all non-logic
    signature_lines = body_start - fdef.line  # includes the def line

    non_logic = 0
    in_docstring = False
    docstring_delimiter = ""  # track which quote style opened the docstring
    docstring_done = False
    first_content_seen = False

    for lineno in range(body_start, body_end + 1):
        line = source[lineno] if lineno < len(source) else ""
        stripped = line.strip()

        # Blank line
        if not stripped:
            non_logic += 1
            continue

        # Comment-only line
        if stripped.startswith("#"):
            non_logic += 1
            continue

        # Inside a multi-line docstring — check BEFORE first_content_seen
        # so continuation lines are always caught regardless of flag state
        if in_docstring:
            non_logic += 1
            # Only close on the SAME delimiter that opened the docstring
            if docstring_delimiter in stripped:
                in_docstring = False
                docstring_done = True
            continue

        # Docstring detection: first non-blank, non-comment content in body
        if not first_content_seen:
            first_content_seen = True
            # Triple-quoted docstring (single or double quotes)
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # Check if docstring opens and closes on same line:
                    # the closing delimiter must appear AFTER the opening one
                    rest = stripped[3:]
                    if quote in rest:
                        non_logic += 1
                        docstring_done = True
                    else:
                        in_docstring = True
                        docstring_delimiter = quote
                        non_logic += 1
                    break
            if in_docstring or docstring_done:
                continue
            # Single-line string literal as docstring (rare but valid)
            if stripped.startswith(("'", '"')) and not stripped.startswith(("'''", '"""')):
                non_logic += 1
                docstring_done = True
                continue

        # Pure type annotation line: "name: Type" or "name: Annotated[...]"
        # Must not contain "=" (that's an assignment) and must have a colon
        if ":" in stripped and "=" not in stripped:
            # Split on first colon — left side should be a simple name
            left = stripped.split(":", 1)[0].strip()
            if left.isidentifier():
                non_logic += 1
                continue

    effective = total - signature_lines - non_logic
    # Never return less than 1
    return max(effective, 1)


def check_long_method(
    semantics: FileSemantics,
    filepath: str,
    threshold: int = 50,
) -> list[Finding]:
    """Flag functions longer than threshold effective lines.

    Effective lines exclude docstrings, blank lines, comment-only lines,
    and pure type annotation lines — preventing false positives on
    well-documented functions with reasonable logic.
    """
    findings = []

    for fdef in semantics.function_defs:
        effective = _count_effective_lines(semantics, fdef)
        if effective > threshold:
            total = fdef.end_line - fdef.line + 1
            label = "Method" if fdef.parent_class else "Function"
            name = fdef.qualified_name.split(":")[-1] if ":" in fdef.qualified_name else fdef.qualified_name
            # Show both effective and total when they differ
            if effective < total:
                size_desc = f"{effective} effective lines ({total} total)"
            else:
                size_desc = f"{effective} lines"
            findings.append(
                Finding(
                    file=filepath,
                    line=fdef.line,
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    source=Source.AST,
                    rule="long-method",
                    message=f"{label} '{name}' is {size_desc} (>{threshold})",
                    suggestion=f"Consider extracting parts of '{fdef.name}' into smaller functions",
                )
            )

    return findings


# ─── Check: Near-Duplicate Functions ─────────────────────────────────


def _structural_hash(fdef: FunctionDef, semantics: FileSemantics) -> tuple | None:
    """Compute a structural signature for a function.

    Signature: (param_count, assignment_count, call_names_sorted, line_span)
    Only computed for functions with >10 statements (enough to be meaningful).
    """
    # Count statements (rough: assignments + calls in this function's scope)
    assignments_in_func = [
        a for a in semantics.assignments if a.scope_id == fdef.scope_id or (fdef.line <= a.line <= fdef.end_line)
    ]
    calls_in_func = [c for c in semantics.function_calls if fdef.line <= c.line <= fdef.end_line]

    stmt_count = len(assignments_in_func) + len(calls_in_func)
    if stmt_count < 10:
        return None

    call_names = sorted(c.name for c in calls_in_func)

    return (
        len(fdef.params),
        len(assignments_in_func),
        tuple(call_names),
        fdef.end_line - fdef.line,  # rough complexity proxy
    )


def check_near_duplicate_functions(
    semantics_by_file: dict[str, FileSemantics],
) -> list[Finding]:
    """Find functions across files with matching structural signatures.

    Uses structural hashing: functions with identical (param_count,
    assignment_count, sorted_call_names, line_span) and >10 statements.
    """
    findings = []

    # Collect all hashes
    hash_to_funcs: dict[tuple, list[tuple[str, FunctionDef]]] = {}

    for filepath, sem in semantics_by_file.items():
        for fdef in sem.function_defs:
            sig = _structural_hash(fdef, sem)
            if sig is not None:
                hash_to_funcs.setdefault(sig, []).append((filepath, fdef))

    # Flag duplicates
    seen_pairs = set()
    for sig, funcs in hash_to_funcs.items():
        if len(funcs) < 2:
            continue

        # Report each pair once
        for i in range(len(funcs)):
            for j in range(i + 1, len(funcs)):
                file_a, func_a = funcs[i]
                file_b, func_b = funcs[j]

                # Skip same function
                if file_a == file_b and func_a.line == func_b.line:
                    continue

                pair_key = tuple(
                    sorted(
                        [
                            (file_a, func_a.line),
                            (file_b, func_b.line),
                        ]
                    )
                )
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                findings.append(
                    Finding(
                        file=file_a,
                        line=func_a.line,
                        severity=Severity.INFO,
                        category=Category.STYLE,
                        source=Source.AST,
                        rule="near-duplicate",
                        message=(
                            f"Function '{func_a.name}' is structurally similar to "
                            f"'{func_b.name}' in {file_b}:{func_b.line}"
                        ),
                        suggestion="Consider extracting shared logic into a common function",
                    )
                )

    return findings


# ─── Semantic Similarity (v1.0.0) ───────────────────────────────────


@dataclass
class SemanticSignature:
    """Normalized function signature — variable names stripped away."""

    param_count: int
    call_sequence: tuple[str, ...]  # sorted call names (with multiplicity)
    assignment_count: int
    scope_count: int  # number of block scopes in the function
    data_flow_hash: int  # hash of assignment patterns

    def similarity(self, other: SemanticSignature) -> float:
        """Compute similarity score (0-1) using multiset Jaccard + count ratios.

        Weights: call_sequence=0.4, scope_count=0.25, assignment=0.15,
        param=0.1, data_flow=0.1.  Total = 1.0.
        """
        score = 0.0

        # Param count similarity (weight: 0.1)
        if self.param_count == other.param_count:
            score += 0.1
        elif max(self.param_count, other.param_count) > 0:
            score += 0.1 * (1.0 - abs(self.param_count - other.param_count) / max(self.param_count, other.param_count))

        # Call sequence multiset Jaccard (weight: 0.4) — preserves multiplicity
        c1 = Counter(self.call_sequence)
        c2 = Counter(other.call_sequence)
        if c1 or c2:
            intersection = sum((c1 & c2).values())
            union = sum((c1 | c2).values())
            score += 0.4 * (intersection / union)
        else:
            score += 0.4  # both empty = identical

        # Assignment count similarity (weight: 0.15)
        max_a = max(self.assignment_count, other.assignment_count)
        if max_a > 0:
            score += 0.15 * (1.0 - abs(self.assignment_count - other.assignment_count) / max_a)
        else:
            score += 0.15

        # Scope count similarity (weight: 0.25)
        max_s = max(self.scope_count, other.scope_count)
        if max_s > 0:
            score += 0.25 * (1.0 - abs(self.scope_count - other.scope_count) / max_s)
        else:
            score += 0.25

        # Data flow hash (weight: 0.1)
        if self.data_flow_hash == other.data_flow_hash:
            score += 0.1

        return score


def build_semantic_signature(
    fdef: FunctionDef,
    semantics: FileSemantics,
    *,
    min_statements: int = 8,
) -> SemanticSignature | None:
    """Build a normalized semantic signature for a function.

    Variable names are stripped — only structural patterns matter.
    Only computed for functions with >= min_statements statements (default 8).
    Functions with many parameters (>= 10) are skipped — they're typically
    API surface methods (route handlers, CLI wrappers) that are intentionally
    similar.
    """
    # Skip high-parameter functions — API surface methods that are
    # intentionally similar (e.g., FastAPI route handlers, Click commands).
    if len(fdef.params) >= 10:
        return None

    # Collect statements in this function
    assignments_in_func = [
        a for a in semantics.assignments if fdef.line <= a.line <= fdef.end_line and not a.is_parameter
    ]
    calls_in_func = [c for c in semantics.function_calls if fdef.line <= c.line <= fdef.end_line]

    stmt_count = len(assignments_in_func) + len(calls_in_func)
    if stmt_count < min_statements:
        return None

    # Call sequence (sorted, normalized)
    call_names = sorted(c.name for c in calls_in_func)

    # Count block scopes within this function
    scope_count = sum(
        1
        for scope in semantics.scopes
        if scope.start_line >= fdef.line and scope.end_line <= fdef.end_line and scope.kind in ("block",)
    )

    # Data flow hash: hash of (assignment_value_types, call_names)
    flow_parts = [a.value_node_type for a in assignments_in_func] + call_names
    data_flow_hash = hash(",".join(flow_parts))

    return SemanticSignature(
        param_count=len(fdef.params),
        call_sequence=tuple(call_names),
        assignment_count=len(assignments_in_func),
        scope_count=scope_count,
        data_flow_hash=data_flow_hash,
    )


@dataclass
class ClonePair:
    """Structured result from semantic clone detection."""

    file_a: str
    func_a_name: str
    func_a_line: int
    file_b: str
    func_b_name: str
    func_b_line: int
    similarity: float


def _transitive_reduce(pairs: list[ClonePair]) -> list[ClonePair]:
    """Remove redundant transitive edges from clone pairs.

    If A~B and B~C are reported, A~C is redundant — the developer can
    already see the cluster via the chain.  We keep the minimum spanning
    edges: for each connected component, build an MST (max-similarity
    spanning tree) and drop all other edges.

    This turns C(N,2) pairs for an N-function clone group into N-1 pairs.
    """
    if len(pairs) <= 1:
        return pairs

    # Collect all unique function nodes
    nodes: set[tuple[str, int]] = set()
    for p in pairs:
        nodes.add((p.file_a, p.func_a_line))
        nodes.add((p.file_b, p.func_b_line))

    if len(nodes) <= 2:
        return pairs

    # Union-Find for Kruskal's MST (max-similarity = sort descending)
    parent: dict[tuple[str, int], tuple[str, int]] = {n: n for n in nodes}

    def find(x: tuple[str, int]) -> tuple[str, int]:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: tuple[str, int], b: tuple[str, int]) -> bool:
        ra, rb = find(a), find(b)
        if ra == rb:
            return False
        parent[ra] = rb
        return True

    # Sort by similarity descending — keep highest-similarity edges first
    sorted_pairs = sorted(pairs, key=lambda p: p.similarity, reverse=True)
    kept: list[ClonePair] = []
    for p in sorted_pairs:
        node_a = (p.file_a, p.func_a_line)
        node_b = (p.file_b, p.func_b_line)
        if union(node_a, node_b):
            kept.append(p)

    return kept


def _is_example_or_docs_path(fp: str) -> bool:
    """Return True if the path is in an example or docs directory."""
    fp_lower = fp.lower().replace("\\", "/")
    return any(
        seg in fp_lower
        for seg in ("/docs_src/", "/docs/", "/examples/", "/example/")
    )


# Same segments used by detector.py's _is_test_path
_CLONE_TEST_PATH_SEGMENTS = (
    "/test/", "/tests/", "test_", "_test.", "/spec/", "/specs/",
)
_CLONE_TEST_FILENAMES = ("conftest.py",)


def _is_test_path_for_clones(fp: str) -> bool:
    """Return True if the path looks like a test file."""
    fp_lower = fp.lower().replace("\\", "/")
    if any(seg in fp_lower for seg in _CLONE_TEST_PATH_SEGMENTS):
        return True
    basename = fp_lower.rsplit("/", 1)[-1]
    return basename in _CLONE_TEST_FILENAMES


def find_semantic_clone_pairs(
    semantics_by_file: dict[str, FileSemantics],
    similarity_threshold: float = 0.85,
) -> list[ClonePair]:
    """Find function pairs with high semantic similarity.

    Returns structured ClonePair objects — callers decide how to present them
    (as Finding, CrossFileFinding, etc). No string parsing needed.

    Applies transitive reduction: if functions A, B, C are all similar,
    only the spanning-tree edges are reported (N-1 pairs instead of N*(N-1)/2).

    Suppresses clones in example/docs directories and between test files.
    """
    pairs: list[ClonePair] = []
    sigs: list[tuple[str, FunctionDef, SemanticSignature]] = []

    for filepath, sem in semantics_by_file.items():
        # Skip files in example/docs directories entirely
        if _is_example_or_docs_path(filepath):
            continue
        for fdef in sem.function_defs:
            sig = build_semantic_signature(fdef, sem)
            if sig:
                sigs.append((filepath, fdef, sig))

    seen = set()
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            file_a, func_a, sig_a = sigs[i]
            file_b, func_b, sig_b = sigs[j]

            if file_a == file_b and func_a.line == func_b.line:
                continue

            # Suppress clone detection within / between test files.
            # Test functions are intentionally repetitive (same setup,
            # similar assertions with different inputs).
            if _is_test_path_for_clones(file_a) and _is_test_path_for_clones(file_b):
                continue

            sim = sig_a.similarity(sig_b)
            if sim >= similarity_threshold:
                pair_key = tuple(
                    sorted(
                        [
                            (file_a, func_a.line),
                            (file_b, func_b.line),
                        ]
                    )
                )
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                pairs.append(
                    ClonePair(
                        file_a=file_a,
                        func_a_name=func_a.name,
                        func_a_line=func_a.line,
                        file_b=file_b,
                        func_b_name=func_b.name,
                        func_b_line=func_b.line,
                        similarity=sim,
                    )
                )

    # Transitive reduction: collapse N*(N-1)/2 pairs into N-1 spanning edges
    return _transitive_reduce(pairs)


def check_semantic_clones(
    semantics_by_file: dict[str, FileSemantics],
    similarity_threshold: float = 0.85,
) -> list[Finding]:
    """Find functions with high semantic similarity — returns Finding objects.

    Thin wrapper over find_semantic_clone_pairs() for backward compatibility
    with single-file callers (detector.py) that expect Finding lists.
    """
    pairs = find_semantic_clone_pairs(semantics_by_file, similarity_threshold)
    return [
        Finding(
            file=p.file_a,
            line=p.func_a_line,
            severity=Severity.INFO,
            category=Category.STYLE,
            source=Source.AST,
            rule="semantic-clone",
            message=(
                f"Function '{p.func_a_name}' is semantically similar "
                f"({p.similarity:.0%}) to '{p.func_b_name}' in {p.file_b}:{p.func_b_line}"
            ),
            suggestion="Consider extracting shared logic into a common function",
        )
        for p in pairs
    ]
