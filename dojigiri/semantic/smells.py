"""Architectural smell detection: god classes, feature envy, near-duplicates, long methods.

Semantic similarity with normalized signatures (variable names stripped).
Uses structural hashing with multiset Jaccard on call sequences + count-based
scope/assignment comparison. Returns [] when tree-sitter is not available.

Called by: detector.py, analyzer.py (cross-file clones)
Calls into: semantic/core.py, config.py
Data in → Data out: FileSemantics (or dict of them for cross-file) → list[Finding]
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..types import Category, Finding, Severity, Source
from .core import FileSemantics, FunctionDef

# ─── Check: God Class ────────────────────────────────────────────────


def check_god_class(
    semantics: FileSemantics,
    filepath: str,
    method_threshold: int = 15,
    attribute_threshold: int = 10,
) -> list[Finding]:
    """Flag classes with too many methods or attributes."""
    findings = []

    for cdef in semantics.class_defs:
        reasons = []
        if cdef.method_count > method_threshold:
            reasons.append(f"{cdef.method_count} methods (>{method_threshold})")
        if len(cdef.attribute_names) > attribute_threshold:
            reasons.append(f"{len(cdef.attribute_names)} attributes (>{attribute_threshold})")

        if reasons:
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


def check_feature_envy(
    semantics: FileSemantics,
    filepath: str,
    external_ratio: float = 2.0,
    min_external: int = 3,
) -> list[Finding]:
    """Flag methods that use more external state than internal state.

    A method has feature envy when it accesses another object's attributes
    more than its own class's attributes.
    """
    findings = []

    # Build set of attribute names per class
    class_attrs: dict[str, set[str]] = {}
    for cdef in semantics.class_defs:
        class_attrs[cdef.name] = set(cdef.attribute_names)

    # Also add method names as internal references
    for fdef in semantics.function_defs:
        if fdef.parent_class:
            class_attrs.setdefault(fdef.parent_class, set()).add(fdef.name)

    # Check each method
    for fdef in semantics.function_defs:
        if not fdef.parent_class:
            continue

        internal_attrs = class_attrs.get(fdef.parent_class, set())
        if not internal_attrs:
            continue

        # Count internal vs external attribute references in this function
        internal_refs = 0
        external_refs = 0

        for ref in semantics.references:
            if ref.scope_id != fdef.scope_id:
                # Check if ref is in a child scope of this function
                continue
            if ref.context == "attribute_access":
                if ref.name in internal_attrs:
                    internal_refs += 1
                else:
                    external_refs += 1

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


def check_long_method(
    semantics: FileSemantics,
    filepath: str,
    threshold: int = 50,
) -> list[Finding]:
    """Flag functions longer than threshold lines."""
    findings = []

    for fdef in semantics.function_defs:
        length = fdef.end_line - fdef.line + 1
        if length > threshold:
            label = "Method" if fdef.parent_class else "Function"
            name = fdef.qualified_name.split(":")[-1] if ":" in fdef.qualified_name else fdef.qualified_name
            findings.append(
                Finding(
                    file=filepath,
                    line=fdef.line,
                    severity=Severity.INFO,
                    category=Category.STYLE,
                    source=Source.AST,
                    rule="long-method",
                    message=f"{label} '{name}' is {length} lines long (>{threshold})",
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
) -> SemanticSignature | None:
    """Build a normalized semantic signature for a function.

    Variable names are stripped — only structural patterns matter.
    Only computed for functions with >5 statements.
    """
    # Collect statements in this function
    assignments_in_func = [
        a for a in semantics.assignments if fdef.line <= a.line <= fdef.end_line and not a.is_parameter
    ]
    calls_in_func = [c for c in semantics.function_calls if fdef.line <= c.line <= fdef.end_line]

    stmt_count = len(assignments_in_func) + len(calls_in_func)
    if stmt_count < 5:
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


def find_semantic_clone_pairs(
    semantics_by_file: dict[str, FileSemantics],
    similarity_threshold: float = 0.85,
) -> list[ClonePair]:
    """Find function pairs with high semantic similarity.

    Returns structured ClonePair objects — callers decide how to present them
    (as Finding, CrossFileFinding, etc). No string parsing needed.
    """
    pairs: list[ClonePair] = []
    sigs: list[tuple[str, FunctionDef, SemanticSignature]] = []

    for filepath, sem in semantics_by_file.items():
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

    return pairs


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
