"""Type inference engine: infer types from literals, constructors, annotations, and propagation.

Builds a FileTypeMap mapping (variable_name, scope_id) → TypeInfo.
Used by null safety checks and contract inference.

Returns empty FileTypeMap when tree-sitter is not available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .lang_config import LanguageConfig, get_config
from .core import FileSemantics, Assignment, FunctionDef, ScopeInfo


# ─── Type model ──────────────────────────────────────────────────────

class InferredType(Enum):
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
    SET = "set"
    NONE = "none"
    CALLABLE = "callable"
    INSTANCE = "instance"
    OPTIONAL = "optional"
    UNKNOWN = "unknown"


# Map from Python/TS type annotation strings to InferredType
_ANNOTATION_TYPE_MAP: dict[str, InferredType] = {
    "int": InferredType.INT,
    "float": InferredType.FLOAT,
    "str": InferredType.STRING,
    "string": InferredType.STRING,
    "bool": InferredType.BOOL,
    "boolean": InferredType.BOOL,
    "list": InferredType.LIST,
    "dict": InferredType.DICT,
    "set": InferredType.SET,
    "None": InferredType.NONE,
    "none": InferredType.NONE,
    "null": InferredType.NONE,
    "void": InferredType.NONE,
    "number": InferredType.FLOAT,
    "Array": InferredType.LIST,
    "Map": InferredType.DICT,
    "Set": InferredType.SET,
    "object": InferredType.DICT,
    "Object": InferredType.DICT,
}


@dataclass
class TypeInfo:
    inferred_type: InferredType
    class_name: Optional[str] = None
    nullable: bool = False
    source: str = "literal"  # "literal", "annotation", "constructor", "return_type", "propagated"

    def __repr__(self) -> str:
        parts = [self.inferred_type.value]
        if self.class_name:
            parts.append(f"({self.class_name})")
        if self.nullable:
            parts.append("?")
        return "".join(parts)


@dataclass
class FileTypeMap:
    """Type information for all variables in a file."""
    types: dict[tuple[str, int], TypeInfo] = field(default_factory=dict)  # (var_name, scope_id)
    return_types: dict[str, TypeInfo] = field(default_factory=dict)  # qualified_fn_name → return type


@dataclass
class FunctionContract:
    """Inferred behavioral contract for a function."""
    qualified_name: str
    returns_nullable: bool = False
    param_nullability: dict[str, bool] = field(default_factory=dict)  # param_name → nullable
    return_type: Optional[TypeInfo] = None


# ─── Inference rules ─────────────────────────────────────────────────

def _infer_from_literal(value_node_type: str, config: LanguageConfig) -> Optional[TypeInfo]:
    """Rule 1: Infer type from literal assignment."""
    mapped = config.literal_type_map.get(value_node_type)
    if mapped:
        itype = InferredType(mapped.lower()) if mapped.lower() in [e.value for e in InferredType] else InferredType.UNKNOWN
        return TypeInfo(inferred_type=itype, source="literal")
    return None


def _infer_from_constructor(value_text: str, semantics: FileSemantics) -> Optional[TypeInfo]:
    """Rule 2: Infer type from constructor call — `x = MyClass()`."""
    # Check if value looks like a constructor: CapitalizedName(...)
    stripped = value_text.strip()
    if "(" in stripped:
        name = stripped[:stripped.index("(")].strip()
        if name and name[0].isupper() and name.isidentifier():
            # Check if this class exists in the file
            for cdef in semantics.class_defs:
                if cdef.name == name:
                    return TypeInfo(
                        inferred_type=InferredType.INSTANCE,
                        class_name=name,
                        source="constructor",
                    )
            # Even without class def, treat as instance
            return TypeInfo(
                inferred_type=InferredType.INSTANCE,
                class_name=name,
                source="constructor",
            )
    return None


def _infer_from_annotation(value_text: str, language: str) -> Optional[TypeInfo]:
    """Rule 3: Infer from type annotation (Python: x: int, TS: x: number)."""
    # This is called with annotation text extracted from AST
    text = value_text.strip()

    # Handle Optional[X]
    if text.startswith("Optional[") and text.endswith("]"):
        inner = text[9:-1].strip()
        base = _ANNOTATION_TYPE_MAP.get(inner, InferredType.UNKNOWN)
        return TypeInfo(inferred_type=base, nullable=True, source="annotation")

    # Handle X | None (Python 3.10+)
    if " | None" in text or "None | " in text:
        parts = [p.strip() for p in text.split("|")]
        non_none = [p for p in parts if p != "None"]
        if non_none:
            base = _ANNOTATION_TYPE_MAP.get(non_none[0], InferredType.UNKNOWN)
            return TypeInfo(inferred_type=base, nullable=True, source="annotation")

    # Simple type
    mapped = _ANNOTATION_TYPE_MAP.get(text)
    if mapped:
        return TypeInfo(inferred_type=mapped, source="annotation")

    return None


def _infer_nullable_from_call(value_text: str, config: LanguageConfig) -> Optional[TypeInfo]:
    """Rule 5: Infer nullable from known nullable-return patterns.

    Special case: .get(key, default) with a non-None default is NOT nullable.
    """
    for pattern in config.nullable_return_patterns:
        if pattern in value_text:
            # Check for .get() with a non-None default value
            if pattern.endswith(".get") or pattern == ".get":
                # Match .get(key, default) — if there's a second arg, check if it's None
                m = re.search(r'\.get\s*\([^,]+,\s*(.+?)\s*\)', value_text)
                if m:
                    default_val = m.group(1).strip()
                    if default_val not in ("None", "null", "nil"):
                        # Has a non-None default — not nullable
                        return None
            return TypeInfo(
                inferred_type=InferredType.OPTIONAL,
                nullable=True,
                source="return_type",
            )
    return None


def _infer_none_literal(value_text: str, value_node_type: str) -> Optional[TypeInfo]:
    """Detect explicit None/null/nil assignment."""
    if value_node_type in ("none", "null", "nil"):
        return TypeInfo(inferred_type=InferredType.NONE, nullable=True, source="literal")
    if value_text.strip() in ("None", "null", "nil", "undefined"):
        return TypeInfo(inferred_type=InferredType.NONE, nullable=True, source="literal")
    return None


# ─── Type annotation extraction ─────────────────────────────────────

def _extract_annotations_from_tree(semantics: FileSemantics, source_bytes: bytes) -> dict[tuple[str, int], str]:
    """Extract type annotations from the cached tree-sitter AST.

    Returns {(var_name, scope_id): annotation_text}.
    Only works for Python and TypeScript (languages with type annotations in AST).
    """
    annotations: dict[tuple[str, int], str] = {}
    root = getattr(semantics, '_tree_root', None)
    if root is None:
        return annotations

    lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    language = semantics.language

    if language == "python":
        # Look for type annotations in assignments: x: int = ...
        # tree-sitter Python: type node in typed_parameter, type alias, etc.
        # Simpler approach: regex over source lines
        for asgn in semantics.assignments:
            if asgn.is_parameter:
                continue
            line_idx = asgn.line - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                # Match pattern: varname: type = value  or  varname: type
                m = re.match(
                    r'\s*' + re.escape(asgn.name) + r'\s*:\s*([^=]+?)(?:\s*=|$)',
                    line,
                )
                if m:
                    ann_text = m.group(1).strip()
                    if ann_text:
                        # Find scope
                        annotations[(asgn.name, asgn.scope_id)] = ann_text

        # Also extract return type annotations
        for fdef in semantics.function_defs:
            line_idx = fdef.line - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                m = re.search(r'->\s*(.+?):', line)
                if m:
                    ret_text = m.group(1).strip()
                    # Use the function's OWN scope ID (not the outer scope
                    # where it's defined) so resolution can find it
                    func_scope_id = fdef.scope_id
                    for s in semantics.scopes:
                        if s.kind == "function" and s.name == fdef.qualified_name:
                            func_scope_id = s.scope_id
                            break
                    annotations[("__return__", func_scope_id)] = ret_text

    elif language in ("typescript",):
        for asgn in semantics.assignments:
            line_idx = asgn.line - 1
            if 0 <= line_idx < len(lines):
                line = lines[line_idx]
                # Match: let/const/var name: Type = ...
                m = re.search(
                    re.escape(asgn.name) + r'\s*:\s*([^=;]+?)(?:\s*[=;]|$)',
                    line,
                )
                if m:
                    ann_text = m.group(1).strip()
                    if ann_text:
                        annotations[(asgn.name, asgn.scope_id)] = ann_text

    return annotations


# ─── Main entry points ───────────────────────────────────────────────

def infer_types(
    semantics: FileSemantics,
    source_bytes: bytes,
    config: LanguageConfig,
    cfgs: Optional[dict] = None,
) -> FileTypeMap:
    """Infer types for all variables in the file.

    Priority order:
    1. Type annotations (Python, TypeScript)
    2. Literal assignment (x = 5 → INT)
    3. Constructor (x = MyClass() → INSTANCE)
    4. None/null literal
    5. Nullable return patterns (dict.get → OPTIONAL)
    6. Propagation (y = x → y gets x's type)
    """
    type_map = FileTypeMap()

    # Extract annotations
    annotations = _extract_annotations_from_tree(semantics, source_bytes)

    # Pre-compute lookup dicts for O(1) annotation resolution
    scope_by_id = {s.scope_id: s for s in semantics.scopes}
    fdef_by_qname = {fd.qualified_name: fd for fd in semantics.function_defs}

    # Apply annotation-based types first (highest priority)
    for (name, scope_id), ann_text in annotations.items():
        if name == "__return__":
            # Return type annotation — look up scope then function
            scope = scope_by_id.get(scope_id)
            fdef = fdef_by_qname.get(scope.name) if scope and scope.kind == "function" else None  # type: ignore[arg-type]  # scope.name is str when kind == "function"
            if fdef:
                tinfo = _infer_from_annotation(ann_text, semantics.language)
                if tinfo:
                    type_map.return_types[fdef.qualified_name] = tinfo
        else:
            tinfo = _infer_from_annotation(ann_text, semantics.language)
            if tinfo:
                type_map.types[(name, scope_id)] = tinfo

    # Infer from assignments (rules 1-5)
    for asgn in semantics.assignments:
        key = (asgn.name, asgn.scope_id)
        if key in type_map.types:
            continue  # annotation takes priority

        if asgn.is_parameter:
            continue

        # None/null literal (check before regular literals to preserve nullable flag)
        tinfo = _infer_none_literal(asgn.value_text, asgn.value_node_type)
        if tinfo:
            type_map.types[key] = tinfo
            continue

        # Rule 1: Literal
        tinfo = _infer_from_literal(asgn.value_node_type, config)
        if tinfo:
            type_map.types[key] = tinfo
            continue

        # Rule 2: Constructor
        tinfo = _infer_from_constructor(asgn.value_text, semantics)
        if tinfo:
            type_map.types[key] = tinfo
            continue

        # Rule 5: Nullable return
        tinfo = _infer_nullable_from_call(asgn.value_text, config)
        if tinfo:
            type_map.types[key] = tinfo
            continue

    # Rule 6: Propagation (y = x → y gets x's type)
    # Simple single-pass propagation
    for asgn in semantics.assignments:
        key = (asgn.name, asgn.scope_id)
        if key in type_map.types:
            continue
        if asgn.is_parameter or asgn.is_augmented:
            continue

        # Check if RHS is a single identifier
        rhs = asgn.value_text.strip()
        if rhs.isidentifier():
            # Look up the source variable's type in same or parent scope
            source_key = (rhs, asgn.scope_id)
            if source_key in type_map.types:
                src_type = type_map.types[source_key]
                type_map.types[key] = TypeInfo(
                    inferred_type=src_type.inferred_type,
                    class_name=src_type.class_name,
                    nullable=src_type.nullable,
                    source="propagated",
                )

    # Infer function return types from return statements
    for fdef in semantics.function_defs:
        if fdef.qualified_name in type_map.return_types:
            continue  # annotation takes priority

        has_none_return = False
        has_value_return = False

        # Check source lines for return statements
        lines = source_bytes.decode("utf-8", errors="replace").splitlines()
        for i in range(fdef.line - 1, min(fdef.end_line, len(lines))):
            line = lines[i].strip()
            if line == "return None" or line == "return":
                has_none_return = True
            elif line.startswith("return "):
                has_value_return = True

        if has_none_return and has_value_return:
            type_map.return_types[fdef.qualified_name] = TypeInfo(
                inferred_type=InferredType.OPTIONAL,
                nullable=True,
                source="return_type",
            )

    return type_map


def infer_contracts(
    semantics_by_file: dict[str, FileSemantics],
    type_maps: dict[str, FileTypeMap],
    call_graph: Optional[dict] = None,
) -> dict[str, FunctionContract]:
    """Infer function contracts from type maps across files.

    Returns {qualified_function_name: FunctionContract}.
    """
    contracts: dict[str, FunctionContract] = {}

    for filepath, sem in semantics_by_file.items():
        tmap = type_maps.get(filepath)
        if tmap is None:
            continue

        for fdef in sem.function_defs:
            contract = FunctionContract(qualified_name=fdef.qualified_name)

            # Check return type
            ret_type = tmap.return_types.get(fdef.qualified_name)
            if ret_type:
                contract.return_type = ret_type
                contract.returns_nullable = ret_type.nullable

            # Check parameter nullability (from type annotations)
            for param in fdef.params:
                key = (param, fdef.scope_id)
                if key in tmap.types:
                    contract.param_nullability[param] = tmap.types[key].nullable

            contracts[fdef.qualified_name] = contract

    return contracts
