"""Single-pass AST extraction layer for semantic analysis.

Walks the tree-sitter AST once per file and extracts assignments, references,
function definitions, function calls, class definitions, and scope information.
All other semantic modules operate on these extracted data structures.

Returns None when tree-sitter is not installed (graceful degradation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Iterator
from typing import Any, Optional

from .lang_config import get_config, LanguageConfig


# ─── Data structures ─────────────────────────────────────────────────

@dataclass
class Assignment:
    name: str
    line: int
    scope_id: int
    value_node_type: str
    value_text: str
    is_parameter: bool
    is_augmented: bool


@dataclass
class NameReference:
    name: str
    line: int
    scope_id: int
    context: str  # "read", "call", "attribute_access"


@dataclass
class FunctionDef:
    name: str
    qualified_name: str  # "Class.method" or just "func"
    line: int
    end_line: int
    params: list[str]
    scope_id: int
    parent_class: Optional[str]
    has_varargs: bool = False


@dataclass
class FunctionCall:
    name: str
    line: int
    scope_id: int
    arg_count: int
    receiver: Optional[str]  # "obj" in obj.method()


@dataclass
class ClassDef:
    name: str
    line: int
    end_line: int
    method_count: int
    attribute_names: list[str]
    scope_id: int


@dataclass
class ScopeInfo:
    scope_id: int
    parent_id: Optional[int]
    kind: str  # "module", "function", "class", "block"
    start_line: int
    end_line: int
    name: Optional[str]


@dataclass
class FileSemantics:
    filepath: str
    language: str
    assignments: list[Assignment] = field(default_factory=list)
    references: list[NameReference] = field(default_factory=list)
    function_defs: list[FunctionDef] = field(default_factory=list)
    function_calls: list[FunctionCall] = field(default_factory=list)
    class_defs: list[ClassDef] = field(default_factory=list)
    scopes: list[ScopeInfo] = field(default_factory=list)
    # Cached tree-sitter root node (v0.9.0) — avoids double parsing for CFG
    _tree_root: object = field(default=None, repr=False)


# ─── Helpers ─────────────────────────────────────────────────────────

from ._utils import _get_text, _line, _end_line  # noqa: E402


# ─── Extraction engine ───────────────────────────────────────────────

class _Extractor:
    """Walks the AST once, maintaining a scope stack."""

    def __init__(self, source_bytes: bytes, config: LanguageConfig,
                 filepath: str, language: str):
        self.src = source_bytes
        self.config = config
        self.filepath = filepath
        self.language = language

        self.result = FileSemantics(filepath=filepath, language=language)
        self._scope_counter = 0
        self._scope_stack: list[int] = []
        self._scope_info: dict[int, ScopeInfo] = {}
        self._current_class: Optional[str] = None

        # Sets for fast lookup
        self._assignment_types = set(config.assignment_node_types)
        self._call_types = set(config.call_node_types)
        self._class_types = set(config.class_node_types)
        self._func_types = set(config.function_node_types)
        self._for_types = set(config.cfg_for_node_types)
        self._scope_boundary_types = set(config.scope_boundary_types)
        self._attr_types = set(config.attribute_access_types)
        self._block_types = set(config.block_node_types)

    @property
    def _current_scope(self) -> int:
        return self._scope_stack[-1] if self._scope_stack else 0

    def _push_scope(self, kind: str, node, name: Optional[str] = None) -> int:
        self._scope_counter += 1
        sid = self._scope_counter
        parent = self._current_scope
        info = ScopeInfo(
            scope_id=sid,
            parent_id=parent if parent != 0 or kind != "module" else None,
            kind=kind,
            start_line=_line(node),
            end_line=_end_line(node),
            name=name,
        )
        self._scope_info[sid] = info
        self.result.scopes.append(info)
        self._scope_stack.append(sid)
        return sid

    def _pop_scope(self) -> None:
        if self._scope_stack:
            self._scope_stack.pop()

    def extract(self, root_node: Any) -> None:
        # Module scope
        self._push_scope("module", root_node, name=self.filepath)
        self._walk(root_node)
        self._pop_scope()

    def _walk(self, node: Any) -> None:
        ntype = node.type

        # ── Function definitions ──────────────────────────────────
        if ntype in self._func_types and node.is_named:
            self._handle_function(node)
            return  # children handled inside

        # ── Class definitions ─────────────────────────────────────
        if ntype in self._class_types:
            self._handle_class(node)
            return

        # ── Assignments ───────────────────────────────────────────
        if ntype in self._assignment_types:
            self._handle_assignment(node)

        # ── For-loop variables (treated as assignments) ───────────
        if ntype in self._for_types:
            self._handle_for_loop_var(node)

        # ── Function calls ────────────────────────────────────────
        if ntype in self._call_types:
            self._handle_call(node)

        # ── Identifier references ─────────────────────────────────
        if ntype == "identifier":
            self._handle_identifier(node)

        # ── Block scoping (for block-scoped languages) ────────────
        if self.config.block_scoped and ntype in self._block_types:
            # Only create block scope if parent is not a function/class
            # (those already pushed their own scope)
            parent_type = node.parent.type if node.parent else ""
            if parent_type not in self._func_types and parent_type not in self._class_types:
                self._push_scope("block", node)
                for child in node.children:
                    self._walk(child)
                self._pop_scope()
                return

        # Recurse children
        for child in node.children:
            self._walk(child)

    def _handle_function(self, node: Any) -> None:
        name_node = node.child_by_field_name("name")
        name = _get_text(name_node, self.src) if name_node else "<anonymous>"

        # Build qualified name
        if self._current_class:
            qualified = f"{self._current_class}.{name}"
        else:
            qualified = name

        # Extract parameters
        params = self._extract_params(node)
        has_varargs = self._has_varargs(node)

        fdef = FunctionDef(
            name=name,
            qualified_name=qualified,
            line=_line(node),
            end_line=_end_line(node),
            params=params,
            scope_id=self._current_scope,
            parent_class=self._current_class,
            has_varargs=has_varargs,
        )
        self.result.function_defs.append(fdef)

        # Push function scope and record params as assignments
        self._push_scope("function", node, name=qualified)
        fn_scope = self._current_scope

        for pname in params:
            self.result.assignments.append(Assignment(
                name=pname,
                line=_line(node),
                scope_id=fn_scope,
                value_node_type="parameter",
                value_text="",
                is_parameter=True,
                is_augmented=False,
            ))

        # Walk function body
        for child in node.children:
            self._walk(child)

        self._pop_scope()

    def _handle_class(self, node: Any) -> None:
        name_node = node.child_by_field_name("name")
        name = _get_text(name_node, self.src) if name_node else "<anonymous>"

        prev_class = self._current_class
        self._current_class = name

        self._push_scope("class", node, name=name)

        # Walk children to discover methods and attributes
        attribute_names = []

        for child in node.children:
            self._walk(child)

        # Count methods and attributes from what we collected
        class_scope = self._current_scope
        for asgn in self.result.assignments:
            if asgn.scope_id == class_scope and not asgn.is_parameter:
                if asgn.name not in attribute_names:
                    attribute_names.append(asgn.name)

        actual_methods = sum(
            1 for fd in self.result.function_defs if fd.parent_class == name
        )

        # Collect self.attr assignments as class attributes
        self_kw = self.config.self_keyword
        if self_kw:
            for asgn in self.result.assignments:
                if (asgn.value_node_type == "self_attr"
                        and asgn.name not in attribute_names):
                    attribute_names.append(asgn.name)

        cdef = ClassDef(
            name=name,
            line=_line(node),
            end_line=_end_line(node),
            method_count=actual_methods,
            attribute_names=attribute_names,
            scope_id=self._scope_stack[-2] if len(self._scope_stack) >= 2 else 0,
        )
        self.result.class_defs.append(cdef)

        self._pop_scope()
        self._current_class = prev_class

    def _handle_assignment(self, node: Any) -> None:
        is_augmented = "augmented" in node.type or "compound" in node.type
        lang = self.language

        if lang == "python":
            self._handle_python_assignment(node, is_augmented)
        elif lang in ("javascript", "typescript"):
            self._handle_js_assignment(node, is_augmented)
        elif lang == "go":
            self._handle_go_assignment(node, is_augmented)
        elif lang == "rust":
            self._handle_rust_assignment(node, is_augmented)
        elif lang == "java":
            self._handle_java_assignment(node, is_augmented)
        elif lang == "csharp":
            self._handle_csharp_assignment(node, is_augmented)

    def _handle_for_loop_var(self, node: Any) -> None:
        """Extract for-loop target variable as an assignment.

        Python: for item in items → 'left' field is the loop variable
        JS/TS:  for (var x of items) → 'left' field
        Java:   for (Type x : items) → enhanced_for, name field
        Go:     for i, v := range items → 'left' field
        """
        # Try 'left' field first (Python, JS, Go)
        left = node.child_by_field_name("left")
        if left is None:
            # Java enhanced_for: try 'name' field
            left = node.child_by_field_name("name")
        if left is None:
            return

        # Extract identifier(s) from the loop target
        if left.type == "identifier":
            name = _get_text(left, self.src)
            self.result.assignments.append(Assignment(
                name=name, line=_line(node), scope_id=self._current_scope,
                value_node_type="loop_variable", value_text="",
                is_parameter=False, is_augmented=False,
            ))
        elif left.type in ("pattern_list", "tuple_pattern", "expression_list"):
            # Tuple unpacking in for: for a, b in items
            for child in left.children:
                if child.type == "identifier":
                    name = _get_text(child, self.src)
                    self.result.assignments.append(Assignment(
                        name=name, line=_line(node), scope_id=self._current_scope,
                        value_node_type="loop_variable", value_text="",
                        is_parameter=False, is_augmented=False,
                    ))

    def _record_assignment(
        self, name: str, node: Any, rhs_type: str = "", rhs_text: str = "",
        is_augmented: bool = False, value_node_type: str | None = None,
    ) -> None:
        """Record a variable assignment. Shared by all language handlers."""
        self.result.assignments.append(Assignment(
            name=name, line=_line(node), scope_id=self._current_scope,
            value_node_type=value_node_type or rhs_type,
            value_text=rhs_text,
            is_parameter=False, is_augmented=is_augmented,
        ))

    def _extract_lhs_rhs(self, node: Any) -> tuple[Any | None, Any | None]:
        """Extract left/right children from an assignment node."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return left, right

    def _rhs_info(self, right: Any) -> tuple[str, str]:
        """Extract type and text from an RHS node."""
        rhs_type = right.type if right else ""
        rhs_text = _get_text(right, self.src)[:100] if right else ""
        return rhs_type, rhs_text

    def _handle_python_assignment(self, node: Any, is_augmented: bool) -> None:
        if is_augmented:
            left, _ = self._extract_lhs_rhs(node)
            if left and left.type == "identifier":
                name = _get_text(left, self.src)
                self._record_assignment(name, node, value_node_type="augmented", is_augmented=True)
                self.result.references.append(NameReference(
                    name=name, line=_line(node), scope_id=self._current_scope,
                    context="read",
                ))
        else:
            left, right = self._extract_lhs_rhs(node)

            if left is None:
                children = [c for c in node.children if c.is_named]
                if len(children) >= 2:
                    left, right = children[0], children[-1]

            if left is None:
                return

            rhs_type, rhs_text = self._rhs_info(right)

            # Check for self.attr = ...
            self_kw = self.config.self_keyword
            if left.type in self._attr_types and self_kw:
                obj_node = left.child_by_field_name("object")
                attr_node = left.child_by_field_name("attribute")
                if obj_node and _get_text(obj_node, self.src) == self_kw and attr_node:
                    attr_name = _get_text(attr_node, self.src)
                    self._record_assignment(attr_name, node, rhs_text=rhs_text, value_node_type="self_attr")
                    return

            if left.type == "identifier":
                self._record_assignment(_get_text(left, self.src), node, rhs_type, rhs_text)
            elif left.type in ("pattern_list", "tuple_pattern"):
                for child in left.children:
                    if child.type == "identifier":
                        self._record_assignment(_get_text(child, self.src), node, rhs_type, rhs_text)

    def _handle_js_assignment(self, node: Any, is_augmented: bool) -> None:
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and name_node.type == "identifier":
                rhs_type, rhs_text = self._rhs_info(value_node)
                self._record_assignment(_get_text(name_node, self.src), node, rhs_type, rhs_text)
        elif node.type in ("assignment_expression", "augmented_assignment_expression"):
            left, right = self._extract_lhs_rhs(node)
            if left and left.type == "identifier":
                rhs_type, rhs_text = self._rhs_info(right)
                self._record_assignment(_get_text(left, self.src), node, rhs_type, rhs_text, is_augmented)

    def _handle_go_assignment(self, node: Any, is_augmented: bool) -> None:
        left, right = self._extract_lhs_rhs(node)
        if left:
            rhs_type = right.type if right else ""
            for child in left.children:
                if child.type == "identifier":
                    self._record_assignment(
                        _get_text(child, self.src), node, rhs_type,
                        is_augmented=(is_augmented and node.type != "short_var_declaration"),
                    )

    def _handle_rust_assignment(self, node: Any, is_augmented: bool) -> None:
        if node.type == "let_declaration":
            pat = node.child_by_field_name("pattern")
            value = node.child_by_field_name("value")
            if pat and pat.type == "identifier":
                rhs_type = value.type if value else ""
                self._record_assignment(_get_text(pat, self.src), node, rhs_type)
        elif node.type in ("assignment_expression", "compound_assignment_expr"):
            left, _ = self._extract_lhs_rhs(node)
            if left and left.type == "identifier":
                self._record_assignment(_get_text(left, self.src), node, is_augmented=is_augmented)

    def _handle_java_assignment(self, node: Any, is_augmented: bool) -> None:
        if node.type == "local_variable_declaration":
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and name_node.type == "identifier":
                        rhs_type = value_node.type if value_node else ""
                        self._record_assignment(_get_text(name_node, self.src), node, rhs_type)
        elif node.type == "assignment_expression":
            left, _ = self._extract_lhs_rhs(node)
            if left and left.type == "identifier":
                self._record_assignment(_get_text(left, self.src), node, is_augmented=is_augmented)

    def _handle_csharp_assignment(self, node: Any, is_augmented: bool) -> None:
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name") or (
                node.children[0] if node.children and node.children[0].type == "identifier" else None
            )
            if name_node and name_node.type == "identifier":
                self._record_assignment(_get_text(name_node, self.src), node)
        elif node.type == "assignment_expression":
            left, _ = self._extract_lhs_rhs(node)
            if left and left.type == "identifier":
                self._record_assignment(_get_text(left, self.src), node, is_augmented=is_augmented)

    def _handle_call(self, node: Any) -> None:
        func_node = node.child_by_field_name("function")
        if func_node is None:
            # Java method_invocation uses "name" and "object" fields
            func_node = node.child_by_field_name("name")

        if func_node is None:
            return

        receiver = None
        name = ""

        if func_node.type == "identifier":
            name = _get_text(func_node, self.src)
        elif func_node.type in self._attr_types:
            # obj.method()
            obj = func_node.child_by_field_name("object")
            attr = func_node.child_by_field_name("attribute") or func_node.child_by_field_name("field")
            if obj:
                receiver = _get_text(obj, self.src)
            if attr:
                name = _get_text(attr, self.src)
            else:
                name = _get_text(func_node, self.src)
        else:
            name = _get_text(func_node, self.src)

        # For Java, also check "object" field on the method_invocation itself
        if not receiver and node.type == "method_invocation":
            obj = node.child_by_field_name("object")
            if obj:
                receiver = _get_text(obj, self.src)

        # Count arguments
        args_node = node.child_by_field_name("arguments")
        arg_count = 0
        if args_node:
            for child in args_node.children:
                if child.is_named and child.type not in ("(", ")", ","):
                    arg_count += 1

        self.result.function_calls.append(FunctionCall(
            name=name,
            line=_line(node),
            scope_id=self._current_scope,
            arg_count=arg_count,
            receiver=receiver,
        ))

    def _handle_identifier(self, node: Any) -> None:
        parent = node.parent
        if parent is None:
            return

        # Skip identifiers that are part of declarations / import names
        # (those are handled by their parent node handlers)
        parent_type = parent.type
        skip_parents = {
            "import_statement", "import_from_statement", "import_specifier",
            "import_clause", "dotted_name", "aliased_import",
            "import_declaration", "import_spec", "use_declaration",
            "using_directive",
        }
        if parent_type in skip_parents:
            return

        # Skip if this is the "name" field of a function/class definition
        if parent_type in self._func_types or parent_type in self._class_types:
            name_field = parent.child_by_field_name("name")
            if name_field and name_field.id == node.id:
                return

        # Skip if this is the LHS of an assignment (handled by assignment handler)
        if parent_type in self._assignment_types:
            left = parent.child_by_field_name("left")
            if left and left.id == node.id:
                return
            # Python assignment: check positional children
            children = [c for c in parent.children if c.is_named]
            if children and children[0].id == node.id and parent_type in ("assignment",):
                return

        # Skip parameter names
        param_parents = {
            "parameters", "formal_parameters", "parameter_list",
            "typed_parameter", "default_parameter", "typed_default_parameter",
            "parameter", "formal_parameter", "required_parameter",
        }
        if parent_type in param_parents:
            return

        # Skip variable declarator name fields
        if parent_type == "variable_declarator":
            name_field = parent.child_by_field_name("name")
            if name_field and name_field.id == node.id:
                return

        # Skip let_declaration pattern fields
        if parent_type == "let_declaration":
            pat = parent.child_by_field_name("pattern")
            if pat and pat.id == node.id:
                return

        # Skip short_var_declaration left side
        if parent_type == "short_var_declaration":
            left = parent.child_by_field_name("left")
            if left:
                for child in left.children:
                    if child.id == node.id:
                        return

        name = _get_text(node, self.src)

        # Determine context
        context = "read"
        if parent_type in self._call_types:
            func = parent.child_by_field_name("function")
            if func and func.id == node.id:
                context = "call"
        if parent_type in self._attr_types:
            context = "attribute_access"

        self.result.references.append(NameReference(
            name=name,
            line=_line(node),
            scope_id=self._current_scope,
            context=context,
        ))

    def _extract_params(self, func_node) -> list[str]:
        """Extract parameter names from a function node."""
        params: list[str] = []
        for child in func_node.children:
            if child.type in ("parameters", "formal_parameters", "parameter_list"):
                self._collect_param_names(child, params)
                break
        return params

    def _collect_param_names(self, param_list: Any, params: list[str]) -> None:
        """Recursively collect parameter names."""
        for child in param_list.children:
            if child.type == "identifier":
                parent_type = child.parent.type if child.parent else ""
                # Check this is the name, not a type annotation
                if parent_type in ("parameters", "formal_parameters", "parameter_list"):
                    params.append(_get_text(child, self.src))
                elif parent_type in ("typed_parameter", "default_parameter",
                                     "typed_default_parameter"):
                    name_field = child.parent.child_by_field_name("name")
                    if name_field and name_field.id == child.id:
                        params.append(_get_text(child, self.src))
                elif parent_type in ("parameter", "formal_parameter", "required_parameter"):
                    name_field = child.parent.child_by_field_name("name")
                    if name_field and name_field.id == child.id:
                        params.append(_get_text(child, self.src))
            elif child.type in ("typed_parameter", "default_parameter",
                                "typed_default_parameter", "parameter",
                                "formal_parameter", "required_parameter"):
                self._collect_param_names(child, params)
            elif child.type == "list_splat_pattern" or child.type == "dictionary_splat_pattern":
                # *args, **kwargs in Python
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(_get_text(sub, self.src))
            elif child.type == "rest_pattern":
                # ...rest in JS
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(_get_text(sub, self.src))

    def _has_varargs(self, func_node) -> bool:
        """Check if function has *args/**kwargs or ...rest."""
        for child in func_node.children:
            if child.type in ("parameters", "formal_parameters", "parameter_list"):
                for param in self._walk_all(child):
                    if param.type in ("list_splat_pattern", "dictionary_splat_pattern",
                                      "rest_pattern", "spread_element"):
                        return True
        return False

    def _walk_all(self, node: Any) -> Iterator[Any]:
        """Simple tree walker."""
        yield node
        for child in node.children:
            yield from self._walk_all(child)


# ─── Entry point ─────────────────────────────────────────────────────

def extract_semantics(content: str, filepath: str, language: str) -> Optional[FileSemantics]:
    """Single-pass extraction. Returns None if tree-sitter unavailable."""
    config = get_config(language)
    if config is None:
        return None

    # Need at least assignment or call types to do anything useful
    if not config.assignment_node_types and not config.call_node_types:
        return None

    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return None

    try:
        parser = get_parser(config.ts_language_name)  # type: ignore[arg-type]  # tree-sitter-language-pack has no stubs
    except (LookupError, ValueError, RuntimeError):
        return None

    source_bytes = content.encode("utf-8")
    tree = parser.parse(source_bytes)

    extractor = _Extractor(source_bytes, config, filepath, language)
    extractor.extract(tree.root_node)
    # Cache tree root to avoid double parsing in CFG construction
    extractor.result._tree_root = tree.root_node
    return extractor.result
