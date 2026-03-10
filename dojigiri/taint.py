"""Cross-file and enhanced intra-file taint tracking.

Adds two capabilities missing from semantic/taint.py:
1. Variable indirection via function parameter taint — treats function params
   as potential taint sources when they flow to sinks (catches `def f(x): eval(x)`
   and callers like `f(user_input)`).
2. Cross-file taint tracking — follows imports to detect taint flowing across
   module boundaries (e.g. utils.get_query(request.args['name']) → SQL injection).

Uses Python's built-in ast module (always available) for import resolution and
function body analysis. The semantic/taint.py module handles the tree-sitter-based
intra-procedural analysis; this module sits on top of it.

Called by: detector.py (intra-file), analyzer.py (cross-file)
Calls into: types.py
Data in → Data out:
  - (filepath, content) → list[Finding] (intra-file parameter taint)
  - dict[filepath, content] → list[CrossFileFinding] (cross-file taint)
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass

from .types import Category, CrossFileFinding, Finding, Severity, Source

logger = logging.getLogger(__name__)

# ─── Taint sources / sinks (AST-based, mirrors semantic/lang_config.py) ────

# Attribute chains that produce tainted data
TAINT_SOURCE_ATTRS = {
    ("request", "args"): "user_input",
    ("request", "form"): "user_input",
    ("request", "json"): "user_input",
    ("request", "data"): "user_input",
    ("request", "values"): "user_input",
    ("request", "cookies"): "user_input",
    ("request", "headers"): "user_input",
    ("os", "environ"): "env_var",
    ("sys", "argv"): "user_input",
}

# Function calls that produce tainted data
TAINT_SOURCE_CALLS = {
    "input": "user_input",
}

# Method/function calls that are dangerous sinks
TAINT_SINK_PATTERNS: list[tuple[str, str]] = [
    ("cursor.execute", "sql_query"),
    ("conn.execute", "sql_query"),
    ("connection.execute", "sql_query"),
    ("db.execute", "sql_query"),
    ("execute", "sql_query"),
    ("executemany", "sql_query"),
    ("os.system", "system_cmd"),
    ("os.popen", "system_cmd"),
    ("subprocess.run", "system_cmd"),
    ("subprocess.call", "system_cmd"),
    ("subprocess.Popen", "system_cmd"),
    ("eval", "eval"),
    ("exec", "eval"),
    ("pickle.loads", "deserialization"),
    ("yaml.load", "deserialization"),
    ("Template", "ssti"),
    ("render_template_string", "ssti"),
    ("requests.get", "ssrf"),
    ("requests.post", "ssrf"),
    ("requests.put", "ssrf"),
    ("requests.delete", "ssrf"),
    ("requests.patch", "ssrf"),
    ("requests.head", "ssrf"),
    ("requests.request", "ssrf"),
    ("httpx.get", "ssrf"),
    ("httpx.post", "ssrf"),
    ("httpx.put", "ssrf"),
    ("httpx.delete", "ssrf"),
    ("httpx.patch", "ssrf"),
    ("httpx.head", "ssrf"),
    ("httpx.request", "ssrf"),
    ("urllib.request.urlopen", "ssrf"),
    ("urlopen", "ssrf"),
    ("aiohttp.ClientSession.get", "ssrf"),
    ("aiohttp.ClientSession.post", "ssrf"),
]

# Functions that sanitize tainted data
SANITIZER_CALLS = frozenset({
    "html.escape",
    "bleach.clean",
    "markupsafe.escape",
    "shlex.quote",
    "urllib.parse.quote",
    "int",
    "float",
    "bool",
    "parameterize",
    "escape",
})


# ─── Data structures ─────────────────────────────────────────────────


@dataclass
class TaintVar:
    """A variable with taint status tracked through a function body."""

    name: str
    tainted: bool
    source_kind: str  # "user_input", "env_var", "parameter", "propagated"
    source_line: int
    source_file: str


@dataclass
class FunctionTaintSummary:
    """Summary of a function's taint behavior for cross-file analysis."""

    name: str
    qualified_name: str  # module.function or module.Class.method
    filepath: str
    line: int
    params: list[str]
    # Which parameters flow to sinks (index → sink kind)
    param_flows_to_sink: dict[int, str]
    # Whether the function returns tainted data based on parameters
    returns_tainted_param: bool
    # Which parameter indices are returned (potentially tainted)
    returned_param_indices: set[int]


@dataclass
class ImportInfo:
    """Resolved import information."""

    local_name: str  # name as used in the importing file
    module: str  # source module path
    original_name: str  # name in the source module
    line: int


# ─── AST helpers ──────────────────────────────────────────────────────


def _get_call_name(node: ast.Call) -> str | None:
    """Extract the full dotted call name from an ast.Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    return None


def _get_name(node: ast.expr) -> str | None:
    """Extract a simple name from an AST node."""
    if isinstance(node, ast.Name):
        return node.id
    return None


def _expr_contains_name(node: ast.expr, name: str) -> bool:
    """Check if an expression references a given variable name."""
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, ast.JoinedStr):
        # f-string: check all values
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and _expr_contains_name(value.value, name):
                return True
    if isinstance(node, ast.BinOp):
        return _expr_contains_name(node.left, name) or _expr_contains_name(node.right, name)
    if isinstance(node, ast.Call):
        call_name = _get_call_name(node)
        if call_name and call_name in SANITIZER_CALLS:
            return False  # sanitized
        for arg in node.args:
            if _expr_contains_name(arg, name):
                return True
        for kw in node.keywords:
            if kw.value and _expr_contains_name(kw.value, name):
                return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_contains_name(elt, name) for elt in node.elts)
    if isinstance(node, ast.Dict):
        for v in node.values:
            if v and _expr_contains_name(v, name):
                return True
    if isinstance(node, ast.Subscript):
        return _expr_contains_name(node.value, name) or (
            isinstance(node.slice, ast.expr) and _expr_contains_name(node.slice, name)
        )
    if isinstance(node, ast.Attribute):
        return _expr_contains_name(node.value, name)
    if isinstance(node, ast.IfExp):
        return (
            _expr_contains_name(node.body, name)
            or _expr_contains_name(node.test, name)
            or _expr_contains_name(node.orelse, name)
        )
    return False


def _expr_is_taint_source(node: ast.expr) -> str | None:
    """Check if an expression is a known taint source. Returns kind or None."""
    if isinstance(node, ast.Call):
        call_name = _get_call_name(node)
        if call_name and call_name in TAINT_SOURCE_CALLS:
            return TAINT_SOURCE_CALLS[call_name]
        # Check for method calls like request.args.get(...)
        if call_name:
            for (obj, attr), kind in TAINT_SOURCE_ATTRS.items():
                if call_name.startswith(f"{obj}.{attr}"):
                    return kind
    if isinstance(node, ast.Subscript):
        # request.args['name']
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            key = (node.value.value.id, node.value.attr)
            if key in TAINT_SOURCE_ATTRS:
                return TAINT_SOURCE_ATTRS[key]
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            key = (node.value.id, node.attr)
            if key in TAINT_SOURCE_ATTRS:
                return TAINT_SOURCE_ATTRS[key]
    return None


def _call_is_sink(call_name: str) -> str | None:
    """Check if a call name matches a taint sink. Returns sink kind or None."""
    for pattern, kind in TAINT_SINK_PATTERNS:
        if call_name == pattern or call_name.endswith("." + pattern):
            return kind
        # Match suffix: "cursor.execute" matches "execute"
        if "." not in pattern and call_name.endswith(pattern):
            # Only match if it's the method name part
            parts = call_name.rsplit(".", 1)
            if len(parts) == 2 and parts[1] == pattern:
                return kind
            if len(parts) == 1 and parts[0] == pattern:
                return kind
    return None


def _call_is_sanitizer(call_name: str) -> bool:
    """Check if a call is a known sanitizer."""
    return call_name in SANITIZER_CALLS


# ─── Intra-file taint analysis (AST-based) ───────────────────────────


def analyze_taint_ast(filepath: str, content: str) -> list[Finding]:
    """AST-based intra-file taint analysis with variable indirection tracking.

    Handles patterns the tree-sitter taint misses:
    - f-string interpolation: query = f"SELECT {user_input}"
    - Variable chains: a = input(); b = f"SELECT {a}"; c = b; execute(c)
    - Function parameter taint: def f(x): execute(x)

    This analysis works per-function (intra-procedural).
    """
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()  # (source_line, sink_line)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_findings = _analyze_function_taint(node, filepath)
            for f in func_findings:
                key = (f.line, id(f))  # Use source line for dedup
                # Extract source line from message for dedup
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

    return findings


def _analyze_function_taint(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    filepath: str,
) -> list[Finding]:
    """Analyze a single function for taint flows including parameter taint."""
    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    # Track taint state: variable_name → TaintVar
    taint_map: dict[str, TaintVar] = {}

    # Treat function parameters as potential taint sources
    for arg in func_node.args.args + func_node.args.posonlyargs + func_node.args.kwonlyargs:
        arg_name = arg.arg
        if arg_name == "self" or arg_name == "cls":
            continue
        taint_map[arg_name] = TaintVar(
            name=arg_name,
            tainted=True,
            source_kind="parameter",
            source_line=func_node.lineno,
            source_file=filepath,
        )
    if func_node.args.vararg:
        taint_map[func_node.args.vararg.arg] = TaintVar(
            name=func_node.args.vararg.arg,
            tainted=True,
            source_kind="parameter",
            source_line=func_node.lineno,
            source_file=filepath,
        )
    if func_node.args.kwarg:
        taint_map[func_node.args.kwarg.arg] = TaintVar(
            name=func_node.args.kwarg.arg,
            tainted=True,
            source_kind="parameter",
            source_line=func_node.lineno,
            source_file=filepath,
        )

    # Walk function body in source order
    for stmt in func_node.body:
        _process_stmt_taint(stmt, taint_map, filepath, findings, seen)

    return findings


def _process_stmt_taint(
    stmt: ast.stmt,
    taint_map: dict[str, TaintVar],
    filepath: str,
    findings: list[Finding],
    seen: set[tuple[int, int]],
) -> None:
    """Process a statement for taint tracking."""
    if isinstance(stmt, ast.Assign):
        _process_assign(stmt, taint_map, filepath)
    elif isinstance(stmt, ast.AugAssign):
        _process_aug_assign(stmt, taint_map, filepath)
    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        if isinstance(stmt.target, ast.Name):
            _update_taint_from_expr(stmt.target.id, stmt.value, stmt.lineno, taint_map, filepath)
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        _check_call_sink(stmt.value, taint_map, filepath, findings, seen)
    elif isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
        # Recurse into compound statements
        _process_compound_stmt(stmt, taint_map, filepath, findings, seen)
    elif isinstance(stmt, ast.Return):
        pass  # Return values tracked separately for cross-file

    # Check for calls embedded in assignments (e.g. x = conn.execute(query))
    if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
        value = None
        if isinstance(stmt, ast.Assign):
            value = stmt.value
        elif isinstance(stmt, ast.AugAssign):
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            value = stmt.value
        if value is not None:
            for node in ast.walk(value):
                if isinstance(node, ast.Call):
                    _check_call_sink(node, taint_map, filepath, findings, seen)


def _process_compound_stmt(
    stmt: ast.stmt,
    taint_map: dict[str, TaintVar],
    filepath: str,
    findings: list[Finding],
    seen: set[tuple[int, int]],
) -> None:
    """Recurse into compound statement bodies."""
    bodies = []
    if isinstance(stmt, ast.If):
        bodies = [stmt.body, stmt.orelse]
    elif isinstance(stmt, (ast.For, ast.While)):
        bodies = [stmt.body, stmt.orelse]
    elif isinstance(stmt, ast.With):
        bodies = [stmt.body]
    elif isinstance(stmt, ast.Try):
        bodies = [stmt.body, stmt.orelse, stmt.finalbody]
        for handler in stmt.handlers:
            bodies.append(handler.body)

    for body in bodies:
        for child_stmt in body:
            _process_stmt_taint(child_stmt, taint_map, filepath, findings, seen)


def _process_assign(
    stmt: ast.Assign,
    taint_map: dict[str, TaintVar],
    filepath: str,
) -> None:
    """Process an assignment for taint propagation."""
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            _update_taint_from_expr(target.id, stmt.value, stmt.lineno, taint_map, filepath)
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple unpacking — conservatively taint all targets if RHS is tainted
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    _update_taint_from_expr(elt.id, stmt.value, stmt.lineno, taint_map, filepath)


def _process_aug_assign(
    stmt: ast.AugAssign,
    taint_map: dict[str, TaintVar],
    filepath: str,
) -> None:
    """Process augmented assignment (+=, etc.) — result is tainted if either operand is."""
    if isinstance(stmt.target, ast.Name):
        name = stmt.target.id
        # If current value is tainted, it stays tainted
        if name in taint_map and taint_map[name].tainted:
            return
        # Otherwise check RHS
        _update_taint_from_expr(name, stmt.value, stmt.lineno, taint_map, filepath)


def _update_taint_from_expr(
    var_name: str,
    expr: ast.expr,
    lineno: int,
    taint_map: dict[str, TaintVar],
    filepath: str,
) -> None:
    """Update taint status of var_name based on the value expression."""
    # Check if expression is a direct taint source
    source_kind = _expr_is_taint_source(expr)
    if source_kind:
        taint_map[var_name] = TaintVar(
            name=var_name,
            tainted=True,
            source_kind=source_kind,
            source_line=lineno,
            source_file=filepath,
        )
        return

    # Check if expression is a sanitizer call
    if isinstance(expr, ast.Call):
        call_name = _get_call_name(expr)
        if call_name and _call_is_sanitizer(call_name):
            taint_map[var_name] = TaintVar(
                name=var_name,
                tainted=False,
                source_kind="sanitized",
                source_line=lineno,
                source_file=filepath,
            )
            return

    # Check if expression references any tainted variable
    for tvar_name, tvar in taint_map.items():
        if tvar.tainted and _expr_contains_name(expr, tvar_name):
            taint_map[var_name] = TaintVar(
                name=var_name,
                tainted=True,
                source_kind=tvar.source_kind,
                source_line=tvar.source_line,
                source_file=filepath,
            )
            return

    # Not tainted
    taint_map[var_name] = TaintVar(
        name=var_name,
        tainted=False,
        source_kind="clean",
        source_line=lineno,
        source_file=filepath,
    )


def _check_call_sink(
    call: ast.Call,
    taint_map: dict[str, TaintVar],
    filepath: str,
    findings: list[Finding],
    seen: set[tuple[int, int]],
) -> None:
    """Check if a call is a sink with tainted arguments."""
    call_name = _get_call_name(call)
    if not call_name:
        return

    sink_kind = _call_is_sink(call_name)
    if not sink_kind:
        return

    # Check each argument for taint
    for arg in call.args:
        tainted_var = _find_tainted_in_expr(arg, taint_map)
        if tainted_var:
            key = (tainted_var.source_line, call.lineno)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                Finding(
                    file=filepath,
                    line=call.lineno,
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    source=Source.AST,
                    rule="taint-flow",
                    message=(
                        f"Tainted data from '{tainted_var.name}' "
                        f"({tainted_var.source_kind}, line {tainted_var.source_line}) "
                        f"reaches sink '{call_name}' ({sink_kind}) — "
                        "variable indirection tracking"
                    ),
                    suggestion=(
                        f"Sanitize '{tainted_var.name}' before passing to "
                        f"'{call_name}', or use parameterized queries/safe APIs"
                    ),
                )
            )
            break  # one finding per call

    # Also check keyword arguments
    for kw in call.keywords:
        if kw.value:
            tainted_var = _find_tainted_in_expr(kw.value, taint_map)
            if tainted_var:
                key = (tainted_var.source_line, call.lineno)
                if key in seen:
                    continue
                seen.add(key)

                findings.append(
                    Finding(
                        file=filepath,
                        line=call.lineno,
                        severity=Severity.WARNING,
                        category=Category.SECURITY,
                        source=Source.AST,
                        rule="taint-flow",
                        message=(
                            f"Tainted data from '{tainted_var.name}' "
                            f"({tainted_var.source_kind}, line {tainted_var.source_line}) "
                            f"reaches sink '{call_name}' ({sink_kind}) — "
                            "variable indirection tracking"
                        ),
                        suggestion=(
                            f"Sanitize '{tainted_var.name}' before passing to "
                            f"'{call_name}', or use parameterized queries/safe APIs"
                        ),
                    )
                )
                break


def _find_tainted_in_expr(
    expr: ast.expr,
    taint_map: dict[str, TaintVar],
) -> TaintVar | None:
    """Find a tainted variable referenced in an expression. Returns None if clean."""
    if isinstance(expr, ast.Name):
        tv = taint_map.get(expr.id)
        if tv and tv.tainted:
            return tv
    elif isinstance(expr, ast.JoinedStr):
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                result = _find_tainted_in_expr(value.value, taint_map)
                if result:
                    return result
    elif isinstance(expr, ast.BinOp):
        return _find_tainted_in_expr(expr.left, taint_map) or _find_tainted_in_expr(
            expr.right, taint_map
        )
    elif isinstance(expr, ast.Call):
        call_name = _get_call_name(expr)
        if call_name and _call_is_sanitizer(call_name):
            return None
        for arg in expr.args:
            result = _find_tainted_in_expr(arg, taint_map)
            if result:
                return result
    elif isinstance(expr, ast.Subscript):
        return _find_tainted_in_expr(expr.value, taint_map)
    elif isinstance(expr, ast.Attribute):
        return _find_tainted_in_expr(expr.value, taint_map)
    return None


# ─── Function taint summarization (for cross-file) ───────────────────


def _summarize_function_taint(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    filepath: str,
    module_name: str,
) -> FunctionTaintSummary:
    """Analyze a function to determine which parameters flow to sinks or returns."""
    params = [arg.arg for arg in func_node.args.args if arg.arg not in ("self", "cls")]

    # Build taint map with all params tainted
    taint_map: dict[str, TaintVar] = {}
    for i, pname in enumerate(params):
        taint_map[pname] = TaintVar(
            name=pname,
            tainted=True,
            source_kind="parameter",
            source_line=func_node.lineno,
            source_file=filepath,
        )

    param_flows_to_sink: dict[int, str] = {}
    returns_tainted = False
    returned_param_indices: set[int] = set()

    # Walk the function body — check ALL calls for sinks, not just bare Expr statements.
    # Sinks can appear in return statements (return httpx.get(url)), assignments
    # (resp = httpx.get(url)), or bare expression statements.
    for stmt in ast.walk(func_node):
        # Collect all Call nodes from any context within this statement
        call_nodes: list[ast.Call] = []
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_nodes.append(stmt.value)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Call):
                    call_nodes.append(node)
        elif isinstance(stmt, ast.Assign):
            for node in ast.walk(stmt.value):
                if isinstance(node, ast.Call):
                    call_nodes.append(node)

        for call_node in call_nodes:
            call_name = _get_call_name(call_node)
            if call_name:
                sink_kind = _call_is_sink(call_name)
                if sink_kind:
                    for arg in call_node.args:
                        tvar = _find_tainted_in_expr(arg, taint_map)
                        if tvar and tvar.source_kind == "parameter":
                            try:
                                idx = params.index(tvar.name)
                                param_flows_to_sink[idx] = sink_kind
                            except ValueError:  # doji:ignore(exception-swallowed,empty-exception-handler)
                                pass
                    for kw in call_node.keywords:
                        if kw.value:
                            tvar = _find_tainted_in_expr(kw.value, taint_map)
                            if tvar and tvar.source_kind == "parameter":
                                try:
                                    idx = params.index(tvar.name)
                                    param_flows_to_sink[idx] = sink_kind
                                except ValueError:  # doji:ignore(exception-swallowed,empty-exception-handler)
                                    pass

        if isinstance(stmt, ast.Return) and stmt.value is not None:
            tvar = _find_tainted_in_expr(stmt.value, taint_map)
            if tvar and tvar.source_kind == "parameter":
                returns_tainted = True
                try:
                    idx = params.index(tvar.name)
                    returned_param_indices.add(idx)
                except ValueError:  # doji:ignore(exception-swallowed,empty-exception-handler)
                    pass
            # Also check if the return value contains tainted data via propagation
            for vname, vinfo in taint_map.items():
                if vinfo.tainted and _expr_contains_name(stmt.value, vname):
                    returns_tainted = True
                    break

    qualified = f"{module_name}.{func_node.name}" if module_name else func_node.name

    return FunctionTaintSummary(
        name=func_node.name,
        qualified_name=qualified,
        filepath=filepath,
        line=func_node.lineno,
        params=params,
        param_flows_to_sink=param_flows_to_sink,
        returns_tainted_param=returns_tainted,
        returned_param_indices=returned_param_indices,
    )


# ─── Intra-file transitive sink propagation ──────────────────────────


def _propagate_intra_file_sinks(
    tree: ast.Module,
    summaries: dict[str, FunctionTaintSummary],
) -> None:
    """Propagate param_flows_to_sink transitively through local call chains.

    If function A calls function B (same file) and B.param_flows_to_sink
    records that B's param[j] flows to a sink, then for each of A's params
    that flow into B's arg[j], mark A.param_flows_to_sink with the same
    sink kind.

    Mutates summaries in-place.  Iterates to a fixed point to handle
    arbitrary call chain depth (fetch_json → fetch_url → httpx.get).
    """
    if not summaries:
        return

    # Build a map of function name → AST node for body inspection
    func_nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in summaries:
                func_nodes[node.name] = node

    max_iters = 10
    for _iteration in range(max_iters):
        changed = False

        for func_name, func_node in func_nodes.items():
            summary = summaries[func_name]
            params = summary.params

            # Build taint map: param name → param index
            param_idx_map = {p: i for i, p in enumerate(params)}

            # Build a simple taint map tracking which variables hold which param
            # (variable_name → set of param indices it's derived from)
            var_to_params: dict[str, set[int]] = {}
            for pname, pidx in param_idx_map.items():
                var_to_params[pname] = {pidx}

            # Walk the function body in order to track assignments
            for stmt in ast.iter_child_nodes(func_node):
                if not isinstance(stmt, ast.stmt):
                    continue
                _trace_param_flow_stmt(stmt, var_to_params, summaries, summary, params)
                if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    for child_stmt in ast.walk(stmt):
                        if isinstance(child_stmt, ast.stmt) and child_stmt is not stmt:
                            _trace_param_flow_stmt(child_stmt, var_to_params, summaries, summary, params)

            # Check if summary was updated
            if summary.param_flows_to_sink != summaries[func_name].param_flows_to_sink:
                changed = True

        if not changed:
            break


def _trace_param_flow_stmt(
    stmt: ast.stmt,
    var_to_params: dict[str, set[int]],
    all_summaries: dict[str, FunctionTaintSummary],
    current_summary: FunctionTaintSummary,
    params: list[str],
) -> None:
    """Process a statement to trace parameter flow through local function calls."""
    # Track assignments: if `resp = some_call(url)`, and url maps to param[0],
    # then resp inherits those param associations
    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                # Check which params the RHS references
                referenced_params: set[int] = set()
                for node in ast.walk(stmt.value):
                    if isinstance(node, ast.Name) and node.id in var_to_params:
                        referenced_params |= var_to_params[node.id]
                if referenced_params:
                    var_to_params[target.id] = referenced_params

    # Find all calls in this statement (any context: bare, return, assign)
    call_nodes: list[ast.Call] = []
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call_nodes.append(stmt.value)
    elif isinstance(stmt, ast.Return) and stmt.value is not None:
        for node in ast.walk(stmt.value):
            if isinstance(node, ast.Call):
                call_nodes.append(node)
    elif isinstance(stmt, ast.Assign):
        for node in ast.walk(stmt.value):
            if isinstance(node, ast.Call):
                call_nodes.append(node)

    for call_node in call_nodes:
        call_name = _get_call_name(call_node)
        if not call_name:
            continue

        # Check if this calls another function in the same file
        callee_summary = all_summaries.get(call_name)
        if callee_summary is None or not callee_summary.param_flows_to_sink:
            continue

        # For each callee parameter that flows to a sink, check if the caller
        # passes one of its own parameters (or a variable derived from them)
        for callee_param_idx, sink_kind in callee_summary.param_flows_to_sink.items():
            if callee_param_idx < len(call_node.args):
                arg = call_node.args[callee_param_idx]
                # Find which of current function's params flow into this argument
                caller_param_indices = _find_param_indices_in_expr(arg, var_to_params)
                for caller_pidx in caller_param_indices:
                    if caller_pidx not in current_summary.param_flows_to_sink:
                        current_summary.param_flows_to_sink[caller_pidx] = sink_kind

            # Also check keyword arguments
            for kw in call_node.keywords:
                if kw.arg and kw.value:
                    # Match keyword to callee param index
                    try:
                        kw_idx = callee_summary.params.index(kw.arg)
                    except ValueError:
                        continue
                    if kw_idx in callee_summary.param_flows_to_sink:
                        caller_param_indices = _find_param_indices_in_expr(kw.value, var_to_params)
                        for caller_pidx in caller_param_indices:
                            if caller_pidx not in current_summary.param_flows_to_sink:
                                current_summary.param_flows_to_sink[caller_pidx] = callee_summary.param_flows_to_sink[kw_idx]


def _find_param_indices_in_expr(
    expr: ast.expr,
    var_to_params: dict[str, set[int]],
) -> set[int]:
    """Find which function parameter indices are referenced in an expression."""
    result: set[int] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in var_to_params:
            result |= var_to_params[node.id]
    return result


# ─── Cross-file taint analysis ───────────────────────────────────────


def _extract_imports(tree: ast.Module) -> list[ImportInfo]:
    """Extract import information from an AST."""
    imports: list[ImportInfo] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports.append(
                    ImportInfo(
                        local_name=alias.asname or alias.name,
                        module=node.module,
                        original_name=alias.name,
                        line=node.lineno,
                    )
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(
                    ImportInfo(
                        local_name=alias.asname or alias.name,
                        module=alias.name,
                        original_name=alias.name,
                        line=node.lineno,
                    )
                )
    return imports


def _module_name_from_path(filepath: str) -> str:
    """Derive a module-style name from a file path (best effort)."""

    # Strip .py extension and convert separators to dots
    name = filepath.replace("\\", "/")
    if name.endswith(".py"):
        name = name[:-3]
    # Take only the last few path components (avoid full absolute path)
    parts = name.split("/")
    # Use at most the last 3 segments
    parts = parts[-3:]
    return ".".join(parts)


def analyze_taint_cross_file(
    file_contents: dict[str, str],
) -> list[CrossFileFinding]:
    """Analyze taint flows across file boundaries.

    Takes a dict of {filepath: content} for all Python files in the project.
    Returns CrossFileFindings for taint that flows across import boundaries.

    Strategy:
    1. Parse all files, extract function taint summaries
    2. Build import graph
    3. For each file, find calls to imported functions
    4. If the imported function's return value is tainted, track it in the caller
    5. If a tainted value from the caller flows through an imported function to a sink,
       report it
    """
    findings: list[CrossFileFinding] = []
    seen: set[tuple[str, int, str, int]] = set()  # (source_file, source_line, sink_file, sink_line)

    # Phase 1: Parse all files
    trees: dict[str, ast.Module] = {}
    for filepath, content in file_contents.items():
        if not filepath.endswith(".py"):
            continue
        try:
            trees[filepath] = ast.parse(content, filename=filepath)
        except SyntaxError:
            continue

    if len(trees) < 2:
        return findings

    # Phase 2: Build function taint summaries per file
    func_summaries: dict[str, dict[str, FunctionTaintSummary]] = {}  # filepath → {func_name → summary}
    module_names: dict[str, str] = {}  # filepath → module_name

    for filepath, tree in trees.items():
        mod_name = _module_name_from_path(filepath)
        module_names[filepath] = mod_name
        summaries: dict[str, FunctionTaintSummary] = {}

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                summary = _summarize_function_taint(node, filepath, mod_name)
                summaries[node.name] = summary

        func_summaries[filepath] = summaries

    # Phase 2.5: Transitive sink propagation within each file.
    # If function A calls function B (same file) and B has param_flows_to_sink,
    # then A inherits that sink info for whichever of A's params flow into B's
    # tainted argument position.  This handles wrapper chains like:
    #   fetch_json(url) → fetch_url(url) → httpx.get(url)
    for filepath, summaries in func_summaries.items():
        tree = trees[filepath]
        _propagate_intra_file_sinks(tree, summaries)

    # Phase 3: Build module → filepath mapping (for import resolution)
    # Try both full module name and partial matches
    module_to_filepath: dict[str, str] = {}
    for filepath, mod_name in module_names.items():
        module_to_filepath[mod_name] = filepath
        # Also register by filename stem (e.g. "utils" for "utils.py")
        import os

        stem = os.path.splitext(os.path.basename(filepath))[0]
        if stem not in module_to_filepath:
            module_to_filepath[stem] = filepath

    # Phase 4: For each file, check imported function calls
    for caller_path, caller_tree in trees.items():
        imports = _extract_imports(caller_tree)

        for imp in imports:
            # Resolve import to a source file
            source_path = module_to_filepath.get(imp.module)
            if source_path is None:
                # Try partial match: "mypackage.utils" → check if "utils" matches
                parts = imp.module.split(".")
                for i in range(len(parts)):
                    partial = ".".join(parts[i:])
                    if partial in module_to_filepath:
                        source_path = module_to_filepath[partial]
                        break
            if source_path is None or source_path == caller_path:
                continue

            source_summaries = func_summaries.get(source_path, {})

            # Check if the imported name is a function we analyzed
            func_summary = source_summaries.get(imp.original_name)
            if func_summary is None:
                continue

            # Find all calls to this imported function in the caller
            for node in ast.walk(caller_tree):
                if not isinstance(node, ast.Call):
                    continue

                call_name = _get_call_name(node)
                if call_name != imp.local_name:
                    continue

                # Case 1: Caller passes tainted args to a function that has param→sink flows
                if func_summary.param_flows_to_sink:
                    # Check if the caller passes tainted data
                    caller_taint = _get_caller_taint_at_line(
                        caller_tree, node.lineno, caller_path
                    )
                    for param_idx, sink_kind in func_summary.param_flows_to_sink.items():
                        if param_idx < len(node.args):
                            arg = node.args[param_idx]
                            tvar = _find_tainted_in_expr(arg, caller_taint)
                            if tvar:
                                key = (caller_path, node.lineno, source_path, func_summary.line)
                                if key in seen:
                                    continue
                                seen.add(key)

                                findings.append(
                                    CrossFileFinding(
                                        source_file=caller_path,
                                        target_file=source_path,
                                        line=node.lineno,
                                        target_line=func_summary.line,
                                        severity=Severity.WARNING,
                                        category=Category.SECURITY,
                                        rule="taint-flow-cross-file",
                                        message=(
                                            f"Tainted data '{tvar.name}' ({tvar.source_kind}) "
                                            f"flows from {_basename(caller_path)}:{node.lineno} "
                                            f"into '{func_summary.name}()' in "
                                            f"{_basename(source_path)}:{func_summary.line} "
                                            f"which passes parameter '{func_summary.params[param_idx]}' "
                                            f"to a {sink_kind} sink"
                                        ),
                                        suggestion=(
                                            f"Sanitize the argument before passing to "
                                            f"'{func_summary.name}()', or add input validation "
                                            f"inside '{func_summary.name}()'"
                                        ),
                                    )
                                )

                # Case 2: Function returns tainted data → caller uses it in a sink
                if func_summary.returns_tainted_param:
                    # Check if the return value is assigned and then used in a sink
                    _check_return_taint_usage(
                        caller_tree, node, func_summary, imp,
                        caller_path, source_path, findings, seen,
                    )

    return findings


def _basename(filepath: str) -> str:
    """Get the filename from a path."""
    import os

    return os.path.basename(filepath)


def _get_caller_taint_at_line(
    tree: ast.Module,
    target_line: int,
    filepath: str,
) -> dict[str, TaintVar]:
    """Get the taint state at a specific line in a file.

    Walks the enclosing function up to target_line to build taint state.
    """
    # Find the enclosing function
    enclosing_func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, "end_lineno") and node.end_lineno:
                if node.lineno <= target_line <= node.end_lineno:
                    enclosing_func = node
            elif node.lineno <= target_line:
                enclosing_func = node

    if enclosing_func is None:
        # Module-level code — check for taint sources
        taint_map: dict[str, TaintVar] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and node.lineno < target_line:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        _update_taint_from_expr(target.id, node.value, node.lineno, taint_map, filepath)
        return taint_map

    # Build taint map by analyzing the function up to target_line
    taint_map = {}

    # Function parameters
    for arg in enclosing_func.args.args:
        if arg.arg not in ("self", "cls"):
            taint_map[arg.arg] = TaintVar(
                name=arg.arg,
                tainted=True,
                source_kind="parameter",
                source_line=enclosing_func.lineno,
                source_file=filepath,
            )

    # Walk body up to target line
    for stmt in enclosing_func.body:
        if stmt.lineno >= target_line:
            break
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    _update_taint_from_expr(target.id, stmt.value, stmt.lineno, taint_map, filepath)

    return taint_map


def _check_return_taint_usage(
    caller_tree: ast.Module,
    call_node: ast.Call,
    func_summary: FunctionTaintSummary,
    imp: ImportInfo,
    caller_path: str,
    source_path: str,
    findings: list[CrossFileFinding],
    seen: set[tuple[str, int, str, int]],
) -> None:
    """Check if the return value of a taint-returning function is used in a sink."""
    # Find the assignment that captures this call's return value
    for node in ast.walk(caller_tree):
        if isinstance(node, ast.Assign) and node.lineno == call_node.lineno:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    # Now look for this variable being used in a sink
                    for sink_node in ast.walk(caller_tree):
                        if (
                            isinstance(sink_node, ast.Call)
                            and sink_node.lineno > call_node.lineno
                        ):
                            sink_call_name = _get_call_name(sink_node)
                            if sink_call_name:
                                sink_kind = _call_is_sink(sink_call_name)
                                if sink_kind:
                                    for arg in sink_node.args:
                                        if isinstance(arg, ast.Name) and arg.id == var_name:
                                            key = (caller_path, call_node.lineno, source_path, func_summary.line)
                                            if key in seen:
                                                continue
                                            seen.add(key)

                                            findings.append(
                                                CrossFileFinding(
                                                    source_file=source_path,
                                                    target_file=caller_path,
                                                    line=func_summary.line,
                                                    target_line=sink_node.lineno,
                                                    severity=Severity.WARNING,
                                                    category=Category.SECURITY,
                                                    rule="taint-flow-cross-file",
                                                    message=(
                                                        f"Function '{func_summary.name}()' in "
                                                        f"{_basename(source_path)} returns "
                                                        f"potentially tainted data → assigned to "
                                                        f"'{var_name}' at "
                                                        f"{_basename(caller_path)}:{call_node.lineno} "
                                                        f"→ reaches sink '{sink_call_name}' "
                                                        f"({sink_kind}) at line {sink_node.lineno}"
                                                    ),
                                                    suggestion=(
                                                        f"Sanitize the return value of "
                                                        f"'{func_summary.name}()' before passing "
                                                        f"to '{sink_call_name}()'"
                                                    ),
                                                )
                                            )
