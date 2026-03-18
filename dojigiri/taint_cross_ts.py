"""Cross-file taint analysis for JS/Java via tree-sitter.

Same detection protocol as taint_cross.py (Python, ast-based) but uses
tree-sitter infrastructure (semantic/core.py, semantic/taint.py) instead
of the Python ast module.

Protocol:
1. Parse all files via extract_semantics()
2. Build FunctionTaintSummary per function (params → sinks, params → return)
3. Extract imports and build module→filepath map
4. For each file, check imported function calls:
   Case 1: Caller passes tainted arg → imported func has param→sink → finding
   Case 2: Imported func returns tainted param → caller uses in sink → finding

Called by: analyzer.py
Calls into: semantic/core.py, semantic/taint.py, semantic/lang_config.py,
            taint_cross_base.py, graph/depgraph.py
Data in → Data out: dict[filepath, content] → list[CrossFileFinding]
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from .semantic.core import FileSemantics, extract_semantics
from .semantic.lang_config import LanguageConfig, get_config
from .semantic.taint import (
    TaintSource,
    _build_scope_children,
    _find_taint_sinks,
    _find_taint_sources,
    _get_all_children,
    _propagate_taint,
)
from .taint_cross_base import FunctionTaintSummary, ImportInfo, _taint_severity
from .types import Category, Confidence, CrossFileFinding, Severity

logger = logging.getLogger(__name__)

# ─── JS/TS import patterns ────────────────────────────────────────────

# ESM: import { foo } from './utils'  /  import foo from './utils'
_JS_ESM_RE = re.compile(
    r"""import\s+"""
    r"""(?:"""
    r"""(?:\{([^}]+)\})|"""  # group 1: named imports { foo, bar as baz }
    r"""(\w+)|"""  # group 2: default import
    r"""(?:\*\s+as\s+(\w+))"""  # group 3: namespace import
    r""")"""
    r"""\s+from\s+['"]([^'"]+)['"]""",  # group 4: module specifier
    re.MULTILINE,
)

# CommonJS: const foo = require('./utils')  /  const { foo } = require('./utils')
_JS_CJS_RE = re.compile(
    r"""(?:const|let|var)\s+"""
    r"""(?:"""
    r"""(?:\{([^}]+)\})|"""  # group 1: destructured
    r"""(\w+)"""  # group 2: simple binding
    r""")"""
    r"""\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""",  # group 3: module
    re.MULTILINE,
)

# Java: import com.example.UserService;  /  import static com.example.Utils.method;
_JAVA_IMPORT_RE = re.compile(
    r"""^\s*import\s+(?:static\s+)?([\w.]+)\s*;""",
    re.MULTILINE,
)

# Java: package com.example;
_JAVA_PACKAGE_RE = re.compile(
    r"""^\s*package\s+([\w.]+)\s*;""",
    re.MULTILINE,
)

# JS export patterns for matching exported function names
_JS_EXPORT_FUNC_RE = re.compile(
    r"""(?:export\s+(?:default\s+)?)?(?:function|const|let|var|class)\s+(\w+)""",
)
_JS_MODULE_EXPORTS_RE = re.compile(
    r"""module\.exports\s*=\s*\{([^}]+)\}""",
    re.MULTILINE,
)

# ─── Phase 1: Parse all files ────────────────────────────────────────


def _parse_all_files_ts(
    file_contents: dict[str, str], language: str,
) -> dict[str, FileSemantics]:
    """Parse all files into FileSemantics via tree-sitter."""
    semantics_map: dict[str, FileSemantics] = {}
    for filepath, content in file_contents.items():
        sem = extract_semantics(content, filepath, language)
        if sem is not None:
            semantics_map[filepath] = sem
    return semantics_map


# ─── Phase 2: Build function taint summaries ─────────────────────────


def _build_function_summaries_ts(
    file_contents: dict[str, str],
    semantics_map: dict[str, FileSemantics],
    language: str,
) -> dict[str, dict[str, FunctionTaintSummary]]:
    """Build per-file function taint summaries using tree-sitter analysis.

    For each function, treats all params as tainted, propagates via
    _propagate_taint(), then checks which params flow to sinks and returns.
    """
    config = get_config(language)
    if config is None:
        return {}

    all_summaries: dict[str, dict[str, FunctionTaintSummary]] = {}

    for filepath, sem in semantics_map.items():
        content = file_contents.get(filepath, "")
        source_bytes = content.encode("utf-8")
        lines = content.splitlines()
        file_summaries: dict[str, FunctionTaintSummary] = {}

        # Build arrow function name map: line → assigned name
        # Handles: const doQuery = (input) => { ... }
        arrow_names: dict[int, str] = {}
        for asgn in sem.assignments:
            if not asgn.is_parameter and ("=>" in asgn.value_text or "function" in asgn.value_text):
                arrow_names[asgn.line] = asgn.name

        scope_children = _build_scope_children(sem)

        for func_def in sem.function_defs:
            func_scope = None
            for scope in sem.scopes:
                if scope.kind == "function" and scope.start_line == func_def.line:
                    # Match by line — scope name may be qualified (Class.method)
                    if (scope.name == func_def.name
                            or scope.name == func_def.qualified_name):
                        func_scope = scope
                        break
            if func_scope is None:
                # Fallback: find scope containing the function definition
                for scope in sem.scopes:
                    if (scope.kind == "function"
                            and scope.start_line <= func_def.line <= scope.end_line
                            and (scope.name == func_def.name
                                 or scope.name == func_def.qualified_name)):
                        func_scope = scope
                        break
            if func_scope is None:
                continue

            func_scope_ids = _get_all_children(func_scope.scope_id, scope_children)

            # Collect parameter names
            params = func_def.params[:]
            # Filter out 'self'/'this' for class methods
            if language == "java" and params and params[0] == "this":
                params = params[1:]

            if not params:
                file_summaries[func_def.name] = FunctionTaintSummary(
                    name=func_def.name,
                    qualified_name=func_def.qualified_name,
                    filepath=filepath,
                    line=func_def.line,
                    params=[],
                    param_flows_to_sink={},
                    returns_tainted_param=False,
                    returned_param_indices=set(),
                )
                continue

            # Run taint propagation treating all params as tainted
            initial_tainted = set(params)
            taint_chains = _propagate_taint(
                sem, initial_tainted, func_scope_ids, config,
            )
            tainted_vars = set(taint_chains.keys())

            # Check which params flow to sinks
            sinks = _find_taint_sinks(
                sem, config, tainted_vars, func_scope_ids, source_bytes,
            )
            param_flows: dict[int, str] = {}
            for sink in sinks:
                # For each param, check if it contributes to the sink variable
                # Use line text analysis since chain walking only tracks one path
                sink_rhs = ""
                for a in sem.assignments:
                    if a.scope_id in func_scope_ids and a.name == sink.variable:
                        sink_rhs = a.value_text
                        break
                for i, p in enumerate(params):
                    if i in param_flows:
                        continue
                    if p not in tainted_vars:
                        continue
                    # Check: does this param appear in the sink variable's RHS
                    # or does it transitively reach the sink via chain walking
                    if (re.search(r"\b" + re.escape(p) + r"\b", sink_rhs)
                            or _var_reaches_sink_var(p, sink.variable, taint_chains)):
                        param_flows[i] = sink.kind

            # Check if any param flows to return
            returns_tainted = False
            returned_indices: set[int] = set()
            lines = content.splitlines()
            for line_num in range(func_def.line, min(func_def.end_line + 1, len(lines) + 1)):
                line_idx = line_num - 1
                if 0 <= line_idx < len(lines):
                    line_text = lines[line_idx].strip()
                    if line_text.startswith("return "):
                        return_expr = line_text[len("return "):]
                        for i, p in enumerate(params):
                            if p in tainted_vars and re.search(
                                r"\b" + re.escape(p) + r"\b", return_expr,
                            ):
                                returns_tainted = True
                                returned_indices.add(i)
                            # Also check vars derived from params
                            for tvar in tainted_vars:
                                if tvar != p and re.search(
                                    r"\b" + re.escape(tvar) + r"\b", return_expr,
                                ):
                                    # Find which param this traces back to
                                    chain = taint_chains.get(tvar, [])
                                    for src_var, _ in chain:
                                        if src_var in params:
                                            idx = params.index(src_var)
                                            returns_tainted = True
                                            returned_indices.add(idx)

            # Resolve arrow function names: const doQuery = () => { ... }
            func_name = func_def.name
            if func_name == "<anonymous>":
                func_name = arrow_names.get(func_def.line, func_name)

            summary = FunctionTaintSummary(
                name=func_name,
                qualified_name=func_def.qualified_name,
                filepath=filepath,
                line=func_def.line,
                params=params,
                param_flows_to_sink=param_flows,
                returns_tainted_param=returns_tainted,
                returned_param_indices=returned_indices,
            )
            file_summaries[func_name] = summary
            # Also register under original name for fallback
            if func_name != func_def.name:
                file_summaries[func_def.name] = summary

        all_summaries[filepath] = file_summaries

    return all_summaries


def _var_reaches_sink_var(
    source: str, sink_var: str, chains: dict[str, list[tuple[str, int]]],
) -> bool:
    """Check if source variable reaches sink_var through taint chains."""
    if source == sink_var:
        return True
    # Walk the chain from sink_var backward
    visited: set[str] = set()
    queue = [sink_var]
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        if current == source:
            return True
        for prev_var, _ in chains.get(current, []):
            queue.append(prev_var)
    return False


# ─── Phase 3: Import extraction ──────────────────────────────────────


def _extract_imports_js(
    filepath: str, content: str,
) -> list[ImportInfo]:
    """Extract JS/TS imports (ESM + CommonJS)."""
    imports: list[ImportInfo] = []

    for match in _JS_ESM_RE.finditer(content):
        named = match.group(1)
        default = match.group(2)
        namespace = match.group(3)
        module_spec = match.group(4)
        line = content[:match.start()].count("\n") + 1

        if named:
            for item in named.split(","):
                item = item.strip()
                if not item:
                    continue
                if " as " in item:
                    original, _, alias = item.partition(" as ")
                    imports.append(ImportInfo(
                        local_name=alias.strip(),
                        module=module_spec,
                        original_name=original.strip(),
                        line=line,
                    ))
                else:
                    imports.append(ImportInfo(
                        local_name=item,
                        module=module_spec,
                        original_name=item,
                        line=line,
                    ))
        if default:
            imports.append(ImportInfo(
                local_name=default,
                module=module_spec,
                original_name="default",
                line=line,
            ))
        if namespace:
            imports.append(ImportInfo(
                local_name=namespace,
                module=module_spec,
                original_name="*",
                line=line,
            ))

    for match in _JS_CJS_RE.finditer(content):
        destructured = match.group(1)
        simple = match.group(2)
        module_spec = match.group(3)
        line = content[:match.start()].count("\n") + 1

        if destructured:
            for item in destructured.split(","):
                item = item.strip()
                if not item:
                    continue
                if ":" in item:
                    original, _, alias = item.partition(":")
                    imports.append(ImportInfo(
                        local_name=alias.strip(),
                        module=module_spec,
                        original_name=original.strip(),
                        line=line,
                    ))
                else:
                    imports.append(ImportInfo(
                        local_name=item,
                        module=module_spec,
                        original_name=item,
                        line=line,
                    ))
        if simple:
            imports.append(ImportInfo(
                local_name=simple,
                module=module_spec,
                original_name="default",
                line=line,
            ))

    return imports


def _extract_imports_java(
    filepath: str, content: str,
) -> list[ImportInfo]:
    """Extract Java imports."""
    imports: list[ImportInfo] = []

    for match in _JAVA_IMPORT_RE.finditer(content):
        import_path = match.group(1)  # e.g. "com.example.UserService"
        parts = import_path.split(".")
        if len(parts) < 2:
            continue

        class_name = parts[-1]
        # For static imports, last part is method, second-to-last is class
        line = content[:match.start()].count("\n") + 1

        imports.append(ImportInfo(
            local_name=class_name,
            module=".".join(parts[:-1]),
            original_name=class_name,
            line=line,
        ))

    return imports


def _extract_imports_ts(
    filepath: str, content: str, language: str,
) -> list[ImportInfo]:
    """Extract imports based on language."""
    if language in ("javascript", "typescript"):
        return _extract_imports_js(filepath, content)
    elif language == "java":
        return _extract_imports_java(filepath, content)
    return []


# ─── Module/filepath resolution ──────────────────────────────────────


def _build_module_map_js(
    file_contents: dict[str, str],
) -> dict[str, str]:
    """Build module specifier → filepath map for JS/TS.

    Maps relative import paths to their resolved file paths.
    """
    module_to_filepath: dict[str, str] = {}
    for filepath in file_contents:
        # Map the file stem and relative paths
        stem = Path(filepath).stem
        if stem not in module_to_filepath:
            module_to_filepath[stem] = filepath
        # Also map the full path without extension
        no_ext = str(Path(filepath).with_suffix("")).replace("\\", "/")
        module_to_filepath[no_ext] = filepath
    return module_to_filepath


def _build_module_map_java(
    file_contents: dict[str, str],
) -> dict[str, str]:
    """Build package.ClassName → filepath map for Java."""
    module_to_filepath: dict[str, str] = {}
    for filepath, content in file_contents.items():
        m = _JAVA_PACKAGE_RE.search(content)
        class_name = Path(filepath).stem
        if m:
            pkg = m.group(1)
            module_to_filepath[f"{pkg}.{class_name}"] = filepath
            module_to_filepath[class_name] = filepath
        else:
            module_to_filepath[class_name] = filepath
    return module_to_filepath


def _resolve_import_to_filepath_js(
    imp: ImportInfo,
    caller_path: str,
    file_contents: dict[str, str],
) -> str | None:
    """Resolve a JS import to a filepath in the project."""
    module_spec = imp.module

    # Only resolve relative imports
    if not module_spec.startswith("."):
        return None

    caller_dir = str(Path(caller_path).parent).replace("\\", "/")
    # Resolve the relative path
    if caller_dir == ".":
        target_base = module_spec
    else:
        target_base = f"{caller_dir}/{module_spec}"

    # Normalize path (handle ../ and ./, use forward slashes)
    target_base = os.path.normpath(target_base).replace("\\", "/")

    # Try with different extensions
    extensions = ["", ".js", ".ts", ".tsx", ".jsx", "/index.js", "/index.ts"]
    for ext in extensions:
        candidate = target_base + ext
        # Normalize candidate too
        candidate = candidate.replace("\\", "/")
        if candidate in file_contents:
            return candidate

    return None


def _resolve_import_to_filepath_java(
    imp: ImportInfo,
    caller_path: str,
    module_map: dict[str, str],
) -> str | None:
    """Resolve a Java import to a filepath."""
    # Try full qualified name
    fqn = f"{imp.module}.{imp.original_name}"
    result = module_map.get(fqn)
    if result and result != caller_path:
        return result

    # Try just the class name
    result = module_map.get(imp.original_name)
    if result and result != caller_path:
        return result

    return None


# ─── Phase 4: Cross-file detection ───────────────────────────────────


def _get_caller_taint_at_line_ts(
    sem: FileSemantics,
    config: LanguageConfig,
    source_bytes: bytes,
    target_line: int,
) -> set[str]:
    """Get tainted variables at a specific line using tree-sitter analysis.

    Finds the enclosing function scope, runs source detection + propagation,
    and returns the set of tainted variable names.
    """
    # Find enclosing function scope
    enclosing_scope = None
    for scope in sem.scopes:
        if (scope.kind == "function"
                and scope.start_line <= target_line <= scope.end_line):
            # Pick the tightest enclosing scope
            if enclosing_scope is None or scope.start_line > enclosing_scope.start_line:
                enclosing_scope = scope

    scope_children = _build_scope_children(sem)

    if enclosing_scope is not None:
        func_scope_ids = _get_all_children(enclosing_scope.scope_id, scope_children)
    else:
        # Module-level — use all scopes that are module-level
        func_scope_ids = set()
        for scope in sem.scopes:
            if scope.kind == "module":
                func_scope_ids = _get_all_children(scope.scope_id, scope_children)
                break
        if not func_scope_ids:
            func_scope_ids = {s.scope_id for s in sem.scopes}

    sources = _find_taint_sources(sem, config, source_bytes, func_scope_ids)
    if not sources:
        # Also check for framework-specific taint: function params with taint names
        # (e.g., Express route handler `(req, res)` — req is tainted)
        for asgn in sem.assignments:
            if asgn.is_parameter and asgn.scope_id in func_scope_ids:
                if _is_framework_taint_param(asgn.name, config):
                    sources.append(TaintSource(
                        variable=asgn.name, line=asgn.line, kind="user_input",
                    ))

    initial_tainted = {s.variable for s in sources}
    if not initial_tainted:
        return set()

    taint_chains = _propagate_taint(sem, initial_tainted, func_scope_ids, config)
    return set(taint_chains.keys())


def _is_framework_taint_param(name: str, config: LanguageConfig) -> bool:
    """Check if a parameter name indicates a framework taint source.

    Express: req, request → user_input
    Spring: request, httpServletRequest → user_input
    """
    taint_param_names = {
        "req", "request", "httpServletRequest", "servletRequest",
        "httpRequest", "body",
    }
    return name in taint_param_names


def _find_exported_names_js(content: str) -> set[str]:
    """Find function/variable names that are exported from a JS file."""
    exported: set[str] = set()

    # export function foo / export const foo / export default function foo
    for m in _JS_EXPORT_FUNC_RE.finditer(content):
        exported.add(m.group(1))

    # module.exports = { foo, bar }
    for m in _JS_MODULE_EXPORTS_RE.finditer(content):
        for item in m.group(1).split(","):
            item = item.strip()
            if ":" in item:
                item = item.split(":")[0].strip()
            if item and item.isidentifier():
                exported.add(item)

    return exported


def analyze_taint_cross_file_ts(
    file_contents: dict[str, str],
    language: str,
) -> list[CrossFileFinding]:
    """Analyze cross-file taint flows for JS/Java using tree-sitter.

    Args:
        file_contents: {filepath: source_code} for all files of one language.
        language: "javascript", "typescript", or "java".

    Returns:
        List of CrossFileFinding for taint flows across file boundaries.
    """
    findings: list[CrossFileFinding] = []
    seen: set[tuple[str, int, str, int]] = set()

    config = get_config(language)
    if config is None:
        return findings

    # Phase 1: Parse all files
    semantics_map = _parse_all_files_ts(file_contents, language)
    if len(semantics_map) < 2:
        return findings

    # Phase 2: Build function taint summaries
    func_summaries = _build_function_summaries_ts(file_contents, semantics_map, language)

    # Phase 3: Build module→filepath maps
    if language in ("javascript", "typescript"):
        module_map = _build_module_map_js(file_contents)
    elif language == "java":
        module_map = _build_module_map_java(file_contents)
    else:
        return findings

    # Phase 4: Check cross-file calls
    for caller_path, caller_sem in semantics_map.items():
        caller_content = file_contents.get(caller_path, "")
        imports = _extract_imports_ts(caller_path, caller_content, language)

        for imp in imports:
            # Resolve import to source file
            if language in ("javascript", "typescript"):
                source_path = _resolve_import_to_filepath_js(
                    imp, caller_path, file_contents,
                )
            else:
                source_path = _resolve_import_to_filepath_java(
                    imp, caller_path, module_map,
                )

            if source_path is None or source_path == caller_path:
                continue

            source_summaries = func_summaries.get(source_path, {})
            if not source_summaries:
                continue

            # Find all calls to imported functions in the caller
            for call in caller_sem.function_calls:
                func_summary = None

                if call.receiver and call.receiver == imp.local_name:
                    # Receiver matches import: ClassName.method() or namespace.func()
                    # Look up the method name directly in source summaries
                    func_summary = source_summaries.get(call.name)
                elif call.name == imp.local_name and not call.receiver:
                    # Direct call: doQuery() matches import { doQuery }
                    func_summary = source_summaries.get(imp.original_name)
                    if func_summary is None and imp.original_name == "default":
                        func_summary = source_summaries.get(imp.local_name)
                else:
                    continue

                if func_summary is None:
                    continue

                # Case 1: Caller passes tainted arg → imported func has param→sink
                if func_summary.param_flows_to_sink:
                    caller_tainted = _get_caller_taint_at_line_ts(
                        caller_sem, config,
                        caller_content.encode("utf-8"),
                        call.line,
                    )
                    _check_case1(
                        call, caller_path, source_path,
                        func_summary, caller_tainted, caller_content,
                        findings, seen,
                    )

                # Case 2: Imported func returns tainted param → caller uses in sink
                if func_summary.returns_tainted_param:
                    _check_case2(
                        call, caller_path, source_path,
                        caller_sem, config, caller_content,
                        func_summary, imp,
                        findings, seen,
                    )

    return findings


def _check_case1(
    call,
    caller_path: str,
    source_path: str,
    func_summary: FunctionTaintSummary,
    caller_tainted: set[str],
    caller_content: str,
    findings: list[CrossFileFinding],
    seen: set[tuple[str, int, str, int]],
) -> None:
    """Case 1: Caller passes tainted argument to function with param→sink flow."""
    if not caller_tainted:
        return

    lines = caller_content.splitlines()
    call_line_idx = call.line - 1
    if not (0 <= call_line_idx < len(lines)):
        return

    call_line = lines[call_line_idx]

    for param_idx, sink_kind in func_summary.param_flows_to_sink.items():
        # Find the tainted argument at the call site
        tvar = _find_tainted_arg_in_call(
            call_line, call.name, param_idx, caller_tainted,
        )
        if tvar is None:
            continue

        key = (caller_path, call.line, source_path, func_summary.line)
        if key in seen:
            continue
        seen.add(key)

        param_name = (
            func_summary.params[param_idx]
            if param_idx < len(func_summary.params)
            else f"arg{param_idx}"
        )

        findings.append(CrossFileFinding(
            source_file=caller_path,
            target_file=source_path,
            line=call.line,
            target_line=func_summary.line,
            severity=_taint_severity(sink_kind),
            category=Category.SECURITY,
            rule="taint-flow-cross-file",
            message=(
                f"Tainted data '{tvar}' flows from "
                f"{os.path.basename(caller_path)}:{call.line} "
                f"into '{func_summary.name}()' in "
                f"{os.path.basename(source_path)}:{func_summary.line} "
                f"which passes parameter '{param_name}' to a {sink_kind} sink"
            ),
            suggestion=(
                f"Sanitize the argument before passing to "
                f"'{func_summary.name}()', or add input validation "
                f"inside '{func_summary.name}()'"
            ),
            confidence=Confidence.MEDIUM,
        ))


def _check_case2(
    call,
    caller_path: str,
    source_path: str,
    caller_sem: FileSemantics,
    config: LanguageConfig,
    caller_content: str,
    func_summary: FunctionTaintSummary,
    imp: ImportInfo,
    findings: list[CrossFileFinding],
    seen: set[tuple[str, int, str, int]],
) -> None:
    """Case 2: Imported function returns tainted param → caller uses return in sink."""
    # Find assignments of the call return value
    source_bytes = caller_content.encode("utf-8")
    lines = caller_content.splitlines()

    # Look for variable assigned from this call's return value
    return_var = None
    for asgn in caller_sem.assignments:
        if asgn.line == call.line and not asgn.is_parameter:
            # Check if RHS contains the function call
            if func_summary.name in asgn.value_text or imp.local_name in asgn.value_text:
                return_var = asgn.name
                break

    if return_var is None:
        return

    # Check if return_var flows to a sink
    scope_children = _build_scope_children(caller_sem)

    # Find the scope containing this call
    enclosing_scope_ids: set[int] = set()
    for scope in caller_sem.scopes:
        if scope.kind == "function" and scope.start_line <= call.line <= scope.end_line:
            enclosing_scope_ids = _get_all_children(scope.scope_id, scope_children)
            break
    if not enclosing_scope_ids:
        for scope in caller_sem.scopes:
            if scope.kind == "module":
                enclosing_scope_ids = _get_all_children(scope.scope_id, scope_children)
                break

    if not enclosing_scope_ids:
        return

    # Propagate taint from the return variable
    taint_chains = _propagate_taint(
        caller_sem, {return_var}, enclosing_scope_ids, config,
    )
    tainted_vars = set(taint_chains.keys())

    sinks = _find_taint_sinks(
        caller_sem, config, tainted_vars, enclosing_scope_ids, source_bytes,
    )

    for sink in sinks:
        if sink.line <= call.line:
            continue  # Sink must come after the call

        key = (caller_path, call.line, source_path, func_summary.line)
        if key in seen:
            continue
        seen.add(key)

        findings.append(CrossFileFinding(
            source_file=caller_path,
            target_file=source_path,
            line=sink.line,
            target_line=func_summary.line,
            severity=_taint_severity(sink.kind),
            category=Category.SECURITY,
            rule="taint-flow-cross-file",
            message=(
                f"Return value from '{func_summary.name}()' in "
                f"{os.path.basename(source_path)}:{func_summary.line} "
                f"propagates tainted data to {sink.kind} sink at "
                f"{os.path.basename(caller_path)}:{sink.line} "
                f"via variable '{return_var}'"
            ),
            suggestion=(
                f"Sanitize the return value from '{func_summary.name}()' "
                f"before using it in a {sink.kind} operation"
            ),
            confidence=Confidence.MEDIUM,
        ))


def _find_tainted_arg_in_call(
    line_text: str,
    func_name: str,
    param_idx: int,
    tainted_vars: set[str],
) -> str | None:
    """Find if the argument at param_idx in a function call is tainted.

    Simple heuristic: split the call arguments by commas and check if
    the target argument contains a tainted variable.
    """
    # Find the function call in the line
    # Look for funcName( ... )
    patterns = [
        re.escape(func_name) + r"\s*\(",
    ]
    for pat in patterns:
        m = re.search(pat, line_text)
        if m:
            start = m.end()
            # Extract args by counting parens
            depth = 1
            end = start
            while end < len(line_text) and depth > 0:
                if line_text[end] == "(":
                    depth += 1
                elif line_text[end] == ")":
                    depth -= 1
                end += 1
            args_text = line_text[start:end - 1] if end > start else ""

            # Split by commas (respecting nesting)
            args = _split_args(args_text)
            if param_idx < len(args):
                arg = args[param_idx].strip()
                for tvar in tainted_vars:
                    if re.search(r"\b" + re.escape(tvar) + r"\b", arg):
                        return tvar
            break

    return None


def _split_args(text: str) -> list[str]:
    """Split function arguments by commas, respecting nested parens/brackets."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in ("(", "[", "{"):
            depth += 1
            current.append(ch)
        elif ch in (")", "]", "}"):
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current))
    return args
