"""Dependency graph and call graph engine.

Builds directed graphs of file-level imports (DepGraph) and function calls
(CallGraph) for Python and JS/TS projects. Detects import cycles, dead
modules, hub files, and computes coupling metrics (GraphMetrics).

Called by: graph/callgraph.py, graph/project.py
Calls into: config.py (LANGUAGE_EXTENSIONS)
Data in -> Data out: source directory -> DepGraph, CallGraph, GraphMetrics
"""

from __future__ import annotations  # noqa

import ast as ast_mod
import logging
import re
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
from pathlib import Path

from ..config import LANGUAGE_EXTENSIONS


@dataclass
class FileNode:
    """A single file in the dependency graph."""

    path: str
    language: str
    imports: set[str] = field(default_factory=set)  # files this imports
    imported_by: set[str] = field(default_factory=set)  # files that import this

    @property
    def fan_out(self) -> int:
        return len(self.imports)

    @property
    def fan_in(self) -> int:
        return len(self.imported_by)

    @property
    def is_hub(self) -> bool:
        return self.fan_in >= 3 and self.fan_out >= 3

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "imports": sorted(self.imports),
            "imported_by": sorted(self.imported_by),
            "fan_in": self.fan_in,
            "fan_out": self.fan_out,
            "is_hub": self.is_hub,
        }


@dataclass
class DepGraph:
    """Directed dependency graph over project files."""

    root: str
    nodes: dict[str, FileNode] = field(default_factory=dict)
    circular_deps: list[tuple[str, ...]] = field(default_factory=list)

    @property
    def dead_modules(self) -> list[str]:
        """Files with fan_in == 0 that are not entry points."""
        dead = []
        for path, node in self.nodes.items():
            if node.fan_in == 0 and not _is_entry_point(path):
                dead.append(path)
        return sorted(dead)

    def get_dependencies(self, path: str, depth: int = 1) -> set[str]:
        """Get transitive forward dependencies up to `depth` levels."""
        if path not in self.nodes:
            return set()
        visited = set()
        queue = deque([(path, 0)])
        while queue:
            current, d = queue.popleft()
            if d >= depth:
                continue
            for dep in self.nodes.get(current, FileNode(path="", language="")).imports:
                if dep not in visited:
                    visited.add(dep)
                    queue.append((dep, d + 1))
        return visited

    def get_dependents(self, path: str, depth: int = 1) -> set[str]:
        """Get transitive reverse dependencies (files that depend on this)."""
        if path not in self.nodes:
            return set()
        visited = set()
        queue = deque([(path, 0)])
        while queue:
            current, d = queue.popleft()
            if d >= depth:
                continue
            for dep in self.nodes.get(current, FileNode(path="", language="")).imported_by:
                if dep not in visited:
                    visited.add(dep)
                    queue.append((dep, d + 1))
        return visited

    def topological_sort(self) -> list[str]:
        """Kahn's algorithm. Returns files in dependency order.

        Files with no deps come first (leaves before consumers).
        If cycles exist, remaining nodes are appended in sorted order.
        """
        # in_degree = number of dependencies (imports) each file has
        in_degree = {}
        for path, node in self.nodes.items():
            in_degree[path] = sum(1 for d in node.imports if d in self.nodes)

        queue = deque(sorted(p for p, d in in_degree.items() if d == 0))
        result = []

        while queue:
            current = queue.popleft()
            result.append(current)
            # For each file that imports current, decrement its dep count
            for dependent in sorted(self.nodes[current].imported_by):
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)

        # Append any remaining (cycle members) in sorted order
        remaining = sorted(set(self.nodes.keys()) - set(result))
        result.extend(remaining)
        return result

    def rank_by_importance(self) -> list[tuple[str, int]]:
        """Rank files by weighted fan_in/fan_out score.

        Score = fan_in * 2 + fan_out (being imported is more important).
        """
        ranked = []
        for path, node in self.nodes.items():
            score = node.fan_in * 2 + node.fan_out
            ranked.append((path, score))
        ranked.sort(key=lambda x: (-x[1], x[0]))
        return ranked

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "nodes": {p: n.to_dict() for p, n in sorted(self.nodes.items())},
            "circular_deps": [list(c) for c in self.circular_deps],
        }


@dataclass
class GraphMetrics:
    """Summary metrics for a dependency graph."""

    total_files: int = 0
    total_edges: int = 0
    avg_fan_in: float = 0.0
    avg_fan_out: float = 0.0
    max_fan_in: tuple[str, int] = ("", 0)
    max_fan_out: tuple[str, int] = ("", 0)
    hub_files: list[str] = field(default_factory=list)
    dead_modules: list[str] = field(default_factory=list)
    circular_deps: list[tuple[str, ...]] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    coupling_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "total_edges": self.total_edges,
            "avg_fan_in": round(self.avg_fan_in, 2),
            "avg_fan_out": round(self.avg_fan_out, 2),
            "max_fan_in": list(self.max_fan_in),
            "max_fan_out": list(self.max_fan_out),
            "hub_files": self.hub_files,
            "dead_modules": self.dead_modules,
            "circular_deps": [list(c) for c in self.circular_deps],
            "entry_points": self.entry_points,
            "coupling_score": round(self.coupling_score, 4),
        }


# ─── Entry point detection ──────────────────────────────────────────

_ENTRY_POINT_PATTERNS = {
    "__main__.py",
    "__init__.py",
    "main.py",
    "app.py",
    "server.py",
    "index.js",
    "index.ts",
    "index.tsx",
    "main.js",
    "main.ts",
    "setup.py",
    "conftest.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
}

_ENTRY_POINT_PREFIXES = ("test_", "tests/", "test/")


def _is_entry_point(path: str) -> bool:
    """Check if a file is likely an entry point (should not have fan_in)."""
    name = Path(path).name
    if name in _ENTRY_POINT_PATTERNS:
        return True
    # Test files are entry points
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    # Files in test directories
    rel = path.replace("\\", "/")
    if any(rel.startswith(p) or f"/{p}" in rel for p in _ENTRY_POINT_PREFIXES):
        return True
    return False


# ─── Import resolution ───────────────────────────────────────────────


def _detect_language(filepath: str) -> str | None:
    """Detect language from file extension."""
    suffix = Path(filepath).suffix.lower()
    return LANGUAGE_EXTENSIONS.get(suffix)


def _resolve_import_node(node, root_path: Path, file_dir: Path, resolved: set[str]) -> None:
    """Resolve a single import AST node to project file paths."""
    if isinstance(node, ast_mod.Import):
        for alias in node.names:
            _try_resolve_dotted(alias.name.split("."), root_path, resolved)
        return

    if not isinstance(node, ast_mod.ImportFrom):
        return

    if node.level == 0 and node.module:
        _try_resolve_dotted(node.module.split("."), root_path, resolved)
        return

    if node.level <= 0:
        return

    # Relative import
    base = file_dir
    for _ in range(node.level - 1):
        base = base.parent

    if node.module:
        _try_resolve_dotted(node.module.split("."), root_path, resolved, base=base)
    elif node.names:
        for alias in node.names:
            _try_resolve_dotted([alias.name], root_path, resolved, base=base)


def _resolve_python_imports(filepath: str, content: str, project_root: str) -> set[str]:
    """Parse Python AST for imports. Resolve to local project files only."""
    try:
        tree = ast_mod.parse(content)
    except SyntaxError:
        return set()

    root_path = Path(project_root)
    file_dir = Path(filepath).parent
    resolved: set[str] = set()

    for node in ast_mod.walk(tree):
        _resolve_import_node(node, root_path, file_dir, resolved)

    # Normalize to relative paths from project root
    normalized = set()
    for p in resolved:
        try:
            rel = str(Path(p).relative_to(root_path)).replace("\\", "/")
            normalized.add(rel)
        except ValueError as e:
            logger.debug("Failed to compute relative path: %s", e)
    return normalized


def _try_resolve_dotted(parts: list[str], root: Path, result: set[str], base: Path | None = None) -> None:
    """Try to resolve a dotted import path to a file on disk."""
    if base is None:
        base = root

    # Try as a module file: foo/bar.py
    mod_path = base / "/".join(parts)
    candidates = [
        mod_path.with_suffix(".py"),
        mod_path / "__init__.py",
    ]
    for c in candidates:
        if c.is_file():
            result.add(str(c))
            return

    # Try just the first part (e.g., import foo → foo.py)
    if len(parts) > 1:
        first_path = base / parts[0]
        candidates = [
            first_path.with_suffix(".py"),
            first_path / "__init__.py",
        ]
        for c in candidates:
            if c.is_file():
                result.add(str(c))
                return


# JS/TS import patterns
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"]"""
    r"""|import\s+['"]([^'"]+)['"]"""
    r"""|require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
    re.MULTILINE,
)

_JS_EXTENSIONS = [".js", ".ts", ".tsx", ".jsx", "/index.js", "/index.ts"]


def _resolve_js_ts_imports(filepath: str, content: str, project_root: str) -> set[str]:
    """Regex-based JS/TS import resolution. Only relative imports."""
    root_path = Path(project_root)
    file_dir = Path(filepath).parent
    resolved = set()

    for match in _JS_IMPORT_RE.finditer(content):
        raw_path = match.group(1) or match.group(2) or match.group(3)
        if not raw_path:
            continue
        # Only resolve relative imports
        if not raw_path.startswith("."):
            continue

        target = file_dir / raw_path
        # Try the path directly, then with extensions
        candidates = [target]
        for ext in _JS_EXTENSIONS:
            candidates.append(Path(str(target) + ext))

        for c in candidates:
            if c.is_file():
                try:
                    rel = str(c.relative_to(root_path)).replace("\\", "/")
                    resolved.add(rel)
                except ValueError as e:
                    logger.debug("Failed to compute relative path: %s", e)
                break

    return resolved


# ─── Java import resolution ──────────────────────────────────────────

_JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
_JAVA_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.MULTILINE,
)


def _build_java_package_map(
    files: dict[str, str], project_root: str,
) -> dict[str, str]:
    """Build package name → directory mapping from Java files.

    Scans all Java files for `package com.example;` declarations and maps
    the package name to the directory containing that file.
    """
    root_path = Path(project_root)
    pkg_to_dir: dict[str, str] = {}
    for filepath, content in files.items():
        m = _JAVA_PACKAGE_RE.search(content)
        if m:
            pkg_name = m.group(1)
            abs_dir = str(Path(filepath).parent)
            try:
                rel_dir = str(Path(abs_dir).relative_to(root_path)).replace("\\", "/")
            except ValueError:
                rel_dir = abs_dir.replace("\\", "/")
            pkg_to_dir[pkg_name] = rel_dir
    return pkg_to_dir


def _resolve_java_imports(
    filepath: str, content: str, project_root: str,
    pkg_map: dict[str, str] | None = None,
    java_files: dict[str, str] | None = None,
) -> set[str]:
    """Parse Java imports and resolve to project file paths.

    Handles:
    - `import com.example.UserService;` → resolves via package map
    - `import static com.example.Utils.method;` → resolves containing class

    Args:
        filepath: Path to the Java file being analyzed.
        content: Source code of the file.
        project_root: Project root directory.
        pkg_map: Pre-built package→directory map (avoids rebuilding per file).
        java_files: All Java files {path: content} for building pkg_map if needed.
    """
    root_path = Path(project_root)
    resolved: set[str] = set()

    if pkg_map is None and java_files is not None:
        pkg_map = _build_java_package_map(java_files, project_root)
    if pkg_map is None:
        pkg_map = {}

    for match in _JAVA_IMPORT_RE.finditer(content):
        import_path = match.group(1)  # e.g. "com.example.UserService"
        parts = import_path.split(".")
        if len(parts) < 2:
            continue

        # The last part is the class name (or method for static imports)
        class_name = parts[-1]
        pkg_parts = parts[:-1]

        # For static imports, the second-to-last is the class
        if class_name[0].islower() and len(parts) >= 3:
            class_name = parts[-2]
            pkg_parts = parts[:-2]

        pkg_name = ".".join(pkg_parts)

        # Look up the package directory
        pkg_dir = pkg_map.get(pkg_name)
        if pkg_dir is None:
            # Try parent packages (for nested packages not fully mapped)
            for i in range(len(pkg_parts) - 1, 0, -1):
                parent_pkg = ".".join(pkg_parts[:i])
                parent_dir = pkg_map.get(parent_pkg)
                if parent_dir is not None:
                    sub_path = "/".join(pkg_parts[i:])
                    pkg_dir = f"{parent_dir}/{sub_path}"
                    break
            if pkg_dir is None:
                continue

        # Try to find ClassNamee.java in the package directory
        candidate = f"{pkg_dir}/{class_name}.java"
        abs_candidate = root_path / candidate
        if abs_candidate.is_file():
            resolved.add(candidate)
            continue

        # Fallback: scan all known files for matching class name
        if java_files:
            for jf_path in java_files:
                jf_name = Path(jf_path).stem
                if jf_name == class_name:
                    try:
                        rel = str(Path(jf_path).relative_to(root_path)).replace("\\", "/")
                        resolved.add(rel)
                    except ValueError:
                        pass
                    break

    return resolved


# ─── Graph construction ──────────────────────────────────────────────


def build_dependency_graph(
    files: list[str],
    project_root: str,
    lang_filter: str | None = None,
) -> DepGraph:
    """Build a dependency graph from a list of file paths.

    Args:
        files: List of file paths (absolute or relative to project_root).
        project_root: Root directory of the project.
        lang_filter: Optional language filter (e.g., "python").

    Returns:
        DepGraph with resolved imports and cycle detection.
    """
    root_path = Path(project_root).resolve()
    graph = DepGraph(root=str(root_path))

    # Normalize all paths to relative from root
    rel_files = set()
    abs_to_rel = {}
    for f in files:
        fp = Path(f)
        if fp.is_absolute():
            try:
                rel = str(fp.relative_to(root_path)).replace("\\", "/")
            except ValueError:
                continue
        else:
            rel = str(fp).replace("\\", "/")
        rel_files.add(rel)
        abs_to_rel[str(fp)] = rel

    # Create nodes for all files
    for rel in sorted(rel_files):
        lang = _detect_language(rel)
        if lang is None:
            continue
        if lang_filter and lang != lang_filter:
            continue
        graph.nodes[rel] = FileNode(path=rel, language=lang)

    # Pre-read Java files for package map building
    java_file_contents: dict[str, str] = {}
    for rel, node in graph.nodes.items():
        if node.language == "java":
            abs_path = root_path / rel
            try:
                java_file_contents[str(abs_path)] = abs_path.read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                pass
    java_pkg_map = _build_java_package_map(java_file_contents, str(root_path)) if java_file_contents else {}

    # Resolve imports for each file
    for rel, node in list(graph.nodes.items()):
        abs_path = root_path / rel
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if node.language == "python":
            raw_imports = _resolve_python_imports(str(abs_path), content, str(root_path))
        elif node.language in ("javascript", "typescript"):
            raw_imports = _resolve_js_ts_imports(str(abs_path), content, str(root_path))
        elif node.language == "java":
            raw_imports = _resolve_java_imports(
                str(abs_path), content, str(root_path),
                pkg_map=java_pkg_map, java_files=java_file_contents,
            )
        else:
            continue

        # Only keep imports that are in our file set
        for imp in raw_imports:
            if imp in graph.nodes and imp != rel:
                node.imports.add(imp)

    # Build reverse edges (imported_by)
    for rel, node in graph.nodes.items():
        for imp in node.imports:
            if imp in graph.nodes:
                graph.nodes[imp].imported_by.add(rel)

    # Detect cycles
    graph.circular_deps = _detect_cycles(graph)

    return graph


def _detect_cycles(graph: DepGraph) -> list[tuple[str, ...]]:
    """DFS cycle detection with 3-color marking.

    WHITE (0) = unvisited, GRAY (1) = in progress, BLACK (2) = done.
    Returns list of cycles found as tuples of file paths.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {path: WHITE for path in graph.nodes}
    parent: dict[str, str] = {}
    cycles = []

    def dfs(u: str) -> None:
        color[u] = GRAY
        for v in sorted(graph.nodes[u].imports):
            if v not in color:
                continue
            if color[v] == GRAY:
                # Found cycle — reconstruct it
                cycle = [v]
                cur = u
                while cur != v:
                    cycle.append(cur)
                    cur = parent.get(cur, v)
                cycle.append(v)
                cycle.reverse()
                cycles.append(tuple(cycle))
            elif color[v] == WHITE:
                parent[v] = u
                dfs(v)
        color[u] = BLACK

    for path in sorted(graph.nodes):
        if color[path] == WHITE:
            dfs(path)

    return cycles


# ─── Call graph data structures (v0.8.0) ──────────────────────────────


@dataclass
class FunctionNode:
    """A function in the call graph."""

    name: str
    qualified_name: str
    file: str
    line: int
    params: list[str]
    has_varargs: bool = False
    callers: set[str] = field(default_factory=set)  # qualified names
    callees: set[str] = field(default_factory=set)  # qualified names


@dataclass
class CallGraph:
    """Function-level dependency graph."""

    functions: dict[str, FunctionNode] = field(default_factory=dict)  # qualified_name -> node
    unresolved_calls: list[tuple[str, str, int]] = field(default_factory=list)  # (caller, call_name, line)


def _link_caller_callee(cg: CallGraph, caller_qname: str, target_qname: str) -> None:
    """Add caller/callee edges if both nodes exist."""
    if caller_qname in cg.functions:
        cg.functions[caller_qname].callees.add(target_qname)
    if target_qname in cg.functions:
        cg.functions[target_qname].callers.add(caller_qname)


def _resolve_call(
    cg: CallGraph,
    dep_graph: DepGraph,
    name_to_qnames: dict[str, list[str]],
    rel_path: str,
    caller_qname: str,
    call_name: str,
) -> bool:
    """Resolve a single function call to its definition(s). Returns True if resolved."""
    # Same-file resolution
    same_file = [qn for qn in name_to_qnames.get(call_name, []) if qn.startswith(f"{rel_path}:")]
    if same_file:
        for target_qname in same_file:
            _link_caller_callee(cg, caller_qname, target_qname)
        return True

    # Cross-file resolution via dep graph imports
    deps = dep_graph.nodes.get(rel_path)
    if not deps:
        return False
    resolved = False
    for imp_file in deps.imports:
        cross = [qn for qn in name_to_qnames.get(call_name, []) if qn.startswith(f"{imp_file}:")]
        for target_qname in cross:
            _link_caller_callee(cg, caller_qname, target_qname)
            resolved = True
    return resolved


def build_call_graph(
    dep_graph: DepGraph,
    semantics_by_file: dict,
) -> CallGraph:
    """Build a call graph from extracted semantics across all files.

    Args:
        dep_graph: File-level dependency graph (for cross-file resolution).
        semantics_by_file: dict of rel_path -> FileSemantics.

    Returns:
        CallGraph with resolved function calls.
    """
    cg = CallGraph()

    # 1. Register all function definitions
    for rel_path, sem in semantics_by_file.items():
        for fdef in sem.function_defs:
            qname = f"{rel_path}:{fdef.qualified_name}"
            cg.functions[qname] = FunctionNode(
                name=fdef.name,
                qualified_name=qname,
                file=rel_path,
                line=fdef.line,
                params=fdef.params,
                has_varargs=fdef.has_varargs,
            )

    # 2. Build lookup: simple name -> list of qualified names
    name_to_qnames: dict[str, list[str]] = {}
    for qname, fnode in cg.functions.items():
        name_to_qnames.setdefault(fnode.name, []).append(qname)

    # 3. Resolve calls
    for rel_path, sem in semantics_by_file.items():
        for call in sem.function_calls:
            # Find innermost enclosing function
            caller_qnames = [
                f"{rel_path}:{fdef.qualified_name}"
                for fdef in sem.function_defs
                if fdef.line <= call.line <= fdef.end_line
            ]
            caller_qname = caller_qnames[-1] if caller_qnames else f"{rel_path}:<module>"

            if not _resolve_call(cg, dep_graph, name_to_qnames, rel_path, caller_qname, call.name):
                if call.name:
                    cg.unresolved_calls.append((caller_qname, call.name, call.line))

    return cg


def compute_metrics(graph: DepGraph) -> GraphMetrics:
    """Compute summary metrics for a dependency graph."""
    metrics = GraphMetrics()
    metrics.total_files = len(graph.nodes)

    if metrics.total_files == 0:
        return metrics

    total_fan_in = 0
    total_fan_out = 0
    max_fi = ("", 0)
    max_fo = ("", 0)

    for path, node in graph.nodes.items():
        fi = node.fan_in
        fo = node.fan_out
        total_fan_in += fi
        total_fan_out += fo
        metrics.total_edges += fo

        if fi > max_fi[1]:
            max_fi = (path, fi)
        if fo > max_fo[1]:
            max_fo = (path, fo)

        if node.is_hub:
            metrics.hub_files.append(path)

        if _is_entry_point(path):
            metrics.entry_points.append(path)

    metrics.avg_fan_in = total_fan_in / metrics.total_files
    metrics.avg_fan_out = total_fan_out / metrics.total_files
    metrics.max_fan_in = max_fi
    metrics.max_fan_out = max_fo
    metrics.hub_files.sort()
    metrics.entry_points.sort()
    metrics.dead_modules = graph.dead_modules
    metrics.circular_deps = graph.circular_deps

    # Coupling score: edges / max possible edges (n*(n-1))
    max_edges = metrics.total_files * (metrics.total_files - 1)
    metrics.coupling_score = metrics.total_edges / max_edges if max_edges > 0 else 0.0

    return metrics
