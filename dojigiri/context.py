"""Context file discovery for LLM-powered analysis.

Resolves related files (imports, dependencies) to provide context alongside
the primary file being analyzed. Used by debug, optimize, and deep scan.

Called by: __main__.py
Calls into: graph/depgraph.py, discovery.py
Data in -> Data out: filepath + language -> {filepath: content} dict
"""

import sys
from pathlib import Path
from typing import Optional

# Maximum total bytes of context files to collect (avoids blowing token budget)
_MAX_CONTEXT_BYTES = 50_000


def auto_discover_python_imports(filepath: str, content: str) -> dict[str, str]:
    """Discover local Python imports and read their contents (legacy fallback).

    Parses AST for import/from-import statements, resolves to local files
    in the same directory or relative paths. Returns {filepath: content} dict.
    Caps at 50KB total to avoid blowing token budget.
    """
    import ast as ast_mod

    try:
        tree = ast_mod.parse(content)
    except SyntaxError:
        return {}

    base_dir = Path(filepath).parent
    candidates = set()

    for node in ast_mod.walk(tree):
        if isinstance(node, ast_mod.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                candidates.add(parts[0])
        elif isinstance(node, ast_mod.ImportFrom):
            if node.module and node.level == 0:
                parts = node.module.split(".")
                candidates.add(parts[0])
            elif node.level > 0 and node.module:
                candidates.add(node.module.split(".")[0])

    result = {}
    total_size = 0

    for mod_name in sorted(candidates):
        mod_path = base_dir / f"{mod_name}.py"
        if mod_path.is_file():
            try:
                mod_content = mod_path.read_text(encoding="utf-8", errors="replace")
                if total_size + len(mod_content) > _MAX_CONTEXT_BYTES:
                    break
                result[str(mod_path)] = mod_content
                total_size += len(mod_content)
            except OSError:
                continue

    return result


def auto_discover_imports(filepath: str, content: str, lang: str) -> dict[str, str]:
    """Enhanced context discovery using depgraph — transitive deps, ranked by importance.

    Falls back to legacy auto_discover_python_imports if depgraph fails.
    Works for Python, JS, and TS (not just Python).
    """
    try:
        from .graph.depgraph import build_dependency_graph
        from .discovery import collect_files

        fp = Path(filepath).resolve()
        project_root = fp.parent

        # Try to find the actual project root (look for common markers)
        for parent in [fp.parent] + list(fp.parents):
            if any((parent / marker).exists() for marker in
                   [".git", "pyproject.toml", "setup.py", "package.json", ".doji.toml"]):
                project_root = parent
                break

        # Collect sibling files in the project
        files, _ = collect_files(project_root, language_filter=lang)
        if not files:
            raise ValueError("No files found")

        graph = build_dependency_graph([str(f) for f in files], str(project_root))

        # Find our file in the graph
        try:
            rel = str(fp.relative_to(project_root)).replace("\\", "/")
        except ValueError:
            raise ValueError("File not in project root")

        if rel not in graph.nodes:
            raise ValueError(f"File {rel} not in graph")

        # Get transitive deps (depth 2) + direct dependents
        deps = graph.get_dependencies(rel, depth=2)
        dependents = graph.get_dependents(rel, depth=1)
        all_related = deps | dependents

        if not all_related:
            return {}

        # Rank by fan_in (most important first)
        ranked = []
        for r in all_related:
            if r in graph.nodes:
                ranked.append((r, graph.nodes[r].fan_in))
        ranked.sort(key=lambda x: (-x[1], x[0]))

        result = {}
        total_size = 0

        for r, _fi in ranked:
            abs_path = project_root / r
            if abs_path.is_file():
                try:
                    ctx_content = abs_path.read_text(encoding="utf-8", errors="replace")
                    if total_size + len(ctx_content) > _MAX_CONTEXT_BYTES:
                        break
                    result[str(abs_path)] = ctx_content
                    total_size += len(ctx_content)
                except OSError:
                    continue

        return result

    except (OSError, ValueError, ImportError):
        # Fall back to legacy method for Python
        if lang == "python":
            return auto_discover_python_imports(filepath, content)
        return {}


def collect_context_files(context_arg: str, filepath: str, lang: str,
                          content: str) -> Optional[dict[str, str]]:
    """Collect context files based on --context argument.

    "auto" → auto-discover imports using depgraph (v2) with legacy fallback
    comma-separated paths → read each file
    """
    if context_arg == "auto":
        return auto_discover_imports(filepath, content, lang)

    result = {}
    total_size = 0

    for path_str in context_arg.split(","):
        path_str = path_str.strip()
        if not path_str:
            continue
        ctx_path = Path(path_str).resolve()
        if ctx_path.is_file():
            try:
                ctx_content = ctx_path.read_text(encoding="utf-8", errors="replace")
                if total_size + len(ctx_content) > _MAX_CONTEXT_BYTES:
                    print(f"  Skipping {path_str} (context size cap reached)", file=sys.stderr)
                    break
                result[str(ctx_path)] = ctx_content
                total_size += len(ctx_content)
            except OSError as e:
                print(f"  Warning: couldn't read context file {path_str}: {e}", file=sys.stderr)
        else:
            print(f"  Warning: context file not found: {path_str}", file=sys.stderr)

    return result if result else None
