"""Cross-file project analysis orchestrator.

Ties together dependency graphing, call graph analysis, per-file static
analysis, and optional LLM-powered synthesis into a single ProjectAnalysis
result. This is the main entry point for whole-project scans.

Called by: __main__.py (scan command), mcp_server.py
Calls into: graph/depgraph.py, graph/callgraph.py, config.py, discovery.py,
            detector.py, llm.py (lazy)
Data in -> Data out: directory path -> ProjectAnalysis
"""

from __future__ import annotations  # noqa

import ast as ast_mod
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

from ..detector import analyze_file_static
from ..discovery import collect_files, detect_language
from ..types import (
    Category,
    Confidence,
    CrossFileFinding,
    FileAnalysis,
    ProjectAnalysis,
    Severity,
)
from .depgraph import DepGraph, GraphMetrics, build_call_graph, build_dependency_graph, compute_metrics

# ─── Signature extraction ────────────────────────────────────────────


def _extract_signatures_python(content: str) -> str:
    """Extract class names, function signatures, and top-level constants from Python."""
    try:
        tree = ast_mod.parse(content)
    except SyntaxError:
        return content[:500]

    lines = []
    for node in ast_mod.iter_child_nodes(tree):
        if isinstance(node, ast_mod.ClassDef):
            bases = ", ".join(ast_mod.unparse(b) for b in node.bases)
            lines.append(f"class {node.name}({bases}):")
            for item in node.body:
                if isinstance(item, ast_mod.FunctionDef):
                    lines.append(f"    def {item.name}({ast_mod.unparse(item.args)}): ...")
        elif isinstance(node, ast_mod.FunctionDef):
            lines.append(f"def {node.name}({ast_mod.unparse(node.args)}): ...")
        elif isinstance(node, ast_mod.Assign):
            for target in node.targets:
                if isinstance(target, ast_mod.Name) and target.id.isupper():
                    lines.append(f"{target.id} = {ast_mod.unparse(node.value)[:80]}")

    return "\n".join(lines) if lines else content[:500]


_JS_EXPORT_RE = re.compile(
    r"""(?:export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)"""
    r"""|export\s+\{([^}]+)\}"""
    r"""|module\.exports\s*=)""",
    re.MULTILINE,
)


def _extract_signatures_js(content: str) -> str:
    """Extract exported functions/classes/constants from JS/TS."""
    lines = []
    for match in _JS_EXPORT_RE.finditer(content):
        name = match.group(1) or match.group(2)
        if name:
            lines.append(f"export {name.strip()}")

    # Also grab top-level function declarations
    for match in re.finditer(r"^(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", content, re.MULTILINE):
        sig = f"function {match.group(1)}({match.group(2)})"
        if sig not in lines:
            lines.append(sig)

    return "\n".join(lines) if lines else content[:500]


def _extract_signatures(content: str, language: str) -> str:
    """Extract signatures for context compression (~80% size reduction)."""
    if language == "python":
        return _extract_signatures_python(content)
    elif language in ("javascript", "typescript"):
        return _extract_signatures_js(content)
    return content[:500]


# ─── Context selection ───────────────────────────────────────────────

_CONTEXT_TOKEN_BUDGET = 30_000  # ~120KB of code context


def _select_context_for_file(
    filepath: str,
    graph: DepGraph,
    file_contents: dict[str, str],
    depth: int = 2,
) -> dict[str, str]:
    """Select context files for a given file within token budget.

    Strategy:
    1. Get transitive deps up to `depth`
    2. Rank by fan_in (most-imported = most important context)
    3. Allocate budget proportionally
    4. Large files get signature-only extraction
    """
    deps = graph.get_dependencies(filepath, depth=depth)
    dependents = graph.get_dependents(filepath, depth=1)
    all_related = deps | dependents

    if not all_related:
        return {}

    # Rank by fan_in
    ranked = []
    for rel in all_related:
        if rel in graph.nodes and rel in file_contents:
            ranked.append((rel, graph.nodes[rel].fan_in))
    ranked.sort(key=lambda x: (-x[1], x[0]))

    context = {}
    total_chars = 0
    char_budget = _CONTEXT_TOKEN_BUDGET * 4  # rough token-to-char ratio

    for rel, _fan_in in ranked:
        content = file_contents[rel]
        if total_chars + len(content) <= char_budget:
            context[rel] = content
            total_chars += len(content)
        else:
            # Extract signatures only for large files
            lang = graph.nodes[rel].language if rel in graph.nodes else "python"
            sig = _extract_signatures(content, lang)
            if total_chars + len(sig) <= char_budget:
                context[rel] = f"# [signatures only]\n{sig}"
                total_chars += len(sig)
            else:
                break

    return context


# ─── Graph summary formatting ────────────────────────────────────────


def _format_graph_summary(graph: DepGraph, metrics: GraphMetrics) -> str:
    """Format graph metrics as a readable text summary for LLM context."""
    lines = [
        f"Project: {metrics.total_files} files, {metrics.total_edges} dependency edges",
        f"Coupling score: {metrics.coupling_score:.2%}",
    ]

    if metrics.hub_files:
        lines.append(f"Hub files (high fan-in + fan-out): {', '.join(metrics.hub_files)}")

    if metrics.circular_deps:
        lines.append(f"Circular dependencies ({len(metrics.circular_deps)}):")
        for cycle in metrics.circular_deps[:5]:
            lines.append(f"  {' → '.join(cycle)}")

    if metrics.dead_modules:
        lines.append(f"Dead modules (never imported): {', '.join(metrics.dead_modules[:10])}")

    # Top files by importance
    ranked = graph.rank_by_importance()[:5]
    if ranked:
        lines.append("Top files by importance:")
        for path, score in ranked:
            node = graph.nodes[path]
            lines.append(f"  {path} (fan_in={node.fan_in}, fan_out={node.fan_out})")

    return "\n".join(lines)


# ─── Main orchestrator ───────────────────────────────────────────────


def _read_file_contents(files, root_path: Path) -> tuple[dict[str, str], list[str]]:
    """Read all file contents and return (rel_path -> content, abs_paths)."""
    file_contents = {}
    file_paths = []
    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            rel = str(fp.relative_to(root_path)).replace("\\", "/")
            file_contents[rel] = content
            file_paths.append(str(fp))
        except OSError:
            continue
    return file_contents, file_paths


def _extract_semantics_and_cross_file(
    root_path: Path, file_contents: dict[str, str], graph,
) -> tuple[dict, list]:
    """Extract semantics per file and run cross-file static analysis."""
    from ..semantic.core import extract_semantics

    semantics_by_file = {}
    for rel, content in file_contents.items():
        lang = detect_language(root_path / rel)
        if lang:
            sem = extract_semantics(content, rel, lang)
            if sem:
                semantics_by_file[rel] = sem

    cross_file_static_findings = []
    if not semantics_by_file:
        return semantics_by_file, cross_file_static_findings

    call_graph = build_call_graph(graph, semantics_by_file)

    from ..semantic.smells import check_near_duplicate_functions, check_semantic_clones
    from .callgraph import find_arg_count_mismatches, find_dead_functions

    cross_file_static_findings.extend(find_dead_functions(call_graph, graph))
    cross_file_static_findings.extend(find_arg_count_mismatches(call_graph, semantics_by_file))
    cross_file_static_findings.extend(check_near_duplicate_functions(semantics_by_file))
    cross_file_static_findings.extend(check_semantic_clones(semantics_by_file))

    # v0.10.0: Cross-file contract inference
    try:
        from ..semantic.lang_config import get_config as get_lang_config
        from ..semantic.types import infer_types

        for rel, sem in semantics_by_file.items():
            lang_cfg = get_lang_config(sem.language)
            if lang_cfg:
                content = file_contents.get(rel, "")
                src_bytes = content.encode("utf-8")
                infer_types(sem, src_bytes, lang_cfg)
    except (ValueError, OSError, AttributeError) as e:
        logger.debug("Cross-file type inference skipped: %s", e)

    return semantics_by_file, cross_file_static_findings


def _build_static_only_result(
    root_path: Path, file_contents: dict[str, str], metrics, graph,
    cross_file_static_findings: list,
) -> ProjectAnalysis:
    """Build ProjectAnalysis for no-LLM mode."""
    static_per_file: dict[str, list] = {}
    for f in cross_file_static_findings:
        static_per_file.setdefault(f.file, []).append(f)

    per_file_analyses = []
    for rel, content in file_contents.items():
        lang = detect_language(root_path / rel)
        fa = FileAnalysis(
            path=str(root_path / rel),
            language=lang or "unknown",
            lines=content.count("\n") + 1,
            findings=static_per_file.get(rel, []),
        )
        if fa.findings:
            per_file_analyses.append(fa)

    return ProjectAnalysis(
        root=str(root_path),
        files_analyzed=len(file_contents),
        graph_metrics=metrics.to_dict(),
        dependency_graph=graph.to_dict(),
        per_file_findings=per_file_analyses,
    )


def _build_cross_findings(raw_findings: list) -> list[CrossFileFinding]:
    """Convert raw LLM cross-file finding dicts to CrossFileFinding objects."""
    cross_findings = []
    for cf in raw_findings:
        try:
            cross_findings.append(
                CrossFileFinding(
                    source_file=cf.get("source_file", ""),
                    target_file=cf.get("target_file", ""),
                    line=cf.get("line", 0),
                    target_line=cf.get("target_line"),
                    severity=Severity(cf.get("severity", "warning")),
                    category=Category(cf.get("category", "bug")),
                    rule=cf.get("rule", "cross-file-issue"),
                    message=cf.get("message", ""),
                    suggestion=cf.get("suggestion"),
                    confidence=Confidence(cf.get("confidence", "medium")) if cf.get("confidence") else None,
                )
            )
        except (ValueError, KeyError):
            continue
    return cross_findings


def analyze_project(
    root: str,
    language_filter: str | None = None,
    depth: int = 2,
    use_llm: bool = True,
) -> ProjectAnalysis:
    """Analyze a project for cross-file issues.

    Args:
        root: Project root directory.
        language_filter: Optional language filter.
        depth: Dependency traversal depth (default 2).
        use_llm: If False, return graph + metrics only (no API key needed).

    Returns:
        ProjectAnalysis with graph, metrics, and optionally LLM findings.
    """
    root_path = Path(root).resolve()

    files, _skipped = collect_files(root_path, language_filter)
    if not files:
        return ProjectAnalysis(root=str(root_path), files_analyzed=0, graph_metrics={}, dependency_graph={})

    file_contents, file_paths = _read_file_contents(files, root_path)
    graph = build_dependency_graph(file_paths, str(root_path), lang_filter=language_filter)
    metrics = compute_metrics(graph)
    graph_summary = _format_graph_summary(graph, metrics)

    _semantics_by_file, cross_file_static_findings = _extract_semantics_and_cross_file(
        root_path, file_contents, graph,
    )

    if not use_llm:
        return _build_static_only_result(root_path, file_contents, metrics, graph, cross_file_static_findings)

    # LLM analysis
    from ..plugin import require_llm_plugin

    _llm = require_llm_plugin()
    cost_tracker = _llm.CostTracker()
    topo_order = graph.topological_sort()

    per_file_results = []
    per_file_analyses = []
    all_cross_file_findings = []

    for i, rel_path in enumerate(topo_order):
        if rel_path not in file_contents:
            continue
        content = file_contents[rel_path]
        lang = detect_language(root_path / rel_path)
        if not lang:
            continue

        abs_path = str(root_path / rel_path)
        print(f"  [{i + 1}/{len(topo_order)}] {rel_path} ({lang})", flush=True)

        static_findings = analyze_file_static(abs_path, content, lang).findings
        for cf in cross_file_static_findings:
            if cf.file == rel_path:
                static_findings.append(cf)

        context = _select_context_for_file(rel_path, graph, file_contents, depth=depth)
        try:
            result, cost_tracker = _llm.analyze_file_with_context(
                content, rel_path, lang, context_files=context,
                graph_summary=graph_summary, static_findings=static_findings, cost_tracker=cost_tracker,
            )
        except (_llm.LLMError, OSError, ValueError) as e:
            logger.warning("LLM error for %s: %s", rel_path, e)
            result = {"cross_file_findings": [], "local_findings": []}

        all_cross_file_findings.extend(result.get("cross_file_findings", []))
        per_file_results.append({"path": rel_path, **result})
        per_file_analyses.append(FileAnalysis(path=abs_path, language=lang, lines=content.count("\n") + 1, findings=static_findings))

    synthesis = None
    try:
        synthesis, cost_tracker = _llm.synthesize_project(
            graph_summary=graph_summary, per_file_summaries=per_file_results,
            all_cross_file_findings=all_cross_file_findings, cost_tracker=cost_tracker,
        )
    except (_llm.LLMError, OSError, ValueError) as e:
        logger.warning("Synthesis error: %s", e)

    return ProjectAnalysis(
        root=str(root_path),
        files_analyzed=len(file_contents),
        graph_metrics=metrics.to_dict(),
        dependency_graph=graph.to_dict(),
        per_file_findings=per_file_analyses,
        cross_file_findings=_build_cross_findings(all_cross_file_findings),
        synthesis=synthesis,
        llm_cost_usd=cost_tracker.total_cost,
    )
