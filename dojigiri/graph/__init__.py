"""dojigiri.graph — Dependency graph and project-level analysis."""

from .callgraph import find_arg_count_mismatches, find_dead_functions  # doji:ignore(unused-import)
from .depgraph import (  # doji:ignore(unused-import)
    CallGraph,
    DepGraph,
    FileNode,
    FunctionNode,
    GraphMetrics,
    build_call_graph,
    build_dependency_graph,
    compute_metrics,
)
from .project import analyze_project  # doji:ignore(unused-import)

__all__ = [
    # depgraph
    "FileNode",
    "DepGraph",
    "GraphMetrics",
    "FunctionNode",
    "CallGraph",
    "build_dependency_graph",
    "build_call_graph",
    "compute_metrics",
    # project
    "analyze_project",
    # callgraph
    "find_dead_functions",
    "find_arg_count_mismatches",
]
