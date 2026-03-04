"""dojigiri.graph — Dependency graph and project-level analysis."""

from .depgraph import (
    FileNode,
    DepGraph,
    GraphMetrics,
    FunctionNode,
    CallGraph,
    build_dependency_graph,
    build_call_graph,
    compute_metrics,
)
from .project import analyze_project
from .callgraph import find_dead_functions, find_arg_count_mismatches

__all__ = [
    # depgraph
    "FileNode", "DepGraph", "GraphMetrics", "FunctionNode", "CallGraph",
    "build_dependency_graph", "build_call_graph", "compute_metrics",
    # project
    "analyze_project",
    # callgraph
    "find_dead_functions", "find_arg_count_mismatches",
]
