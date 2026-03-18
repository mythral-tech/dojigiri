"""Shared types and utilities for cross-file taint analysis.

Used by both taint_cross.py (Python, ast-based) and taint_cross_ts.py
(JS/Java, tree-sitter-based). Factored out to avoid duplication.

Called by: taint_cross.py, taint_cross_ts.py
Calls into: types.py
Data in → Data out: pure types, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import Severity

_CRITICAL_SINK_KINDS = {"sql_query", "system_cmd", "eval", "llm_input", "ssrf"}


def _taint_severity(sink_kind: str, source_kind: str = "") -> Severity:
    """Critical for dangerous sinks with confirmed taint flow, warning otherwise.

    Parameter-sourced taint stays WARNING — speculative without caller analysis.
    """
    if source_kind == "parameter":
        return Severity.WARNING
    return Severity.CRITICAL if sink_kind in _CRITICAL_SINK_KINDS else Severity.WARNING


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
