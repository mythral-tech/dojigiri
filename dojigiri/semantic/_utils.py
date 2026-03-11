"""Shared tree-sitter node helpers.

Small utility functions for extracting text and line numbers from tree-sitter
nodes. Avoids duplicating these one-liners across semantic modules.

Called by: semantic/core.py, semantic/checks.py, semantic/cfg.py, semantic/taint.py,
          semantic/types.py, semantic/nullsafety.py, semantic/resource.py, semantic/smells.py
Calls into: nothing (standalone utility)
Data in → Data out: tree-sitter Node → text string or line number
"""

from __future__ import annotations  # noqa


def _get_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _line(node) -> int:
    return node.start_point[0] + 1


def _end_line(node) -> int:
    return node.end_point[0] + 1
