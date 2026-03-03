"""Shared tree-sitter node helpers.

Avoids duplicating these tiny one-liners in ts_cfg.py and ts_semantic.py.
"""

from __future__ import annotations


def _get_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _line(node) -> int:
    return node.start_point[0] + 1


def _end_line(node) -> int:
    return node.end_point[0] + 1
