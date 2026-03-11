"""Tests for dojigiri/chunker.py — file chunking for LLM analysis."""

import pytest
from dojigiri.chunker import (
    Chunk,
    _chunk_by_boundaries,
    _chunk_lines,
    _find_python_boundaries,
    _finalize_chunks,
    chunk_file,
    estimate_tokens,
)


class TestFindPythonBoundaries:
    def test_finds_functions(self):
        code = "x = 1\n\ndef foo():\n    pass\n\ndef bar():\n    pass\n"
        bounds = _find_python_boundaries(code)
        assert len(bounds) == 2
        assert bounds[0] == 2  # 0-indexed line for def foo
        assert bounds[1] == 5  # 0-indexed line for def bar

    def test_finds_classes(self):
        code = "class Foo:\n    pass\n\nclass Bar:\n    pass\n"
        bounds = _find_python_boundaries(code)
        assert len(bounds) == 2

    def test_syntax_error_returns_empty(self):
        assert _find_python_boundaries("def bad(\n") == []

    def test_no_definitions(self):
        code = "x = 1\ny = 2\n"
        assert _find_python_boundaries(code) == []


class TestChunkByBoundaries:
    def test_single_chunk(self):
        lines = ["line" + str(i) for i in range(10)]
        boundaries = [3, 6]
        chunks = _chunk_by_boundaries(lines, boundaries, "test.py", "python", 100)
        assert len(chunks) == 1
        assert chunks[0].total_chunks == 1

    def test_multiple_chunks(self):
        lines = ["line" + str(i) for i in range(30)]
        boundaries = [5, 10, 15, 20, 25]
        chunks = _chunk_by_boundaries(lines, boundaries, "test.py", "python", 8)
        assert len(chunks) > 1
        for c in chunks:
            assert c.total_chunks == len(chunks)

    def test_no_boundaries(self):
        lines = ["line" + str(i) for i in range(10)]
        chunks = _chunk_by_boundaries(lines, [], "test.py", "python", 100)
        assert chunks == []


class TestChunkLines:
    def test_basic_chunking(self):
        lines = ["line" + str(i) for i in range(20)]
        chunks = _chunk_lines(lines, "test.js", "javascript", 8, 2)
        assert len(chunks) > 1
        assert chunks[0].start_line == 1

    def test_single_chunk(self):
        lines = ["line0", "line1"]
        chunks = _chunk_lines(lines, "test.js", "javascript", 100, 0)
        assert len(chunks) == 1


class TestChunkFile:
    def test_small_file_single_chunk(self):
        content = "x = 1\ny = 2\n"
        chunks = chunk_file(content, "test.py", "python")
        assert len(chunks) == 1
        assert chunks[0].total_chunks == 1

    def test_large_python_file(self):
        # Create content with 500+ lines and some function definitions
        lines = ["x = 1"] * 50
        lines.append("def foo():")
        lines.extend(["    pass"] * 200)
        lines.append("def bar():")
        lines.extend(["    pass"] * 200)
        content = "\n".join(lines)
        chunks = chunk_file(content, "test.py", "python", chunk_size=100)
        assert len(chunks) >= 2

    def test_large_js_file(self):
        lines = ["let x = 1;"] * 500
        content = "\n".join(lines)
        chunks = chunk_file(content, "test.js", "javascript", chunk_size=100, overlap=10)
        assert len(chunks) >= 2

    def test_python_no_boundaries_falls_back(self):
        """Python file with no functions falls back to line-based chunking."""
        lines = ["x = " + str(i) for i in range(500)]
        content = "\n".join(lines)
        chunks = chunk_file(content, "test.py", "python", chunk_size=100)
        assert len(chunks) >= 2


class TestChunkHeader:
    def test_header_format(self):
        c = Chunk(content="x", start_line=1, end_line=10,
                  chunk_index=0, total_chunks=3, filepath="test.py", language="python")
        h = c.header
        assert "test.py" in h
        assert "1-10" in h
        assert "1/3" in h


class TestEstimateTokens:
    def test_estimate(self):
        assert estimate_tokens("a" * 100) == 25

    def test_empty(self):
        assert estimate_tokens("") == 0


class TestFinalizeChunks:
    def test_sets_total(self):
        chunks = [
            Chunk("a", 1, 5, 0, 0, "f", "py"),
            Chunk("b", 6, 10, 1, 0, "f", "py"),
        ]
        result = _finalize_chunks(chunks)
        assert all(c.total_chunks == 2 for c in result)
