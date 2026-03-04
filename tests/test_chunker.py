"""Tests for chunker module - file splitting and token estimation."""

import pytest
from dojigiri.chunker import chunk_file, estimate_tokens, Chunk


def test_chunk_small_file():
    """Test that small files return a single chunk."""
    content = "\n".join([f"line {i}" for i in range(50)])
    chunks = chunk_file(content, "test.py", "python", chunk_size=400, overlap=30)
    
    assert len(chunks) == 1
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 50
    assert chunks[0].chunk_index == 0
    assert chunks[0].total_chunks == 1
    assert chunks[0].filepath == "test.py"
    assert chunks[0].language == "python"
    assert chunks[0].content == content


def test_chunk_large_file_with_overlap():
    """Test that large files are split with overlap."""
    # Create 1000 line file
    lines = [f"line {i}" for i in range(1000)]
    content = "\n".join(lines)
    
    chunks = chunk_file(content, "large.py", "python", chunk_size=400, overlap=30)
    
    # Should create multiple chunks
    assert len(chunks) > 1
    
    # Check all chunks have correct metadata
    for i, chunk in enumerate(chunks):
        assert chunk.chunk_index == i
        assert chunk.total_chunks == len(chunks)
        assert chunk.filepath == "large.py"
        assert chunk.language == "python"
    
    # First chunk should start at line 1
    assert chunks[0].start_line == 1
    
    # Last chunk should end at total lines
    assert chunks[-1].end_line == 1000
    
    # Check overlap between consecutive chunks
    if len(chunks) > 1:
        # The overlap should be visible in line ranges
        step = 400 - 30  # chunk_size - overlap
        expected_start_2nd = 1 + step
        assert chunks[1].start_line == expected_start_2nd


def test_chunk_exact_boundary():
    """Test chunking when file size exactly matches chunk size."""
    lines = [f"line {i}" for i in range(400)]
    content = "\n".join(lines)
    
    chunks = chunk_file(content, "exact.py", "python", chunk_size=400, overlap=30)
    
    assert len(chunks) == 1
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 400


def test_chunk_just_over_boundary():
    """Test chunking when file is just over chunk size."""
    lines = [f"line {i}" for i in range(401)]
    content = "\n".join(lines)
    
    chunks = chunk_file(content, "over.py", "python", chunk_size=400, overlap=30)
    
    assert len(chunks) == 2


def test_chunk_empty_file():
    """Test chunking an empty file."""
    content = ""
    chunks = chunk_file(content, "empty.py", "python")
    
    assert len(chunks) == 1
    assert chunks[0].content == ""
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 0


def test_chunk_single_line():
    """Test chunking a file with a single line."""
    content = "single line"
    chunks = chunk_file(content, "single.py", "python")
    
    assert len(chunks) == 1
    assert chunks[0].content == "single line"
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 1


def test_chunk_header_property():
    """Test the Chunk.header property formatting."""
    chunk = Chunk(
        content="test",
        start_line=10,
        end_line=50,
        chunk_index=2,
        total_chunks=5,
        filepath="/path/to/file.py",
        language="python",
    )
    
    header = chunk.header
    assert "File: /path/to/file.py" in header
    assert "(python)" in header
    assert "Lines 10-50" in header
    assert "chunk 3/5" in header  # chunk_index + 1


def test_estimate_tokens():
    """Test token estimation calculation."""
    # estimate_tokens divides by 4 (4 chars per token)
    assert estimate_tokens("") == 0
    assert estimate_tokens("a" * 4) == 1
    assert estimate_tokens("a" * 8) == 2
    assert estimate_tokens("a" * 100) == 25
    
    # Test with realistic code
    code = "def function():\n    return True"
    expected = len(code) // 4
    assert estimate_tokens(code) == expected


def test_chunk_default_parameters():
    """Test that default chunk_size and overlap from config are used."""
    from dojigiri.config import CHUNK_SIZE, CHUNK_OVERLAP
    
    # Create file larger than default CHUNK_SIZE
    lines = [f"line {i}" for i in range(CHUNK_SIZE + 100)]
    content = "\n".join(lines)
    
    chunks = chunk_file(content, "test.py", "python")
    
    # Should use default parameters and create chunks
    assert len(chunks) > 1


def test_chunk_different_languages():
    """Test chunking works with different language identifiers."""
    content = "\n".join([f"line {i}" for i in range(50)])
    
    languages = ["python", "javascript", "go", "rust", "java"]
    for lang in languages:
        chunks = chunk_file(content, f"test.{lang}", lang)
        assert len(chunks) == 1
        assert chunks[0].language == lang


def test_chunk_preserves_content_integrity():
    """Test that chunking preserves all content without loss."""
    lines = [f"line {i}" for i in range(500)]
    original_content = "\n".join(lines)
    
    chunks = chunk_file(original_content, "test.py", "python", chunk_size=200, overlap=20)
    
    # Reconstruct content from first chunk and non-overlapping parts of others
    if len(chunks) == 1:
        reconstructed = chunks[0].content
    else:
        # For multiple chunks, the full content is not directly reconstructable
        # due to overlap, but we can verify all lines are covered
        covered_lines = set()
        for chunk in chunks:
            for line_num in range(chunk.start_line, chunk.end_line + 1):
                covered_lines.add(line_num)
        
        # All lines should be covered (1-indexed)
        assert min(covered_lines) == 1
        assert max(covered_lines) == 500
        assert len(covered_lines) == 500
