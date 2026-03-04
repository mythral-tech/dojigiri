"""Split large files into overlapping chunks for LLM context management."""

import ast
from dataclasses import dataclass
from .config import CHUNK_SIZE, CHUNK_OVERLAP


@dataclass
class Chunk:
    content: str
    start_line: int
    end_line: int
    chunk_index: int
    total_chunks: int
    filepath: str
    language: str

    @property
    def header(self) -> str:
        return (
            f"File: {self.filepath} ({self.language})\n"
            f"Lines {self.start_line}-{self.end_line} "
            f"(chunk {self.chunk_index + 1}/{self.total_chunks})"
        )


def _find_python_boundaries(content: str) -> list[int]:
    """Find top-level function/class start lines using AST.

    Returns a sorted list of 0-indexed line numbers where top-level
    definitions start. Returns empty list on parse failure.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    boundaries = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            boundaries.append(node.lineno - 1)  # AST is 1-indexed, we want 0-indexed

    return sorted(boundaries)


def _chunk_by_boundaries(
    lines: list[str],
    boundaries: list[int],
    filepath: str,
    language: str,
    chunk_size: int,
) -> list[Chunk]:
    """Split lines into chunks at AST boundaries, respecting chunk_size.

    Groups consecutive top-level definitions into chunks that stay
    under chunk_size lines. Falls back to line-based if a single
    definition exceeds chunk_size.
    """
    total_lines = len(lines)
    if not boundaries:
        return []

    # Build segments: [0, boundary1), [boundary1, boundary2), ..., [boundaryN, end)
    segment_starts = [0] + boundaries
    segment_ends = boundaries + [total_lines]
    segments = list(zip(segment_starts, segment_ends))

    chunks: list[Chunk] = []
    current_start = 0
    current_end = 0

    for seg_start, seg_end in segments:
        seg_len = seg_end - seg_start

        # If adding this segment would exceed chunk_size, flush current chunk
        if current_end > current_start and (current_end - current_start) + seg_len > chunk_size:
            chunk_content = "\n".join(lines[current_start:current_end])
            chunks.append(Chunk(
                content=chunk_content,
                start_line=current_start + 1,
                end_line=current_end,
                chunk_index=len(chunks),
                total_chunks=0,
                filepath=filepath,
                language=language,
            ))
            current_start = seg_start
            current_end = seg_end
        else:
            current_end = seg_end

    # Flush remaining
    if current_end > current_start:
        chunk_content = "\n".join(lines[current_start:current_end])
        chunks.append(Chunk(
            content=chunk_content,
            start_line=current_start + 1,
            end_line=current_end,
            chunk_index=len(chunks),
            total_chunks=0,
            filepath=filepath,
            language=language,
        ))

    # Fix total_chunks
    for c in chunks:
        c.total_chunks = len(chunks)

    return chunks


def chunk_file(
    content: str,
    filepath: str,
    language: str,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[Chunk]:
    """Split file content into chunks for LLM analysis.

    For Python files, uses AST to split at function/class boundaries.
    For other languages, uses line-based splitting with overlap.
    Small files (<=chunk_size lines) always return a single chunk.
    """
    lines = content.splitlines()
    total_lines = len(lines)

    if total_lines <= chunk_size:
        return [Chunk(
            content=content,
            start_line=1,
            end_line=total_lines,
            chunk_index=0,
            total_chunks=1,
            filepath=filepath,
            language=language,
        )]

    # Python: try AST-aware chunking
    if language == "python":
        boundaries = _find_python_boundaries(content)
        if boundaries:
            chunks = _chunk_by_boundaries(lines, boundaries, filepath, language, chunk_size)
            if chunks:
                return chunks
        # Fallback to line-based if AST fails or produces no boundaries

    # Line-based chunking with overlap (default for non-Python)
    return _chunk_lines(lines, filepath, language, chunk_size, overlap)


def _chunk_lines(
    lines: list[str],
    filepath: str,
    language: str,
    chunk_size: int,
    overlap: int,
) -> list[Chunk]:
    """Line-based chunking with overlap."""
    total_lines = len(lines)
    chunks: list[Chunk] = []
    start = 0
    step = chunk_size - overlap

    while start < total_lines:
        end = min(start + chunk_size, total_lines)
        chunk_lines = lines[start:end]
        chunk_content = "\n".join(chunk_lines)

        chunks.append(Chunk(
            content=chunk_content,
            start_line=start + 1,
            end_line=end,
            chunk_index=len(chunks),
            total_chunks=0,  # filled in below
            filepath=filepath,
            language=language,
        ))

        if end >= total_lines:
            break
        start += step

    # Fix total_chunks
    for c in chunks:
        c.total_chunks = len(chunks)

    return chunks


def estimate_tokens(content: str) -> int:
    """Rough token estimate: ~4 chars per token for code."""
    return len(content) // 4
