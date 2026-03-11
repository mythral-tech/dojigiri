"""File discovery: language detection, skip rules, and directory walking.

Pure file-system utilities with no orchestration dependency. Extracted from
analyzer.py so that sub-packages (e.g. graph/) can use file discovery without
importing the full analysis pipeline — keeping dependency direction clean.

Called by: analyzer.py, graph/project.py, mcp_server.py, __main__.py
Calls into: config.py (constants + ignore patterns)
Data in -> Data out: Path in -> list[Path] / bool / Optional[str] out
"""

from __future__ import annotations  # noqa

import fnmatch
from pathlib import Path

from .config import (
    LANGUAGE_EXTENSIONS,
    MAX_FILE_SIZE,
    SENSITIVE_FILE_PATTERNS,
    SKIP_DIRS,
    SKIP_FILES,
    load_ignore_patterns,
)


def detect_language(filepath: Path) -> str | None:
    """Detect language from file extension."""
    return LANGUAGE_EXTENSIONS.get(filepath.suffix.lower())


def should_skip_dir(dirname: str) -> bool:
    """Check if directory should be skipped."""
    return dirname in SKIP_DIRS or dirname.startswith(".")


def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped."""
    if filepath.name in SKIP_FILES:
        return True
    # Block sensitive files (secrets, keys, credentials)
    if any(fnmatch.fnmatch(filepath.name, pat) for pat in SENSITIVE_FILE_PATTERNS):
        return True
    if filepath.suffix.lower() not in LANGUAGE_EXTENSIONS:
        return True
    try:
        size = filepath.stat().st_size
        if size > MAX_FILE_SIZE or size == 0:
            return True
    except OSError:
        return True
    return False


def collect_files(
    root: Path,
    language_filter: str | None = None,
) -> tuple[list[Path], int]:
    """Walk directory tree and collect analyzable files.
    Returns (files, skipped_count).
    """
    files = []
    skipped = 0

    # Load .doji-ignore patterns
    ignore_root = root if root.is_dir() else root.parent
    ignore_patterns = load_ignore_patterns(ignore_root)

    if root.is_file():
        if should_skip_file(root):
            return [], 1
        lang = detect_language(root)
        if lang and (language_filter is None or lang == language_filter):
            return [root], 0
        return [], 1

    resolved_root = root.resolve()

    for item in sorted(root.rglob("*")):
        # Skip directories
        if item.is_dir():
            continue
        # Skip symlinks (prevents reading files outside project tree)
        if item.is_symlink():
            skipped += 1
            continue
        # Verify resolved path stays under project root (traversal protection)
        try:
            item.resolve().relative_to(resolved_root)
        except ValueError:
            skipped += 1
            continue
        # Check if any parent dir should be skipped
        if any(should_skip_dir(p.name) for p in item.relative_to(root).parents):
            skipped += 1
            continue
        if should_skip_file(item):
            skipped += 1
            continue
        # Check .doji-ignore patterns
        rel = str(item.relative_to(root))
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(item.name, pat) for pat in ignore_patterns):
            skipped += 1
            continue
        lang = detect_language(item)
        if lang is None:
            skipped += 1
            continue
        if language_filter and lang != language_filter:
            skipped += 1
            continue
        files.append(item)

    return files, skipped


def collect_files_with_lang(
    root: Path,
    language_filter: str | None = None,
) -> list[tuple[Path, str]]:
    """Collect analyzable files under root, each paired with its detected language.

    Convenience wrapper around collect_files + detect_language — shared by
    __main__.py (cmd_fix) and mcp_server.py (doji_fix).
    """
    if root.is_file():
        lang = detect_language(root)
        if lang and (language_filter is None or lang == language_filter):
            return [(root, lang)]
        return []

    collected, _ = collect_files(root, language_filter=language_filter)
    result = []
    for fp in collected:
        lang = detect_language(fp)
        if lang:
            result.append((fp, lang))
    return result
