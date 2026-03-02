"""Orchestrator: static → LLM pipeline, file/directory scanning."""

import fnmatch
import sys
import threading
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import (
    Finding, FileAnalysis, ScanReport, Severity,
    LANGUAGE_EXTENSIONS, SKIP_DIRS, SKIP_FILES, MAX_FILE_SIZE,
    load_ignore_patterns,
)
from .detector import analyze_file_static
from .chunker import chunk_file, estimate_tokens
from .llm import analyze_chunk, CostTracker, LLMError
from .storage import file_hash, load_cache, save_cache, save_report


def detect_language(filepath: Path) -> Optional[str]:
    """Detect language from file extension."""
    return LANGUAGE_EXTENSIONS.get(filepath.suffix.lower())


def should_skip_dir(dirname: str) -> bool:
    """Check if directory should be skipped."""
    return dirname in SKIP_DIRS or dirname.startswith(".")


def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped."""
    if filepath.name in SKIP_FILES:
        return True
    if filepath.suffix.lower() not in LANGUAGE_EXTENSIONS:
        return True
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return True
        if filepath.stat().st_size == 0:
            return True
    except OSError:
        return True
    return False


def collect_files(
    root: Path,
    language_filter: Optional[str] = None,
) -> tuple[list[Path], int]:
    """Walk directory tree and collect analyzable files.
    Returns (files, skipped_count).
    """
    files = []
    skipped = 0

    # Load .wizignore patterns
    ignore_root = root if root.is_dir() else root.parent
    ignore_patterns = load_ignore_patterns(ignore_root)

    if root.is_file():
        if should_skip_file(root):
            return [], 1
        lang = detect_language(root)
        if lang and (language_filter is None or lang == language_filter):
            return [root], 0
        return [], 1

    for item in sorted(root.rglob("*")):
        # Skip directories
        if item.is_dir():
            continue
        # Check if any parent dir should be skipped
        if any(should_skip_dir(p.name) for p in item.relative_to(root).parents):
            skipped += 1
            continue
        if should_skip_file(item):
            skipped += 1
            continue
        # Check .wizignore patterns
        rel = str(item.relative_to(root))
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(item.name, pat)
               for pat in ignore_patterns):
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


def _analyze_single_file(
    filepath: Path,
    cache: dict,
    use_cache: bool,
    cache_lock: Optional[threading.Lock] = None,
) -> tuple[Optional[FileAnalysis], Optional[str], bool]:
    """Analyze a single file.

    Returns (FileAnalysis, updated_hash, is_error):
      - (fa, hash, False) on success
      - (None, None, False) on cache hit (unchanged file)
      - (None, None, True) on read error
    """
    fp_str = str(filepath)
    lang = detect_language(filepath)

    # Compute hash once and reuse
    current_hash = file_hash(fp_str)

    # Skip unchanged files (thread-safe cache read)
    if use_cache:
        if cache_lock:
            with cache_lock:
                cached = cache.get(fp_str)
        else:
            cached = cache.get(fp_str)
        if cached == current_hash:
            return None, None, False

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None, True

    findings = analyze_file_static(fp_str, content, lang)
    fa = FileAnalysis(
        path=fp_str,
        language=lang,
        lines=content.count("\n") + 1,
        findings=findings,
        file_hash=current_hash,
    )
    return fa, current_hash, False


def scan_quick(
    root: Path,
    language_filter: Optional[str] = None,
    use_cache: bool = True,
    max_workers: int = 4,
) -> ScanReport:
    """Quick scan — static analysis only (free, instant).
    
    Args:
        root: Path to scan
        language_filter: Optional language to filter by
        use_cache: Whether to use file hash cache
        max_workers: Number of parallel workers (1 = sequential, 4 = default parallel)
    """
    files, skipped = collect_files(root, language_filter)
    cache = load_cache() if use_cache else {}
    analyses = []

    if max_workers == 1:
        # Sequential processing
        for filepath in files:
            fa, updated_hash, is_error = _analyze_single_file(filepath, cache, use_cache)
            if fa:
                analyses.append(fa)
                if use_cache and updated_hash:
                    cache[str(filepath)] = updated_hash
            elif is_error:
                skipped += 1
    else:
        # Parallel processing with thread-safe cache access
        cache_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(_analyze_single_file, filepath, cache, use_cache, cache_lock): filepath
                for filepath in files
            }

            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    fa, updated_hash, is_error = future.result()
                    if fa:
                        analyses.append(fa)
                        if use_cache and updated_hash:
                            with cache_lock:
                                cache[str(filepath)] = updated_hash
                    elif is_error:
                        skipped += 1
                except Exception as e:
                    print(f"Error analyzing {filepath}: {e}", file=sys.stderr)
                    skipped += 1

    if use_cache:
        save_cache(cache)

    total_findings = sum(len(fa.findings) for fa in analyses)
    critical = sum(fa.critical_count for fa in analyses)
    warnings = sum(fa.warning_count for fa in analyses)
    info = sum(fa.info_count for fa in analyses)

    report_obj = ScanReport(
        root=str(root),
        mode="quick",
        files_scanned=len(analyses),
        files_skipped=skipped,
        total_findings=total_findings,
        critical=critical,
        warnings=warnings,
        info=info,
        file_analyses=analyses,
    )

    save_report(report_obj)
    return report_obj


def scan_deep(
    root: Path,
    language_filter: Optional[str] = None,
) -> ScanReport:
    """Deep scan — static + Claude API analysis."""
    files, skipped = collect_files(root, language_filter)
    cost_tracker = CostTracker()
    analyses = []

    for i, filepath in enumerate(files):
        fp_str = str(filepath)
        lang = detect_language(filepath)

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue

        line_count = content.count("\n") + 1
        print(f"  [{i+1}/{len(files)}] {fp_str} ({lang}, {line_count} lines)", flush=True)

        # Static analysis first
        static_findings = analyze_file_static(fp_str, content, lang)

        # LLM analysis
        llm_findings = []
        try:
            chunks = chunk_file(content, fp_str, lang)
            for chunk in chunks:
                chunk_findings = analyze_chunk(chunk, cost_tracker)
                llm_findings.extend(chunk_findings)
                if len(chunks) > 1:
                    sys.stdout.write(".")
                    sys.stdout.flush()
            if len(chunks) > 1:
                print()
        except LLMError as e:
            print(f"    LLM error: {e}", file=sys.stderr)

        # Merge: LLM wins on conflicts (same line + similar rule)
        merged = _merge_findings(static_findings, llm_findings)

        fa = FileAnalysis(
            path=fp_str,
            language=lang,
            lines=line_count,
            findings=merged,
            file_hash=file_hash(fp_str),
        )
        analyses.append(fa)

    total_findings = sum(len(fa.findings) for fa in analyses)
    critical = sum(fa.critical_count for fa in analyses)
    warnings = sum(fa.warning_count for fa in analyses)
    info = sum(fa.info_count for fa in analyses)

    report_obj = ScanReport(
        root=str(root),
        mode="deep",
        files_scanned=len(analyses),
        files_skipped=skipped,
        total_findings=total_findings,
        critical=critical,
        warnings=warnings,
        info=info,
        file_analyses=analyses,
        llm_cost_usd=cost_tracker.total_cost,
    )

    save_report(report_obj)
    return report_obj


def _merge_findings(static: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Merge static and LLM findings, deduplicating. LLM wins on conflicts.
    Uses 5-line buckets for dedup: same category within 5 lines = conflict.
    """
    merged = []
    static_lines_covered = set()

    for f in llm:
        merged.append(f)
        # Mark 5-line bucket as covered (LLM may report same issue nearby)
        bucket = f.line // 5
        static_lines_covered.add((bucket, f.category))

    for f in static:
        bucket = f.line // 5
        if (bucket, f.category) not in static_lines_covered:
            merged.append(f)

    # Sort by severity then line
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    merged.sort(key=lambda f: (severity_order[f.severity], f.line))
    return merged


def filter_report(
    report: ScanReport,
    ignore_rules: Optional[set[str]] = None,
    min_severity: Optional[Severity] = None,
) -> ScanReport:
    """Apply post-scan filters (ignore rules, min severity) to a report."""
    if not ignore_rules and not min_severity:
        return report

    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    min_level = severity_order.get(min_severity, 2) if min_severity else 2

    for fa in report.file_analyses:
        fa.findings = [
            f for f in fa.findings
            if (not ignore_rules or f.rule not in ignore_rules)
            and severity_order[f.severity] <= min_level
        ]

    # Recompute counts
    report.total_findings = sum(len(fa.findings) for fa in report.file_analyses)
    report.critical = sum(fa.critical_count for fa in report.file_analyses)
    report.warnings = sum(fa.warning_count for fa in report.file_analyses)
    report.info = sum(fa.info_count for fa in report.file_analyses)
    return report


def cost_estimate(
    root: Path,
    language_filter: Optional[str] = None,
) -> tuple[int, int, int, float]:
    """Estimate deep scan cost without running it.
    Returns (total_lines, total_files, est_tokens, est_cost_usd).
    """
    files, _ = collect_files(root, language_filter)
    total_lines = 0
    total_chars = 0

    for filepath in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            total_lines += content.count("\n") + 1
            total_chars += len(content)
        except OSError:
            continue

    est_tokens = estimate_tokens("x" * total_chars)
    # Add system prompt overhead per file (~500 tokens each)
    est_tokens += len(files) * 500
    # Estimate output as 25% of input
    est_output = est_tokens // 4

    est_cost = (
        (est_tokens / 1_000_000) * 3.0  # input
        + (est_output / 1_000_000) * 15.0  # output
    )

    return total_lines, len(files), est_tokens, est_cost
