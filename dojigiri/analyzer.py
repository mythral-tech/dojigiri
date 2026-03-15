"""Orchestrator: static analysis → LLM pipeline.

Runs static detection, optionally sends chunks through the LLM for deeper
analysis, and assembles the results. File discovery (collect_files,
detect_language, skip helpers) lives in discovery.py.

Called by: __main__.py (CLI entry), mcp_server.py.
Calls into: discovery.py, config.py, detector.py, chunker.py, llm.py,
            storage.py, semantic/smells.py.
Data in → Data out: Path (file or directory) in → ScanReport out.
"""

from __future__ import annotations  # noqa

import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

from .chunker import chunk_file, estimate_tokens
from .detector import analyze_file_static
from .discovery import collect_files, detect_language
from .storage import file_hash, load_cache, save_cache, save_report
from .types import (
    SEVERITY_ORDER,
    Category,
    Confidence,
    CrossFileFinding,
    FileAnalysis,
    Finding,
    ScanReport,
    Severity,
    Source,
)


def _safe_enum(enum_cls: type[Enum], value: str) -> Enum | None:
    """Safely instantiate an enum, returning None for invalid values."""
    try:
        return enum_cls(value)
    except (ValueError, KeyError):
        return None


def _analyze_single_file(
    filepath: Path,
    cache: dict,
    use_cache: bool,
    cache_lock: threading.Lock | None = None,
    custom_rules: list | None = None,
) -> tuple[FileAnalysis | None, str | None, bool]:
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

    result = analyze_file_static(fp_str, content, lang or "", custom_rules=custom_rules)
    fa = FileAnalysis(
        path=fp_str,
        language=lang or "",
        lines=content.count("\n") + 1,
        findings=result.findings,
        file_hash=current_hash,
        semantics=result.semantics,
    )
    return fa, current_hash, False


def _analyze_file_mp(filepath: Path) -> tuple[FileAnalysis | None, bool]:
    """Analyze a single file in a worker process (no shared state).

    Returns (FileAnalysis, is_error). FileAnalysis.semantics has _tree_root
    stripped for pickling.
    """
    fp_str = str(filepath)
    lang = detect_language(filepath)

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, True

    result = analyze_file_static(fp_str, content, lang or "")
    # Strip unpicklable tree-sitter node before returning across process boundary
    if result.semantics and hasattr(result.semantics, "_tree_root"):
        result.semantics._tree_root = None
    fa = FileAnalysis(
        path=fp_str,
        language=lang or "",
        lines=content.count("\n") + 1,
        findings=result.findings,
        file_hash=file_hash(fp_str),
        semantics=result.semantics,
    )
    return fa, False


def _scan_files_multiprocess(files: list[Path], max_workers: int) -> tuple[list[FileAnalysis], int]:
    """Scan files with ProcessPoolExecutor for true CPU parallelism. Returns (analyses, errors_count)."""
    analyses = []
    errors = 0
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(_analyze_file_mp, fp): fp
            for fp in files
        }
        for future in as_completed(future_to_file):
            filepath = future_to_file[future]
            try:
                fa, is_error = future.result()
                if fa:
                    analyses.append(fa)
                elif is_error:
                    errors += 1
            except (OSError, ValueError, RuntimeError, UnicodeDecodeError) as e:
                logger.warning("Error analyzing %s: %s", filepath, e)
                errors += 1
            except Exception as e:
                # Catch pickling errors and other unexpected failures gracefully
                logger.warning("Worker error on %s: %s", filepath, e)
                errors += 1
    return analyses, errors


def _scan_files_sequential(files: list[Path], cache: dict, use_cache: bool, custom_rules: list | None) -> tuple[list[FileAnalysis], int]:
    """Scan files sequentially. Returns (analyses, errors_count)."""
    analyses = []
    errors = 0
    for filepath in files:
        fa, updated_hash, is_error = _analyze_single_file(filepath, cache, use_cache, custom_rules=custom_rules)
        if fa:
            analyses.append(fa)
            if use_cache and updated_hash:
                cache[str(filepath)] = updated_hash
        elif is_error:
            errors += 1
    return analyses, errors


def _scan_files_parallel(files: list[Path], cache: dict, use_cache: bool, max_workers: int, custom_rules: list | None) -> tuple[list[FileAnalysis], int]:
    """Scan files in parallel with thread-safe cache access. Returns (analyses, errors_count)."""
    analyses = []
    errors = 0
    cache_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(
                _analyze_single_file, fp, cache, use_cache, cache_lock, custom_rules=custom_rules
            ): fp
            for fp in files  # doji:ignore(possibly-uninitialized) — fp is the comprehension loop var
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
                    errors += 1
            except (OSError, ValueError, RuntimeError, UnicodeDecodeError) as e:  # worker errors — lets KeyboardInterrupt/SystemExit propagate
                logger.warning("Error analyzing %s: %s", filepath, e)
                errors += 1
    return analyses, errors


def _detect_semantic_clones(analyses: list[FileAnalysis]) -> list[CrossFileFinding]:
    """Run cross-file semantic clone detection. Returns cross-file findings and mutates intra-file."""
    cross_file_findings: list[CrossFileFinding] = []
    semantics_by_file = {a.path: a.semantics for a in analyses if a.semantics is not None}  # doji:ignore(possibly-uninitialized)
    if len(semantics_by_file) < 2:
        return cross_file_findings

    from .semantic.smells import find_semantic_clone_pairs

    clone_pairs = find_semantic_clone_pairs(semantics_by_file)
    analysis_by_path = {fa.path: fa for fa in analyses}  # doji:ignore(possibly-uninitialized)
    for p in clone_pairs:
        if p.file_a != p.file_b:
            cross_file_findings.append(
                CrossFileFinding(
                    source_file=p.file_a, target_file=p.file_b,
                    line=p.func_a_line, target_line=p.func_b_line,
                    severity=Severity.INFO, category=Category.STYLE,
                    rule="semantic-clone",
                    message=(
                        f"Function '{p.func_a_name}' is semantically similar "
                        f"({p.similarity:.0%}) to '{p.func_b_name}'"
                    ),
                    suggestion="Consider extracting shared logic into a common function",
                )
            )
        else:
            fa = analysis_by_path.get(p.file_a)
            if fa:
                fa.findings.append(
                    Finding(
                        file=p.file_a, line=p.func_a_line,
                        severity=Severity.INFO, category=Category.STYLE,
                        source=Source.AST, rule="semantic-clone",
                        message=(
                            f"Function '{p.func_a_name}' is semantically similar "
                            f"({p.similarity:.0%}) to '{p.func_b_name}' "
                            f"at line {p.func_b_line}"
                        ),
                        suggestion="Consider extracting shared logic into a common function",
                    )
                )
    return cross_file_findings


def _detect_cross_file_taint(analyses: list[FileAnalysis]) -> list[CrossFileFinding]:
    """Run cross-file taint analysis on Python files. Returns findings."""
    python_files: dict[str, str] = {}
    for fa in analyses:
        if fa.language == "python":
            try:
                content = Path(fa.path).read_text(encoding="utf-8", errors="replace")
                python_files[fa.path] = content
            except OSError:
                logger.debug("Could not read %s for cross-file taint analysis", fa.path)
    if len(python_files) < 2:
        return []
    try:
        from .taint_cross import analyze_taint_cross_file
        return list(analyze_taint_cross_file(python_files))
    except Exception as e:
        logger.debug("Cross-file taint analysis skipped: %s", e)
        return []


def scan_quick(
    root: Path,
    language_filter: str | None = None,
    use_cache: bool = True,
    max_workers: int = 4,
    custom_rules: list | None = None,
) -> ScanReport:
    """Quick scan — static analysis only (free, instant).

    Args:
        root: Path to scan
        language_filter: Optional language to filter by
        use_cache: Whether to use file hash cache
        max_workers: Number of parallel workers (1 = sequential, 4 = default parallel)
        custom_rules: Compiled custom rules from compile_custom_rules()
    """
    files, skipped = collect_files(root, language_filter)
    # Quick scan is fast enough that caching adds no value — always re-scan.
    # Cache is only useful for deep scans (where LLM calls cost money).
    cache: dict = {}

    if max_workers == 1:
        analyses, errors = _scan_files_sequential(files, cache, False, custom_rules)
    elif custom_rules:
        # Custom rules can't be pickled across processes — fall back to threads
        analyses, errors = _scan_files_parallel(files, cache, False, max_workers, custom_rules)
    else:
        # Use multiprocessing for true CPU parallelism (bypasses GIL)
        analyses, errors = _scan_files_multiprocess(files, max_workers)
    skipped += errors

    cross_file_findings = _detect_semantic_clones(analyses)
    cross_file_findings.extend(_detect_cross_file_taint(analyses))

    # Clear semantics references to free memory (not needed after this point)
    for fa in analyses:
        fa.semantics = None

    report_obj = ScanReport(
        root=str(root),
        mode="quick",
        files_scanned=len(analyses),
        files_skipped=skipped,
        file_analyses=analyses,
        cross_file_findings=cross_file_findings,
    )

    save_report(report_obj)
    return report_obj


# Reverse mapping: language name → canonical file extension (for temp files)
_LANG_TO_EXT: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
    "swift": ".swift",
    "kotlin": ".kt",
    "pine": ".pine",
    "bash": ".sh",
    "sql": ".sql",
    "html": ".html",
    "css": ".css",
}


def scan_string(
    code: str,
    language: str,
    filename: str = "input",
    custom_rules: list | None = None,
) -> ScanReport:
    """Scan a code string directly — no file on disk required.

    Creates a temporary file internally so the analysis pipeline (which expects
    file paths) works unchanged, then cleans up.

    Args:
        code: Source code to scan.
        language: Language identifier (e.g. "python", "javascript").
        filename: Virtual filename used in findings (default "input").
        custom_rules: Compiled custom rules from compile_custom_rules().

    Returns:
        ScanReport with findings for the single input.
    """
    ext = _LANG_TO_EXT.get(language, ".txt")
    suffix = ext if not filename.endswith(ext) else ""

    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="doji_scan_")
        os.write(fd, code.encode("utf-8"))
        os.close(fd)
        fd = None  # mark as closed

        result = analyze_file_static(tmp_path, code, language, custom_rules=custom_rules)

        # Rewrite file paths in findings to use the virtual filename
        for f in result.findings:
            f.file = filename

        fa = FileAnalysis(
            path=filename,
            language=language,
            lines=code.count("\n") + 1,
            findings=result.findings,
        )
        return ScanReport(
            root=filename,
            mode="string",
            files_scanned=1,
            files_skipped=0,
            file_analyses=[fa],
        )
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:  # doji:ignore(exception-swallowed,empty-exception-handler) — best-effort cleanup
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:  # doji:ignore(exception-swallowed,empty-exception-handler) — best-effort cleanup
                pass


def _reconstruct_cached_analysis(fp_str: str, lang: str, fhash: str, cached_data: dict[str, object]) -> FileAnalysis:
    """Reconstruct a FileAnalysis from cached data."""
    cached_findings = [
        Finding(
            file=f["file"],
            line=f["line"],
            severity=Severity(f["severity"]),
            category=Category(f["category"]),
            source=Source(f["source"]),
            rule=f["rule"],
            message=f["message"],
            suggestion=f.get("suggestion"),
            snippet=f.get("snippet"),
            confidence=_safe_enum(Confidence, f["confidence"]) if f.get("confidence") else None,
        )
        for f in cached_data.get("findings", [])
    ]
    return FileAnalysis(
        path=fp_str,
        language=cached_data.get("language", lang),
        lines=cached_data.get("lines", 0),
        findings=cached_findings,
        file_hash=fhash,
    )


def _collect_file_data(files: list[Path], skipped: int, cache: dict, use_cache: bool, custom_rules: list | None) -> tuple[list[tuple], list[FileAnalysis], int]:
    """Phase 1 of deep scan: static analysis and cache check.

    Returns (file_data, cached_analyses, skipped) where file_data is a list of
    tuples for files needing LLM analysis, and cached_analyses are FileAnalysis
    objects reconstructed from cache hits.
    """
    file_data = []  # list of (fp_str, lang, content, line_count, static_findings, fhash)
    cached_analyses = []  # FileAnalyses loaded from cache

    for filepath in files:
        fp_str = str(filepath)
        lang = detect_language(filepath)

        try:
            fhash = file_hash(fp_str)
        except OSError:
            skipped += 1
            continue

        # Check cache - if file unchanged, skip LLM analysis
        if use_cache and fp_str in cache and isinstance(cache[fp_str], dict):
            cached_data = cache[fp_str]
            if cached_data.get("hash") == fhash:
                cached_analyses.append(
                    _reconstruct_cached_analysis(fp_str, lang, fhash, cached_data)
                )
                continue

        # Cache miss or disabled - need to analyze
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        line_count = content.count("\n") + 1
        static_result = analyze_file_static(fp_str, content, lang or "", custom_rules=custom_rules)
        file_data.append((fp_str, lang, content, line_count, static_result.findings, fhash))

    return file_data, cached_analyses, skipped


def _run_llm_on_chunks(content: str, fp_str: str, lang: str, static_findings: list[Finding], cost_tracker: object,
                       analyze_chunk: object, CostLimitExceeded: type, LLMError: type, print_lock: threading.Lock) -> list[Finding]:
    """Run LLM analysis on file chunks. Returns list of LLM findings."""
    llm_findings = []
    try:
        chunks = chunk_file(content, fp_str, lang)
        for chunk in chunks:
            if cost_tracker.limit_exceeded:
                break
            chunk_findings = analyze_chunk(chunk, cost_tracker, static_findings=static_findings)
            llm_findings.extend(chunk_findings)
            if len(chunks) > 1:
                with print_lock:
                    sys.stdout.write(".")
                    sys.stdout.flush()
        if len(chunks) > 1:
            with print_lock:
                print()
    except CostLimitExceeded:
        with print_lock:
            print(
                f"\n  Cost limit reached (${cost_tracker.total_cost:.4f}). "
                "Remaining files will use static analysis only.",
                flush=True,
            )
    except LLMError as e:
        with print_lock:
            logger.warning("LLM error for %s: %s", fp_str, e)
    return llm_findings


def _store_analysis(fa: FileAnalysis, fp_str: str, fhash: str, lang: str, line_count: int, findings: list[Finding],
                    analyses: list[FileAnalysis], analyses_lock: threading.Lock, cache: dict, cache_write_lock: threading.Lock, use_cache: bool) -> None:
    """Thread-safe storage of a file analysis result + cache update."""
    with analyses_lock:
        analyses.append(fa)
    if use_cache:
        with cache_write_lock:
            cache[fp_str] = {
                "hash": fhash,
                "language": lang,
                "lines": line_count,
                "findings": [f.to_dict() for f in findings],
            }


def _run_llm_enrichment(file_data: list[tuple], cached_analyses: list[FileAnalysis], cache: dict, use_cache: bool, max_workers: int,
                        cost_tracker: object, analyze_chunk: object, CostLimitExceeded: type, LLMError: type) -> tuple[list[FileAnalysis], int]:
    """Phase 2 of deep scan: LLM enrichment with parallel workers.

    Returns (analyses, skipped_clean_count).
    """
    from .config import LLM_SKIP_CLEAN_FILES

    analyses = cached_analyses.copy()
    analyses_lock = threading.Lock()
    cache_write_lock = threading.Lock()
    print_lock = threading.Lock()

    skip_clean = LLM_SKIP_CLEAN_FILES and not os.environ.get("DOJI_LLM_FISH_CLEAN")
    skipped_clean_count = 0

    def _analyze_file_deep(index: int, fp_str: str, lang: str, content: str, line_count: int, static_findings: list[Finding], fhash: str) -> None:
        """Per-file LLM analysis — runs in a thread."""
        nonlocal skipped_clean_count

        if skip_clean and not static_findings:
            with print_lock:
                print(
                    f"  [{index + 1}/{len(file_data)}] {fp_str} ({lang}, {line_count} lines) [clean — skipped LLM]",
                    flush=True,
                )
            fa = FileAnalysis(path=fp_str, language=lang, lines=line_count, findings=[], file_hash=fhash)
            with analyses_lock:
                analyses.append(fa)
                skipped_clean_count += 1
            if use_cache:
                with cache_write_lock:
                    cache[fp_str] = {"hash": fhash, "language": lang, "lines": line_count, "findings": []}
            return

        if cost_tracker.limit_exceeded:
            with print_lock:
                print(f"  [{index + 1}/{len(file_data)}] {fp_str} (static only — cost limit)", flush=True)
            llm_findings = []
        else:
            with print_lock:
                print(f"  [{index + 1}/{len(file_data)}] {fp_str} ({lang}, {line_count} lines)", flush=True)
            llm_findings = _run_llm_on_chunks(
                content, fp_str, lang, static_findings, cost_tracker,
                analyze_chunk, CostLimitExceeded, LLMError, print_lock,
            )

        merged = _merge_findings(static_findings, llm_findings)
        fa = FileAnalysis(path=fp_str, language=lang, lines=line_count, findings=merged, file_hash=fhash)
        _store_analysis(fa, fp_str, fhash, lang, line_count, merged,
                        analyses, analyses_lock, cache, cache_write_lock, use_cache)

    if max_workers == 1 or len(file_data) <= 1:
        for i, (fp_str, lang, content, line_count, static_findings, fhash) in enumerate(file_data):
            _analyze_file_deep(i, fp_str, lang, content, line_count, static_findings, fhash)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, (fp_str, lang, content, line_count, static_findings, fhash) in enumerate(file_data):
                futures.append(
                    executor.submit(_analyze_file_deep, i, fp_str, lang, content, line_count, static_findings, fhash)
                )
            for future in as_completed(futures):
                try:
                    future.result()
                except (OSError, ValueError, RuntimeError, UnicodeDecodeError) as e:  # worker errors — lets KeyboardInterrupt/SystemExit propagate
                    logger.warning("Worker error: %s", e)

    if skipped_clean_count:
        print(
            f"  Skipped LLM for {skipped_clean_count}/{len(file_data)} statically-clean files "
            f"(override with DOJI_LLM_FISH_CLEAN=1)",
            flush=True,
        )

    return analyses, skipped_clean_count


def scan_deep(
    root: Path,
    language_filter: str | None = None,
    use_cache: bool = True,
    max_workers: int = 4,
    custom_rules: list | None = None,
    max_cost: float | None = None,
) -> ScanReport:
    """Deep scan — static + Claude API analysis.

    Runs static analysis first and saves intermediate results,
    then enriches with LLM. If LLM fails partway through, static
    findings are still preserved.

    Args:
        root: Path to scan
        language_filter: Optional language to filter by
        use_cache: Whether to use file hash cache (skips LLM for unchanged files)
        max_workers: Number of parallel workers for LLM calls (default: 4)
        custom_rules: Compiled custom rules from compile_custom_rules()
        max_cost: Maximum LLM cost in USD (None = no limit)
    """
    from .plugin import require_llm_plugin

    llm = require_llm_plugin()
    CostLimitExceeded = llm.CostLimitExceeded
    CostTracker = llm.CostTracker
    LLMError = llm.LLMError
    analyze_chunk = llm.analyze_chunk

    files, skipped = collect_files(root, language_filter)
    cost_tracker = CostTracker(max_cost=max_cost)
    if use_cache:
        full_cache = load_cache()
        root_prefix = str(root.resolve()) + os.sep
        cache = {k: v for k, v in full_cache.items() if k.startswith(root_prefix) or k == "__version__"}
    else:
        cache = {}

    # Phase 1: Static analysis and cache check
    file_data, cached_analyses, skipped = _collect_file_data(
        files, skipped, cache, use_cache, custom_rules,
    )

    # Phase 2: LLM enrichment
    analyses, _clean_count = _run_llm_enrichment(
        file_data, cached_analyses, cache, use_cache, max_workers,
        cost_tracker, analyze_chunk, CostLimitExceeded, LLMError,
    )

    if use_cache:
        save_cache(cache)

    report_obj = ScanReport(
        root=str(root),
        mode="deep",
        files_scanned=len(analyses),
        files_skipped=skipped,
        file_analyses=analyses,
        llm_cost_usd=cost_tracker.total_cost,
        llm_models_used=cost_tracker.models_used,
    )

    save_report(report_obj)
    return report_obj


def _merge_findings(static: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Merge static and LLM findings.

    - LLM findings always included.
    - Static findings included unless an LLM finding covers the same area
      (5-line bucket + same category) — LLM wins on those conflicts since
      it has richer context.
    - Final dedup on exact (file, line, rule) to remove true duplicates.
    """
    merged = []
    # Track LLM coverage using 5-line buckets (only for LLM-vs-static merge)
    llm_buckets = set()

    for f in llm:
        merged.append(f)
        bucket = f.line // 5
        llm_buckets.add((bucket, f.category))

    for f in static:
        bucket = f.line // 5
        if (bucket, f.category) not in llm_buckets:
            merged.append(f)

    # Exact dedup: (file, line, rule)
    seen = set()
    unique = []
    for f in merged:
        key = (f.file, f.line, f.rule)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort by severity then line
    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line))
    return unique


def filter_report(
    report: ScanReport,
    ignore_rules: set[str] | None = None,
    min_severity: Severity | None = None,
    min_confidence: Confidence | None = None,
) -> ScanReport:
    """Apply post-scan filters (ignore rules, min severity, min confidence) to a report."""
    if not ignore_rules and not min_severity and not min_confidence:
        return report

    confidence_order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    min_level = SEVERITY_ORDER.get(min_severity, 2) if min_severity else 2
    min_conf = confidence_order.get(min_confidence, 2) if min_confidence else 2

    def _keep(f: Finding) -> bool:
        if ignore_rules and f.rule in ignore_rules:
            return False
        if SEVERITY_ORDER[f.severity] > min_level:
            return False
        # Confidence filter only applies to LLM findings (static/AST have no confidence)
        if f.confidence is not None and confidence_order[f.confidence] > min_conf:
            return False
        return True

    for fa in report.file_analyses:
        fa.findings = [f for f in fa.findings if _keep(f)]

    return report


def _normalize_path(path_str: str, root: str | None = None) -> str:
    """Normalize a path for baseline comparison.

    Converts absolute paths to relative (using root) and normalizes separators.
    """
    import os

    p = os.path.normpath(path_str)
    if root and os.path.isabs(p):
        try:
            p = os.path.relpath(p, os.path.normpath(root))
        except ValueError as e:
            logger.debug("Failed to compute relative path: %s", e)
    return p


def diff_reports(
    report: ScanReport,
    baseline_dict: dict,
) -> ScanReport:
    """Filter report to show only NEW findings not in baseline.

    Uses 5-line bucket matching: findings on similar lines (±5) with the same
    rule are considered the same issue.

    Args:
        report: Current scan report
        baseline_dict: Baseline report as dict (from load_baseline_report)

    Returns:
        Modified report containing only new findings
    """
    baseline_root = baseline_dict.get("root")

    # Build set of baseline finding signatures: (normalized_file, line_bucket, rule)
    baseline_signatures = set()
    for file_data in baseline_dict.get("files", []):
        file_path = _normalize_path(file_data.get("path", ""), baseline_root)
        for finding in file_data.get("findings", []):
            line = finding.get("line", 0)
            rule = finding.get("rule", "")
            bucket = line // 5
            baseline_signatures.add((file_path, bucket, rule))

    # Filter out findings that exist in baseline
    scan_root = report.root
    for fa in report.file_analyses:
        norm_path = _normalize_path(fa.path, scan_root)
        fa.findings = [f for f in fa.findings if (norm_path, f.line // 5, f.rule) not in baseline_signatures]

    return report


def cost_estimate(
    root: Path,
    language_filter: str | None = None,
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

    # Use tiered pricing from the backend's pricing table (avoids hardcoded prices)
    from .llm_backend import TIER_SCAN, get_tier_pricing

    input_cost_per_m, output_cost_per_m = get_tier_pricing(tier=TIER_SCAN)

    est_cost = (est_tokens / 1_000_000) * input_cost_per_m + (est_output / 1_000_000) * output_cost_per_m

    return total_lines, len(files), est_tokens, est_cost


# ─── Git diff scanning ───────────────────────────────────────────────

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git_run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    """Run a git command with safe UTF-8 encoding (avoids Windows cp1252 crashes)."""
    # Validate cwd is a real local directory (prevent UNC path injection)
    cwd_path = Path(cwd).resolve()
    if not cwd_path.is_dir():
        raise OSError(f"Invalid working directory: {cwd}")
    result = subprocess.run(  # doji:ignore(taint-flow)
        args,
        capture_output=True,
        cwd=str(cwd_path),
        encoding="utf-8",
        errors="replace",
    )
    # Ensure stdout/stderr are never None
    if result.stdout is None:
        result.stdout = ""
    if result.stderr is None:
        result.stderr = ""
    return result


def _find_git_root(path: Path) -> Path | None:
    """Find the git root for a path, or None."""
    try:
        result = _git_run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path if path.is_dir() else path.parent),
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())  # doji:ignore(llm-output-to-file) git stdout, not LLM output
    except (OSError, FileNotFoundError) as e:
        logger.debug("Failed to find git root: %s", e)
    return None


def _resolve_base_ref(git_root: Path, base: str | None = None) -> str | None:
    """Resolve the base ref to diff against. Tries base arg, then main, then master."""
    candidates = [base] if base else ["main", "master"]
    for ref in candidates:
        # Validate ref format to prevent flag injection into git commands
        if ref and (ref.startswith("-") or not re.match(r"^[a-zA-Z0-9._/~^@{}\-]+$", ref)):
            logger.warning("Invalid git ref rejected: %s", ref)
            return None
        result = _git_run(
            ["git", "rev-parse", "--verify", ref],
            cwd=str(git_root),
        )
        if result.returncode == 0:
            return ref
    return None


def get_changed_files(git_root: Path, base_ref: str) -> list[Path]:
    """Get list of files changed vs base ref (added, modified, renamed).

    Uses three-dot syntax for branch comparisons, two-dot for HEAD/uncommitted.
    Also picks up untracked files when diffing against HEAD.
    """
    # Try three-dot (branch comparison: changes since divergence)
    result = _git_run(
        ["git", "diff", "--name-only", "--diff-filter=AMR", f"{base_ref}...HEAD"],
        cwd=str(git_root),
    )
    if result.returncode != 0 or not result.stdout.strip():
        # Fallback: two-dot diff (includes uncommitted/staged changes)
        result = _git_run(
            ["git", "diff", "--name-only", "--diff-filter=AMR", base_ref],
            cwd=str(git_root),
        )

    files = set()
    if result.returncode == 0:
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if line:
                files.add(git_root / line)

    # Also include untracked files (new files not yet committed)
    result_untracked = _git_run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=str(git_root),
    )
    if result_untracked.returncode == 0:
        for line in result_untracked.stdout.strip().splitlines():
            line = line.strip()
            if line:
                files.add(git_root / line)

    return list(files)


def get_changed_lines(git_root: Path, base_ref: str, filepath: Path) -> set[int]:
    """Get the set of changed line numbers in a file vs base ref.

    Parses unified diff hunks to extract added/modified line ranges.
    """
    try:
        rel = filepath.relative_to(git_root)
    except ValueError:
        return set()

    result = _git_run(
        ["git", "diff", "-U0", f"{base_ref}...HEAD", "--", str(rel)],
        cwd=str(git_root),
    )
    if result.returncode != 0 or not result.stdout.strip():
        # Fallback: two-dot diff for uncommitted changes
        result = _git_run(
            ["git", "diff", "-U0", base_ref, "--", str(rel)],
            cwd=str(git_root),
        )
    if result.returncode != 0 or not result.stdout.strip():
        # Untracked file — all lines are "changed"
        return set()

    changed = set()
    for line in result.stdout.splitlines():
        m = _HUNK_RE.match(line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count == 0:
                # Pure deletion — include the adjacent line for context
                changed.add(start)
            else:
                for i in range(start, start + count):
                    changed.add(i)
    return changed


def _should_skip_diff_file(
    filepath: Path, git_root: Path, ignore_patterns: list[str],
    language_filter: str | None,
) -> tuple[bool, str | None]:
    """Check if a file should be skipped in diff scan. Returns (should_skip, lang)."""
    import fnmatch as _fnmatch

    if not filepath.is_file():
        return True, None

    if ignore_patterns:
        try:
            rel = str(filepath.relative_to(git_root))
        except ValueError:
            rel = filepath.name
        if any(_fnmatch.fnmatch(rel, pat) or _fnmatch.fnmatch(filepath.name, pat) for pat in ignore_patterns):
            return True, None

    lang = detect_language(filepath)
    if not lang:
        return True, None
    if language_filter and lang != language_filter:
        return True, None

    return False, lang


def _filter_findings_to_changed_lines(findings: list[Finding], changed_lines: set[int]) -> list[Finding]:
    """Filter findings to only those on changed lines (+-2 tolerance). Empty set keeps all."""
    if not changed_lines:
        return findings
    return [f for f in findings if any(abs(f.line - cl) <= 2 for cl in changed_lines)]


def _analyze_diff_file(
    filepath: Path, git_root: Path, ref: str, lang: str, custom_rules: list | None,
) -> FileAnalysis | None:
    """Analyze a single file for diff scan. Returns FileAnalysis or None."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    changed_lines = get_changed_lines(git_root, ref, filepath)
    findings = analyze_file_static(str(filepath), content, lang, custom_rules=custom_rules).findings
    findings = _filter_findings_to_changed_lines(findings, changed_lines)

    if not findings:
        return None

    try:
        rel_path = str(filepath.relative_to(git_root))
    except ValueError:
        rel_path = str(filepath)
    return FileAnalysis(
        path=rel_path, language=lang,
        lines=content.count("\n") + 1, findings=findings,
    )


def scan_diff(
    root: Path,
    base_ref: str | None = None,
    language_filter: str | None = None,
    custom_rules: list | None = None,
) -> tuple[ScanReport, str]:
    """Scan only files changed vs a git base ref, filtering to changed lines.

    Returns (ScanReport, resolved_base_ref).
    """
    git_root = _find_git_root(root)
    if not git_root:
        raise ValueError("Not a git repository (or git is not installed). --diff requires git on PATH.")

    ref = _resolve_base_ref(git_root, base_ref)
    if not ref:
        target = base_ref or "main/master"
        raise ValueError(f"Could not resolve git ref '{target}'")

    changed_files = get_changed_files(git_root, ref)
    if not changed_files:
        return ScanReport(
            root=str(root),
            mode="diff",
            files_scanned=0,
            files_skipped=0,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        ), ref

    from .config import load_ignore_patterns
    ignore_patterns = load_ignore_patterns(git_root)

    file_analyses = []
    skipped = 0

    for filepath in changed_files:
        skip, lang = _should_skip_diff_file(filepath, git_root, ignore_patterns, language_filter)
        if skip:
            skipped += 1
            continue

        fa = _analyze_diff_file(filepath, git_root, ref, lang, custom_rules)
        if fa is None:
            # Could be OSError (count as skip) or no findings (not a skip)
            if not filepath.is_file():
                skipped += 1
            continue
        file_analyses.append(fa)

    report = ScanReport(
        root=str(root),
        mode="diff",
        files_scanned=len(changed_files) - skipped,
        files_skipped=skipped,
        file_analyses=file_analyses,
        timestamp=datetime.now().isoformat(timespec="seconds"),
    )

    return report, ref
