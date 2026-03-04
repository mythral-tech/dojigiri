"""Orchestrator: static → LLM pipeline, file/directory scanning."""

import fnmatch
import logging
import re
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

from .config import (
    Finding, FileAnalysis, ScanReport, Severity, Confidence, Category, Source,
    LANGUAGE_EXTENSIONS, SKIP_DIRS, SKIP_FILES, MAX_FILE_SIZE,
    SENSITIVE_FILE_PATTERNS,
    load_ignore_patterns,
)
from .detector import analyze_file_static
from .chunker import chunk_file, estimate_tokens
from .llm import analyze_chunk, CostTracker, LLMError
from .storage import file_hash, load_cache, save_cache, save_report


def _safe_enum(enum_cls, value):
    """Safely instantiate an enum, returning None for invalid values."""
    try:
        return enum_cls(value)
    except (ValueError, KeyError):
        return None


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
    # Block sensitive files (secrets, keys, credentials)
    if any(fnmatch.fnmatch(filepath.name, pat) for pat in SENSITIVE_FILE_PATTERNS):
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
    custom_rules=None,
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

    findings = analyze_file_static(fp_str, content, lang or "", custom_rules=custom_rules)
    fa = FileAnalysis(
        path=fp_str,
        language=lang or "",
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
    custom_rules=None,
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
    cache = load_cache() if use_cache else {}
    analyses = []

    if max_workers == 1:
        # Sequential processing
        for filepath in files:
            fa, updated_hash, is_error = _analyze_single_file(
                filepath, cache, use_cache, custom_rules=custom_rules)
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
                executor.submit(_analyze_single_file, filepath, cache, use_cache, cache_lock,
                                custom_rules=custom_rules): filepath
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
                except Exception as e:  # future.result() — any worker error must be caught
                    logger.warning("Error analyzing %s: %s", filepath, e)
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
    use_cache: bool = True,
    max_workers: int = 4,
    custom_rules=None,
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
    """
    files, skipped = collect_files(root, language_filter)
    cost_tracker = CostTracker()
    cache = load_cache() if use_cache else {}

    # Phase 1: Static analysis and cache check
    file_data = []  # list of (fp_str, lang, content, line_count, static_findings, fhash, from_cache)
    cached_analyses = []  # FileAnalyses loaded from cache
    
    for filepath in files:
        fp_str = str(filepath)
        lang = detect_language(filepath)
        
        # Compute hash first
        try:
            fhash = file_hash(fp_str)
        except OSError:
            skipped += 1
            continue
        
        # Check cache - if file unchanged, skip LLM analysis
        if use_cache and fp_str in cache and isinstance(cache[fp_str], dict):
            cached_data = cache[fp_str]
            if cached_data.get("hash") == fhash:
                # Cache hit - reconstruct FileAnalysis from cached data
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
                fa = FileAnalysis(
                    path=fp_str,
                    language=cached_data.get("language", lang),
                    lines=cached_data.get("lines", 0),
                    findings=cached_findings,
                    file_hash=fhash,
                )
                cached_analyses.append(fa)
                continue
        
        # Cache miss or disabled - need to analyze
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        line_count = content.count("\n") + 1
        static_findings = analyze_file_static(fp_str, content, lang or "", custom_rules=custom_rules)
        file_data.append((fp_str, lang, content, line_count, static_findings, fhash))

    # Phase 2: LLM enrichment with parallel workers
    analyses = cached_analyses.copy()  # Start with cached results
    analyses_lock = threading.Lock()
    cache_write_lock = threading.Lock()
    print_lock = threading.Lock()

    def _analyze_file_deep(index, fp_str, lang, content, line_count, static_findings, fhash):
        """Per-file LLM analysis — runs in a thread."""
        with print_lock:
            print(f"  [{index+1}/{len(file_data)}] {fp_str} ({lang}, {line_count} lines)", flush=True)

        llm_findings = []
        try:
            chunks = chunk_file(content, fp_str, lang)
            for chunk in chunks:
                chunk_findings = analyze_chunk(chunk, cost_tracker)
                llm_findings.extend(chunk_findings)
                if len(chunks) > 1:
                    with print_lock:
                        sys.stdout.write(".")
                        sys.stdout.flush()
            if len(chunks) > 1:
                with print_lock:
                    print()
        except LLMError as e:
            with print_lock:
                logger.warning("LLM error for %s: %s", fp_str, e)

        merged = _merge_findings(static_findings, llm_findings)

        fa = FileAnalysis(
            path=fp_str,
            language=lang,
            lines=line_count,
            findings=merged,
            file_hash=fhash,
        )
        with analyses_lock:
            analyses.append(fa)

        if use_cache:
            with cache_write_lock:
                cache[fp_str] = {
                    "hash": fhash,
                    "language": lang,
                    "lines": line_count,
                    "findings": [f.to_dict() for f in merged],
                }

    if max_workers == 1 or len(file_data) <= 1:
        for i, (fp_str, lang, content, line_count, static_findings, fhash) in enumerate(file_data):
            _analyze_file_deep(i, fp_str, lang, content, line_count, static_findings, fhash)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, (fp_str, lang, content, line_count, static_findings, fhash) in enumerate(file_data):
                futures.append(executor.submit(
                    _analyze_file_deep, i, fp_str, lang, content, line_count, static_findings, fhash))
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:  # future.result() — any worker error must be caught
                    logger.warning("Worker error: %s", e)

    total_findings = sum(len(fa.findings) for fa in analyses)
    critical = sum(fa.critical_count for fa in analyses)
    warnings = sum(fa.warning_count for fa in analyses)
    info = sum(fa.info_count for fa in analyses)

    # Save cache with updated analyses
    if use_cache:
        save_cache(cache)
    
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
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    unique.sort(key=lambda f: (severity_order[f.severity], f.line))
    return unique


def filter_report(
    report: ScanReport,
    ignore_rules: Optional[set[str]] = None,
    min_severity: Optional[Severity] = None,
    min_confidence: Optional[Confidence] = None,
) -> ScanReport:
    """Apply post-scan filters (ignore rules, min severity, min confidence) to a report."""
    if not ignore_rules and not min_severity and not min_confidence:
        return report

    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    confidence_order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    min_level = severity_order.get(min_severity, 2) if min_severity else 2
    min_conf = confidence_order.get(min_confidence, 2) if min_confidence else 2

    def _keep(f: Finding) -> bool:
        if ignore_rules and f.rule in ignore_rules:
            return False
        if severity_order[f.severity] > min_level:
            return False
        # Confidence filter only applies to LLM findings (static/AST have no confidence)
        if f.confidence is not None and confidence_order[f.confidence] > min_conf:
            return False
        return True

    for fa in report.file_analyses:
        fa.findings = [f for f in fa.findings if _keep(f)]

    # Recompute counts
    report.total_findings = sum(len(fa.findings) for fa in report.file_analyses)
    report.critical = sum(fa.critical_count for fa in report.file_analyses)
    report.warnings = sum(fa.warning_count for fa in report.file_analyses)
    report.info = sum(fa.info_count for fa in report.file_analyses)
    return report


def _normalize_path(path_str: str, root: Optional[str] = None) -> str:
    """Normalize a path for baseline comparison.

    Converts absolute paths to relative (using root) and normalizes separators.
    """
    import os
    p = os.path.normpath(path_str)
    if root and os.path.isabs(p):
        try:
            p = os.path.relpath(p, os.path.normpath(root))
        except ValueError:
            pass  # Different drive on Windows
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
        fa.findings = [
            f for f in fa.findings
            if (norm_path, f.line // 5, f.rule) not in baseline_signatures
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


# ─── Git diff scanning ───────────────────────────────────────────────

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git_run(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    """Run a git command with safe UTF-8 encoding (avoids Windows cp1252 crashes)."""
    result = subprocess.run(
        args, capture_output=True, cwd=cwd,
        encoding="utf-8", errors="replace",
    )
    # Ensure stdout/stderr are never None
    if result.stdout is None:
        result.stdout = ""
    if result.stderr is None:
        result.stderr = ""
    return result


def _find_git_root(path: Path) -> Optional[Path]:
    """Find the git root for a path, or None."""
    try:
        result = _git_run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path if path.is_dir() else path.parent),
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except (OSError, FileNotFoundError):
        pass
    return None


def _resolve_base_ref(git_root: Path, base: Optional[str] = None) -> Optional[str]:
    """Resolve the base ref to diff against. Tries base arg, then main, then master."""
    candidates = [base] if base else ["main", "master"]
    for ref in candidates:
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


def scan_diff(
    root: Path,
    base_ref: Optional[str] = None,
    language_filter: Optional[str] = None,
    custom_rules=None,
) -> tuple[ScanReport, str]:
    """Scan only files changed vs a git base ref, filtering to changed lines.

    Returns (ScanReport, resolved_base_ref).
    """
    git_root = _find_git_root(root)
    if not git_root:
        raise ValueError(
            "Not a git repository (or git is not installed). "
            "--diff requires git on PATH."
        )

    ref = _resolve_base_ref(git_root, base_ref)
    if not ref:
        target = base_ref or "main/master"
        raise ValueError(f"Could not resolve git ref '{target}'")

    changed_files = get_changed_files(git_root, ref)
    if not changed_files:
        return ScanReport(
            root=str(root), mode="diff", files_scanned=0, files_skipped=0,
            total_findings=0, critical=0, warnings=0, info=0,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        ), ref

    file_analyses = []
    skipped = 0

    for filepath in changed_files:
        if not filepath.is_file():
            skipped += 1
            continue

        lang = detect_language(filepath)
        if not lang:
            skipped += 1
            continue
        if language_filter and lang != language_filter:
            skipped += 1
            continue

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue

        changed_lines = get_changed_lines(git_root, ref, filepath)

        findings = analyze_file_static(str(filepath), content, lang, custom_rules=custom_rules)

        # Filter to only findings on changed lines (±2 line tolerance)
        # Empty changed_lines means untracked file — keep all findings
        if changed_lines:
            filtered = []
            for f in findings:
                if any(abs(f.line - cl) <= 2 for cl in changed_lines):
                    filtered.append(f)
            findings = filtered

        if findings:
            lines_count = content.count("\n") + 1
            try:
                rel_path = str(filepath.relative_to(git_root))
            except ValueError:
                rel_path = str(filepath)
            file_analyses.append(FileAnalysis(
                path=rel_path, language=lang,
                lines=lines_count, findings=findings,
            ))

    total = sum(len(fa.findings) for fa in file_analyses)
    crit = sum(fa.critical_count for fa in file_analyses)
    warn = sum(fa.warning_count for fa in file_analyses)
    info = sum(fa.info_count for fa in file_analyses)

    report = ScanReport(
        root=str(root), mode="diff",
        files_scanned=len(changed_files) - skipped,
        files_skipped=skipped,
        total_findings=total, critical=crit, warnings=warn, info=info,
        file_analyses=file_analyses,
        timestamp=datetime.now().isoformat(timespec="seconds"),
    )

    return report, ref
