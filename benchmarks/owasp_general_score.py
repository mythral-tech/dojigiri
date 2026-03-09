#!/usr/bin/env python3
"""Compute the general-only OWASP Benchmark score.

Re-scans all 2,740 OWASP Benchmark test files using only the general-purpose
FP filter (explicit sanitizer detection via ESAPI/Spring/Apache Commons) and
scores the results against the expected results CSV.

This answers: "What would Dojigiri score WITHOUT the 8 benchmark-specific
filters in java_sanitize.py?"

Usage:
    python owasp_general_score.py [--benchmark-dir PATH] [--expected PATH]

Requires: OWASP Benchmark source files on disk (not included in repo).
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

# Add parent dir to path so we can import dojigiri
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dojigiri.detector import run_regex_checks
from dojigiri.java_sanitize import filter_java_fps
from benchmarks.owasp_scorecard import (
    CWE_TO_DOJI_RULES,
    OWASP_CATEGORY_NAMES,
    load_expected,
    score,
    compute_overall,
    print_table,
    generate_markdown,
)


def scan_general_only(benchmark_dir: str) -> dict[str, set[str]]:
    """Scan all OWASP Benchmark Java files with general-only filters.

    Returns {test_name: set_of_security_rules_fired}.
    """
    test_dir = Path(benchmark_dir) / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    if not test_dir.exists():
        print(f"ERROR: Test directory not found: {test_dir}", file=sys.stderr)
        sys.exit(1)

    java_files = sorted(test_dir.glob("BenchmarkTest*.java"))
    print(f"Scanning {len(java_files)} test files with general-only filters...")

    detections: dict[str, set[str]] = defaultdict(set)
    t0 = time.perf_counter()

    for i, java_file in enumerate(java_files):
        if (i + 1) % 500 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  {i+1}/{len(java_files)} ({elapsed:.1f}s)")

        content = java_file.read_text(encoding="utf-8", errors="replace")
        filepath = str(java_file)
        test_name = java_file.stem  # e.g., BenchmarkTest00001

        # Run regex checks (same as full scan)
        findings = run_regex_checks(content, filepath, "java")

        # Apply ONLY general-purpose filters (skip benchmark-specific ones)
        findings = filter_java_fps(findings, content, skip_benchmark_filters=True)

        # Collect security findings
        for f in findings:
            if f.category.value == "security":
                detections[test_name].add(f.rule)

    elapsed = time.perf_counter() - t0
    print(f"  Done in {elapsed:.1f}s — {len(detections)} files with security findings")
    return dict(detections)


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark general-only score")
    parser.add_argument(
        "--benchmark-dir",
        default=str(Path(__file__).resolve().parent.parent.parent.parent / "temp" / "owasp-benchmark"),
        help="Path to OWASP Benchmark clone",
    )
    parser.add_argument(
        "--expected",
        default=None,
        help="Path to expectedresults CSV (default: <benchmark-dir>/expectedresults-1.2.csv)",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parent / "owasp-general-scorecard-results.md"),
        help="Path for Markdown output",
    )
    parser.add_argument(
        "--json-output",
        default=str(Path(__file__).resolve().parent / "owasp_general_results.json"),
        help="Path for JSON output of general-only scan findings",
    )
    args = parser.parse_args()

    expected_path = args.expected or str(Path(args.benchmark_dir) / "expectedresults-1.2.csv")

    print(f"Loading expected results from: {expected_path}")
    expected = load_expected(expected_path)
    print(f"  {len(expected)} test cases")

    # Scan with general-only filters
    detections = scan_general_only(args.benchmark_dir)

    # Score
    print("\nScoring (general-only)...\n")
    results = score(expected, detections)
    overall = compute_overall(results)

    print_table(results)
    print()
    print("Macro-average (OWASP standard, general-only):")
    print(f"  TPR: {overall['macro_TPR']:.1%}  |  FPR: {overall['macro_FPR']:.1%}  |  Youden: {overall['macro_Youden']:+.1%}")
    print()

    # Also load and display with-filters results for comparison
    full_results_path = Path(__file__).resolve().parent / "doji_owasp_results.json"
    if full_results_path.exists():
        from benchmarks.owasp_scorecard import load_dojigiri
        full_detections = load_dojigiri(str(full_results_path))
        full_results = score(expected, full_detections)
        full_overall = compute_overall(full_results)

        print("=== COMPARISON ===")
        print(f"  With benchmark filters:  Youden {full_overall['macro_Youden']:+.1%}  (TPR {full_overall['macro_TPR']:.1%}, FPR {full_overall['macro_FPR']:.1%})")
        print(f"  General-only:            Youden {overall['macro_Youden']:+.1%}  (TPR {overall['macro_TPR']:.1%}, FPR {overall['macro_FPR']:.1%})")
        delta = full_overall['macro_Youden'] - overall['macro_Youden']
        print(f"  Benchmark filters add:   {delta:+.1%} Youden points")

    # Generate markdown
    generate_markdown(results, overall, args.output)
    print(f"\nResults saved to: {args.output}")

    # Save detection data as JSON for future use
    json_data = {test: sorted(rules) for test, rules in detections.items()}
    with open(args.json_output, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"Detection data saved to: {args.json_output}")


if __name__ == "__main__":
    main()
