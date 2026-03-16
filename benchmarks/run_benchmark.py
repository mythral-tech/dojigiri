#!/usr/bin/env python3
"""
Automated benchmark runner for Dojigiri.

Clones/updates target repos, runs doji scan, compares against annotations,
outputs precision/recall/F1 per rule, saves results.

Usage:
    python benchmarks/run_benchmark.py                  # Run all repos
    python benchmarks/run_benchmark.py --repo flask      # Run specific repo
    python benchmarks/run_benchmark.py --compare         # Compare against previous best
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

# Add parent to path so we can import dojigiri
sys.path.insert(0, str(Path(__file__).parent.parent))

BENCHMARK_DIR = Path(__file__).parent
ANNOTATIONS_DIR = BENCHMARK_DIR / "annotations"
RESULTS_DIR = BENCHMARK_DIR / "results"
REPOS_DIR = BENCHMARK_DIR / ".repos"

REPOS = {
    "flask": {
        "url": "https://github.com/pallets/flask.git",
        "language": "python",
        "paths": ["src/flask"],
    },
    "fastapi": {
        "url": "https://github.com/fastapi/fastapi.git",
        "language": "python",
        "paths": ["fastapi"],
    },
    "express": {
        "url": "https://github.com/expressjs/express.git",
        "language": "javascript",
        "paths": ["lib"],
    },
}


def clone_or_update(repo_name: str, repo_info: dict) -> Path:
    """Clone or git-pull the target repo."""
    repo_dir = REPOS_DIR / repo_name
    if repo_dir.exists():
        print(f"  Updating {repo_name}...")
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--quiet"],
                       capture_output=True, timeout=60)
    else:
        print(f"  Cloning {repo_name}...")
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", repo_info["url"], str(repo_dir)],
            timeout=120,
        )
    return repo_dir


def scan_repo(repo_dir: Path, repo_info: dict) -> list[dict]:
    """Run doji scan on the repo paths and collect findings."""
    from dojigiri.discovery import collect_files, detect_language
    from dojigiri.detector import analyze_file_static

    all_findings = []
    scan_paths = [repo_dir / p for p in repo_info["paths"]]

    for scan_path in scan_paths:
        if not scan_path.exists():
            print(f"  Warning: {scan_path} not found, skipping")
            continue

        collected, skipped = collect_files(scan_path, language_filter=repo_info.get("language"))
        for filepath in collected:
            lang = detect_language(filepath)
            if not lang:
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            result = analyze_file_static(str(filepath), content, lang)
            for f in result.findings:
                # Normalize file path relative to repo root
                rel_path = str(filepath.relative_to(repo_dir))
                all_findings.append({
                    "file": rel_path,
                    "line": f.line,
                    "rule": f.rule,
                    "severity": f.severity.value,
                    "message": f.message,
                })

    return all_findings


def load_annotations(repo_name: str) -> dict:
    """Load annotations for a repo (known TPs and FPs)."""
    ann_file = ANNOTATIONS_DIR / f"{repo_name}.json"
    if ann_file.exists():
        return json.loads(ann_file.read_text(encoding="utf-8"))
    return {"true_positives": [], "false_positives": [], "notes": ""}


def compute_metrics(findings: list[dict], annotations: dict) -> dict:
    """Compute precision/recall/F1 per rule given annotations."""
    tp_set = {(a["file"], a["line"], a["rule"]) for a in annotations.get("true_positives", [])}
    fp_set = {(a["file"], a["line"], a["rule"]) for a in annotations.get("false_positives", [])}

    rule_counts = Counter(f["rule"] for f in findings)
    rule_tp = Counter()
    rule_fp = Counter()
    rule_unclassified = Counter()

    for f in findings:
        key = (f["file"], f["line"], f["rule"])
        rule = f["rule"]
        if key in tp_set:
            rule_tp[rule] += 1
        elif key in fp_set:
            rule_fp[rule] += 1
        else:
            rule_unclassified[rule] += 1

    per_rule = {}
    for rule in sorted(rule_counts):
        tp = rule_tp[rule]
        fp = rule_fp[rule]
        total = rule_counts[rule]
        unclassified = rule_unclassified[rule]

        # Precision = TP / (TP + FP), only if we have annotations
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        # Recall requires knowing total TPs — can only compute from annotations
        annotated_tp_count = sum(1 for a in annotations.get("true_positives", []) if a["rule"] == rule)
        recall = tp / annotated_tp_count if annotated_tp_count > 0 else None

        f1 = None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)

        per_rule[rule] = {
            "total": total,
            "true_positives": tp,
            "false_positives": fp,
            "unclassified": unclassified,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
        }

    return {
        "total_findings": len(findings),
        "total_tp": sum(rule_tp.values()),
        "total_fp": sum(rule_fp.values()),
        "total_unclassified": sum(rule_unclassified.values()),
        "per_rule": per_rule,
    }


def compare_with_previous(current: dict, repo_name: str) -> list[str]:
    """Compare current results with the most recent previous run. Returns warnings."""
    warnings = []
    result_files = sorted(RESULTS_DIR.glob(f"{repo_name}_*.json"), reverse=True)

    if len(result_files) < 2:
        return warnings

    # Load previous (skip current which was just saved)
    prev_path = result_files[1] if len(result_files) > 1 else None
    if not prev_path:
        return warnings

    try:
        prev = json.loads(prev_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return warnings

    prev_rules = prev.get("metrics", {}).get("per_rule", {})
    curr_rules = current.get("metrics", {}).get("per_rule", {})

    for rule, curr_data in curr_rules.items():
        prev_data = prev_rules.get(rule, {})
        curr_precision = curr_data.get("precision")
        prev_precision = prev_data.get("precision")

        if curr_precision is not None and prev_precision is not None:
            if prev_precision - curr_precision > 0.05:
                warnings.append(
                    f"  REGRESSION: {rule} precision dropped {prev_precision:.1%} -> {curr_precision:.1%}"
                )

        # Check for new FPs in previously-clean files
        curr_fp = curr_data.get("false_positives", 0)
        prev_fp = prev_data.get("false_positives", 0)
        if curr_fp > prev_fp:
            warnings.append(f"  NEW FPs: {rule} has {curr_fp - prev_fp} new false positive(s)")

    return warnings


def run_benchmark(repo_name: str) -> dict:
    """Run full benchmark for a single repo."""
    if repo_name not in REPOS:
        print(f"Error: unknown repo '{repo_name}'. Available: {', '.join(REPOS)}")
        sys.exit(1)

    repo_info = REPOS[repo_name]
    print(f"\n{'='*60}")
    print(f"Benchmarking: {repo_name}")
    print(f"{'='*60}")

    # Clone/update
    repo_dir = clone_or_update(repo_name, repo_info)

    # Scan
    print(f"  Scanning...")
    start = time.monotonic()
    findings = scan_repo(repo_dir, repo_info)
    duration = time.monotonic() - start
    print(f"  Found {len(findings)} findings in {duration:.1f}s")

    # Compute metrics against annotations
    annotations = load_annotations(repo_name)
    metrics = compute_metrics(findings, annotations)

    # Print summary
    print(f"\n  Summary:")
    print(f"    Total findings: {metrics['total_findings']}")
    print(f"    Annotated TPs: {metrics['total_tp']}")
    print(f"    Annotated FPs: {metrics['total_fp']}")
    print(f"    Unclassified: {metrics['total_unclassified']}")

    if metrics["per_rule"]:
        print(f"\n  Per-rule breakdown:")
        for rule, data in sorted(metrics["per_rule"].items(), key=lambda x: -x[1]["total"]):
            parts = [f"total={data['total']}"]
            if data["precision"] is not None:
                parts.append(f"prec={data['precision']:.1%}")
            if data["f1"] is not None:
                parts.append(f"F1={data['f1']:.1%}")
            print(f"    {rule}: {', '.join(parts)}")

    # Save result
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result = {
        "repo": repo_name,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "duration_s": round(duration, 1),
        "findings_count": len(findings),
        "metrics": metrics,
        "findings": findings,
    }
    result_path = RESULTS_DIR / f"{repo_name}_{timestamp}.json"
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\n  Results saved: {result_path.name}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Dojigiri benchmark runner")
    parser.add_argument("--repo", help="Run specific repo (flask/fastapi/express)")
    parser.add_argument("--compare", action="store_true", help="Compare against previous run")
    parser.add_argument("--no-clone", action="store_true", help="Skip clone/update (use existing)")
    args = parser.parse_args()

    repos_to_run = [args.repo] if args.repo else list(REPOS.keys())
    results = {}

    for repo_name in repos_to_run:
        results[repo_name] = run_benchmark(repo_name)

    # Regression check
    if args.compare:
        print(f"\n{'='*60}")
        print("Regression check:")
        print(f"{'='*60}")
        any_warnings = False
        for repo_name, result in results.items():
            warnings = compare_with_previous(result, repo_name)
            if warnings:
                any_warnings = True
                print(f"\n  {repo_name}:")
                for w in warnings:
                    print(w)

        if not any_warnings:
            print("  No regressions detected.")

    # Overall summary
    print(f"\n{'='*60}")
    print("Overall:")
    total_findings = sum(r["findings_count"] for r in results.values())
    print(f"  Total findings across all repos: {total_findings}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
