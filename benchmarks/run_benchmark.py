#!/usr/bin/env python3
"""
Automated benchmark runner for Dojigiri.

Clones/updates target repos, runs doji scan, compares against annotations,
outputs precision/recall/F1 per rule, saves results.

Usage:
    python benchmarks/run_benchmark.py                  # Run all repos
    python benchmarks/run_benchmark.py --repo flask      # Run specific repo
    python benchmarks/run_benchmark.py --compare         # Compare against previous best
    python benchmarks/run_benchmark.py --audit --repo flask  # Audit mode: sample findings for classification
    python benchmarks/run_benchmark.py --ci              # CI mode: exit 1 on precision regression
"""

import argparse
import json
import math
import os
import random
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

# Precision thresholds for CI gates
PRECISION_FLOOR = 0.70       # Rules below this are flagged
REGRESSION_LIMIT = 0.05      # Max precision drop before blocking
OVERALL_PRECISION_FLOOR = 0.75

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
    "airflow": {
        "url": "https://github.com/apache/airflow.git",
        "paths": ["airflow-core/src/airflow"],
    },
    "gitea": {
        "url": "https://github.com/go-gitea/gitea.git",
        "paths": ["models", "modules", "routers", "services"],
    },
    "immich": {
        "url": "https://github.com/immich-app/immich.git",
        "paths": ["server/src", "web/src", "mobile/lib"],
    },
    "keycloak": {
        "url": "https://github.com/keycloak/keycloak.git",
        "paths": ["services/src", "server-spi/src", "server-spi-private/src", "core/src"],
    },
    "open-interpreter": {
        "url": "https://github.com/OpenInterpreter/open-interpreter.git",
        "language": "python",
        "paths": ["interpreter"],
    },
    "paperless-ngx": {
        "url": "https://github.com/paperless-ngx/paperless-ngx.git",
        "paths": ["src"],
    },
    "saleor": {
        "url": "https://github.com/saleor/saleor.git",
        "language": "python",
        "paths": ["saleor"],
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
            timeout=300,
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

            result = analyze_file_static(str(filepath), content, lang, suppress_noise=False)
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


def wilson_ci(tp: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for precision.

    Returns (lower, upper) bounds at the given z-level (default 95%).
    """
    if total == 0:
        return (0.0, 1.0)
    p = tp / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))


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

        # Wilson confidence interval
        ci = None
        if (tp + fp) > 0:
            ci_lo, ci_hi = wilson_ci(tp, tp + fp)
            ci = [round(ci_lo, 3), round(ci_hi, 3)]

        per_rule[rule] = {
            "total": total,
            "true_positives": tp,
            "false_positives": fp,
            "unclassified": unclassified,
            "precision": round(precision, 3) if precision is not None else None,
            "precision_ci": ci,
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
            if prev_precision - curr_precision > REGRESSION_LIMIT:
                warnings.append(
                    f"  REGRESSION: {rule} precision dropped {prev_precision:.1%} -> {curr_precision:.1%}"
                )

        # Check for new FPs in previously-clean files
        curr_fp = curr_data.get("false_positives", 0)
        prev_fp = prev_data.get("false_positives", 0)
        if curr_fp > prev_fp:
            warnings.append(f"  NEW FPs: {rule} has {curr_fp - prev_fp} new false positive(s)")

    return warnings


def check_ci_gates(results: dict[str, dict]) -> bool:
    """Check CI precision gates. Returns True if all gates pass."""
    passed = True

    for repo_name, result in results.items():
        metrics = result.get("metrics", {})
        per_rule = metrics.get("per_rule", {})

        for rule, data in per_rule.items():
            precision = data.get("precision")
            if precision is not None and precision < PRECISION_FLOOR:
                print(f"  GATE FAIL: {repo_name}/{rule} precision {precision:.1%} < {PRECISION_FLOOR:.0%} floor")
                passed = False

    return passed


def audit_sample(findings: list[dict], repo_name: str, repo_dir: Path,
                 sample_per_rule: int = 10, seed: int = 42) -> None:
    """Generate audit samples for manual TP/FP classification.

    Stratified sampling: for each rule, sample up to sample_per_rule findings.
    Outputs findings with source code context for classification.
    """
    rng = random.Random(seed)

    # Group by rule
    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)

    # Sort rules by volume (biggest first)
    sorted_rules = sorted(by_rule.items(), key=lambda x: -len(x[1]))

    audit_entries = []
    total_sampled = 0

    print(f"\n  Audit sampling (seed={seed}, {sample_per_rule}/rule):")
    for rule, rule_findings in sorted_rules:
        n = len(rule_findings)
        sample_n = min(sample_per_rule, n)
        sample = rng.sample(rule_findings, sample_n)
        total_sampled += sample_n

        print(f"    {rule}: {sample_n}/{n} sampled")

        for f in sample:
            # Read source context
            filepath = repo_dir / f["file"]
            context = ""
            if filepath.exists():
                try:
                    lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
                    start = max(0, f["line"] - 3)
                    end = min(len(lines), f["line"] + 2)
                    context_lines = []
                    for i in range(start, end):
                        marker = ">>>" if i == f["line"] - 1 else "   "
                        context_lines.append(f"  {marker} {i+1:4d} | {lines[i]}")
                    context = "\n".join(context_lines)
                except OSError:
                    context = "(could not read file)"

            audit_entries.append({
                "file": f["file"],
                "line": f["line"],
                "rule": rule,
                "severity": f["severity"],
                "message": f["message"],
                "context": context,
                "verdict": "",  # To be filled: TP, FP, or DEBATABLE
                "confidence": "",  # HIGH or LOW
                "reason": "",
            })

    # Save audit file
    ANNOTATIONS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    audit_path = ANNOTATIONS_DIR / f"{repo_name}_audit_{timestamp}.json"
    audit_path.write_text(json.dumps(audit_entries, indent=2), encoding="utf-8")
    print(f"\n  Audit file saved: {audit_path.name}")
    print(f"  Total sampled: {total_sampled} findings across {len(sorted_rules)} rules")
    print(f"  Fill in 'verdict' (TP/FP/DEBATABLE), 'confidence' (HIGH/LOW), and 'reason'")


def import_audit(repo_name: str) -> None:
    """Import completed audit annotations into the repo's annotation file."""
    # Find the most recent audit file
    audit_files = sorted(ANNOTATIONS_DIR.glob(f"{repo_name}_audit_*.json"), reverse=True)
    if not audit_files:
        print(f"  No audit files found for {repo_name}")
        return

    audit_path = audit_files[0]
    print(f"  Importing from: {audit_path.name}")

    entries = json.loads(audit_path.read_text(encoding="utf-8"))
    classified = [e for e in entries if e.get("verdict")]

    if not classified:
        print("  No classified entries found — fill in 'verdict' field first")
        return

    # Load existing annotations
    annotations = load_annotations(repo_name)

    # Merge
    tp_added = 0
    fp_added = 0
    existing_tp = {(a["file"], a["line"], a["rule"]) for a in annotations.get("true_positives", [])}
    existing_fp = {(a["file"], a["line"], a["rule"]) for a in annotations.get("false_positives", [])}

    for e in classified:
        key = (e["file"], e["line"], e["rule"])
        verdict = e["verdict"].upper()
        entry = {
            "file": e["file"],
            "line": e["line"],
            "rule": e["rule"],
            "note": e.get("reason", ""),
            "confidence": e.get("confidence", ""),
        }

        if verdict == "TP" and key not in existing_tp:
            annotations.setdefault("true_positives", []).append(entry)
            existing_tp.add(key)
            tp_added += 1
        elif verdict == "FP" and key not in existing_fp:
            annotations.setdefault("false_positives", []).append(entry)
            existing_fp.add(key)
            fp_added += 1

    # Save
    ann_path = ANNOTATIONS_DIR / f"{repo_name}.json"
    ann_path.write_text(json.dumps(annotations, indent=2), encoding="utf-8")
    print(f"  Imported: {tp_added} TPs, {fp_added} FPs")
    print(f"  Annotations saved: {ann_path.name}")


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
                if data.get("precision_ci"):
                    lo, hi = data["precision_ci"]
                    parts.append(f"CI=[{lo:.1%},{hi:.1%}]")
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
    parser.add_argument("--audit", action="store_true", help="Audit mode: sample findings for classification")
    parser.add_argument("--import-audit", action="store_true", help="Import classified audit entries into annotations")
    parser.add_argument("--ci", action="store_true", help="CI mode: exit 1 on precision regression")
    parser.add_argument("--sample-per-rule", type=int, default=10, help="Findings to sample per rule in audit mode")
    args = parser.parse_args()

    # Import audit mode — standalone
    if args.import_audit:
        if not args.repo:
            print("Error: --import-audit requires --repo")
            sys.exit(1)
        import_audit(args.repo)
        return

    repos_to_run = [args.repo] if args.repo else list(REPOS.keys())
    results = {}

    for repo_name in repos_to_run:
        results[repo_name] = run_benchmark(repo_name)

        # Audit mode: generate samples after scanning
        if args.audit:
            repo_dir = REPOS_DIR / repo_name
            audit_sample(
                results[repo_name]["findings"], repo_name, repo_dir,
                sample_per_rule=args.sample_per_rule,
            )

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

    # CI gate check
    if args.ci:
        print(f"\n{'='*60}")
        print("CI Gate Check:")
        print(f"{'='*60}")
        if not check_ci_gates(results):
            print("  CI GATES FAILED")
            sys.exit(1)
        print("  All gates passed.")

    # Overall summary
    print(f"\n{'='*60}")
    print("Overall:")
    total_findings = sum(r["findings_count"] for r in results.values())
    print(f"  Total findings across all repos: {total_findings}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
