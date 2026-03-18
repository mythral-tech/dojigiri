#!/usr/bin/env python3
"""Head-to-head comparison: Dojigiri vs Semgrep CE.

Runs both scanners on the same repos and produces a delta report.
Uses Semgrep's auto config (p/default ruleset) for fair comparison.

Usage:
    python benchmarks/head_to_head.py                    # All repos
    python benchmarks/head_to_head.py --repo keycloak    # Single repo
    python benchmarks/head_to_head.py --no-clone         # Skip git operations
"""

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

BENCHMARK_DIR = Path(__file__).parent
REPOS_DIR = BENCHMARK_DIR / ".repos"
RESULTS_DIR = BENCHMARK_DIR / "results"

# Repos to compare — must already be cloned via run_benchmark.py
COMPARE_REPOS = {
    "keycloak": {
        "language": "java",
        "paths": ["services/src", "server-spi/src", "server-spi-private/src", "core/src"],
    },
    "paperless-ngx": {
        "paths": ["src"],
    },
    "saleor": {
        "language": "python",
        "paths": ["saleor"],
    },
    "express": {
        "language": "javascript",
        "paths": ["lib"],
    },
    "flask": {
        "language": "python",
        "paths": ["src/flask"],
    },
}


def run_doji(repo_dir: Path, repo_info: dict) -> list[dict]:
    """Run Dojigiri scan."""
    from dojigiri.discovery import collect_files, detect_language
    from dojigiri.detector import analyze_file_static
    from dojigiri.types import FileAnalysis
    from dojigiri.analyzer import _detect_cross_file_taint

    findings = []
    file_analyses = []
    scan_paths = [repo_dir / p for p in repo_info["paths"]]

    for scan_path in scan_paths:
        if not scan_path.exists():
            continue
        collected, _ = collect_files(scan_path, language_filter=repo_info.get("language"))
        for filepath in collected:
            lang = detect_language(filepath)
            if not lang:
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            result = analyze_file_static(str(filepath), content, lang, suppress_noise=False)
            fa = FileAnalysis(
                path=str(filepath), language=lang,
                lines=content.count("\n") + 1, findings=result.findings,
            )
            file_analyses.append(fa)
            for f in result.findings:
                rel = str(filepath.relative_to(repo_dir))
                findings.append({
                    "file": rel, "line": f.line, "rule": f.rule,
                    "severity": f.severity.value, "category": f.category.value,
                })

    # Cross-file
    try:
        cross = _detect_cross_file_taint(file_analyses)
        for cf in cross:
            rel = str(Path(cf.source_file).relative_to(repo_dir))
            findings.append({
                "file": rel, "line": cf.line, "rule": cf.rule,
                "severity": cf.severity.value, "category": cf.category.value,
            })
    except Exception:
        pass

    return findings


def run_semgrep(repo_dir: Path, repo_info: dict) -> list[dict]:
    """Run Semgrep CE with auto config."""
    scan_paths = [str(repo_dir / p) for p in repo_info["paths"] if (repo_dir / p).exists()]
    if not scan_paths:
        return []

    cmd = [
        "semgrep", "scan",
        "--config", "auto",
        "--json",
        "--quiet",
        "--timeout", "30",
        "--max-memory", "2048",
    ]
    cmd.extend(scan_paths)

    try:
        env = {**subprocess.os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=env,
        )
        data = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        print(f"  Semgrep error: {e}")
        return []

    findings = []
    for r in data.get("results", []):
        path = r.get("path", "")
        try:
            rel = str(Path(path).relative_to(repo_dir))
        except (ValueError, TypeError):
            rel = path
        findings.append({
            "file": rel,
            "line": r.get("start", {}).get("line", 0),
            "rule": r.get("check_id", "unknown"),
            "severity": r.get("extra", {}).get("severity", "WARNING").lower(),
            "category": "security",
        })

    return findings


def categorize_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Categorize findings by type."""
    cats = {"security": [], "bug": [], "style": [], "other": []}
    for f in findings:
        cat = f.get("category", "other")
        if cat == "security":
            cats["security"].append(f)
        elif cat in ("bug", "dead_code"):
            cats["bug"].append(f)
        elif cat in ("style", "performance"):
            cats["style"].append(f)
        else:
            cats["other"].append(f)
    return cats


def compare(repo_name: str, doji: list[dict], semgrep: list[dict]) -> dict:
    """Compare findings between the two scanners."""
    # Build fingerprint sets for overlap detection
    doji_fps = {(f["file"], f["line"], f.get("rule", "")) for f in doji}
    sem_fps = {(f["file"], f["line"], f.get("rule", "")) for f in semgrep}

    # File-level overlap (same file + line, regardless of rule name)
    doji_locs = {(f["file"], f["line"]) for f in doji}
    sem_locs = {(f["file"], f["line"]) for f in semgrep}
    loc_overlap = doji_locs & sem_locs

    # Security-only comparison
    doji_sec = [f for f in doji if f.get("category") == "security"]
    sem_sec = semgrep  # Semgrep auto config is mostly security
    doji_sec_locs = {(f["file"], f["line"]) for f in doji_sec}
    sem_sec_locs = {(f["file"], f["line"]) for f in sem_sec}
    sec_overlap = doji_sec_locs & sem_sec_locs

    # Doji-only security findings (our differentiator)
    doji_only_sec = doji_sec_locs - sem_sec_locs
    sem_only_sec = sem_sec_locs - doji_sec_locs

    # Rules unique to each
    doji_rules = Counter(f["rule"] for f in doji)
    sem_rules = Counter(f["rule"] for f in semgrep)

    return {
        "repo": repo_name,
        "doji_total": len(doji),
        "semgrep_total": len(semgrep),
        "doji_security": len(doji_sec),
        "semgrep_security": len(sem_sec),
        "location_overlap": len(loc_overlap),
        "security_overlap": len(sec_overlap),
        "doji_only_security": len(doji_only_sec),
        "semgrep_only_security": len(sem_only_sec),
        "doji_unique_rules": len(doji_rules),
        "semgrep_unique_rules": len(sem_rules),
        "doji_top_rules": doji_rules.most_common(10),
        "semgrep_top_rules": sem_rules.most_common(10),
    }


def print_comparison(comp: dict) -> None:
    """Print a formatted comparison."""
    print(f"\n{'-' * 60}")
    print(f"  {comp['repo'].upper()}")
    print(f"{'-' * 60}")
    print(f"                    {'Doji':>10}  {'Semgrep':>10}")
    print(f"  Total findings:   {comp['doji_total']:>10}  {comp['semgrep_total']:>10}")
    print(f"  Security only:    {comp['doji_security']:>10}  {comp['semgrep_security']:>10}")
    print(f"  Unique rules:     {comp['doji_unique_rules']:>10}  {comp['semgrep_unique_rules']:>10}")
    print(f"  {'-' * 56}")
    print(f"  Location overlap: {comp['location_overlap']:>10}")
    print(f"  Security overlap: {comp['security_overlap']:>10}")
    print(f"  Doji-only (sec):  {comp['doji_only_security']:>10}")
    print(f"  Semgrep-only:     {comp['semgrep_only_security']:>10}")

    print(f"\n  Doji top rules:")
    for rule, count in comp["doji_top_rules"][:7]:
        print(f"    {rule}: {count}")
    print(f"\n  Semgrep top rules:")
    for rule, count in comp["semgrep_top_rules"][:7]:
        rule_short = rule.split(".")[-1] if "." in rule else rule
        print(f"    {rule_short}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Dojigiri vs Semgrep CE head-to-head")
    parser.add_argument("--repo", help="Run specific repo")
    parser.add_argument("--no-clone", action="store_true", help="Skip clone/update")
    args = parser.parse_args()

    repos = COMPARE_REPOS
    if args.repo:
        if args.repo not in repos:
            print(f"Unknown repo: {args.repo}. Available: {', '.join(repos)}")
            sys.exit(1)
        repos = {args.repo: repos[args.repo]}

    all_comps = []
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    for repo_name, repo_info in repos.items():
        repo_dir = REPOS_DIR / repo_name
        if not repo_dir.exists():
            print(f"\n  {repo_name}: not cloned (run run_benchmark.py --repo {repo_name} first)")
            continue

        print(f"\n{'=' * 60}")
        print(f"  {repo_name}")
        print(f"{'=' * 60}")

        # Run Doji
        t0 = time.time()
        doji_findings = run_doji(repo_dir, repo_info)
        doji_time = time.time() - t0
        print(f"  Doji: {len(doji_findings)} findings in {doji_time:.1f}s")

        # Run Semgrep
        t0 = time.time()
        sem_findings = run_semgrep(repo_dir, repo_info)
        sem_time = time.time() - t0
        print(f"  Semgrep: {len(sem_findings)} findings in {sem_time:.1f}s")

        comp = compare(repo_name, doji_findings, sem_findings)
        comp["doji_time"] = round(doji_time, 1)
        comp["semgrep_time"] = round(sem_time, 1)
        all_comps.append(comp)

        print_comparison(comp)

    # Overall summary
    if len(all_comps) > 1:
        print(f"\n{'=' * 60}")
        print(f"  OVERALL SUMMARY")
        print(f"{'=' * 60}")
        tot_doji = sum(c["doji_total"] for c in all_comps)
        tot_sem = sum(c["semgrep_total"] for c in all_comps)
        tot_doji_sec = sum(c["doji_security"] for c in all_comps)
        tot_sem_sec = sum(c["semgrep_security"] for c in all_comps)
        tot_doji_only = sum(c["doji_only_security"] for c in all_comps)
        tot_sem_only = sum(c["semgrep_only_security"] for c in all_comps)
        tot_doji_t = sum(c["doji_time"] for c in all_comps)
        tot_sem_t = sum(c["semgrep_time"] for c in all_comps)
        print(f"                    {'Doji':>10}  {'Semgrep':>10}")
        print(f"  Total findings:   {tot_doji:>10}  {tot_sem:>10}")
        print(f"  Security:         {tot_doji_sec:>10}  {tot_sem_sec:>10}")
        print(f"  Unique (sec):     {tot_doji_only:>10}  {tot_sem_only:>10}")
        print(f"  Total time:       {tot_doji_t:>9.1f}s  {tot_sem_t:>9.1f}s")

    # Save results
    output = RESULTS_DIR / "head_to_head.json"
    output.write_text(json.dumps(all_comps, indent=2), encoding="utf-8")
    print(f"\n  Results saved: {output}")


if __name__ == "__main__":
    main()
