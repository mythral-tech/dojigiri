#!/usr/bin/env python3
"""
OWASP Benchmark v1.2 Scorecard for Dojigiri.

Computes True Positive Rate (TPR), False Positive Rate (FPR), and
Youden index per CWE category, matching the official OWASP Benchmark
scoring methodology.

Usage:
    python owasp_scorecard.py [--results PATH] [--expected PATH] [--output PATH]
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Map OWASP Benchmark CWE numbers to Dojigiri rule names.
# Only categories where Dojigiri has a matching rule are scored;
# categories with no corresponding rule are reported as "not covered".
CWE_TO_DOJI_RULES = {
    22:  ["path-traversal", "java-path-traversal"],     # pathtraver
    78:  ["java-cmdi", "os-system", "shell-true"],    # cmdi
    79:  ["java-xss", "innerhtml"],                   # xss
    89:  ["sql-injection-execute", "sql-injection-format", "sql-injection-fstring", "sql-injection-concat", "sql-injection-percent", "sql-injection-raw", "java-sql-injection"],  # sqli
    90:  ["java-ldap-injection"],                      # ldapi
    327: ["java-weak-crypto", "insecure-crypto"],      # crypto
    328: ["java-weak-hash", "weak-hash"],              # hash
    330: ["java-weak-random", "weak-random"],           # weakrand
    501: ["java-trust-boundary"],                       # trustbound
    614: ["java-insecure-cookie"],                      # securecookie
    643: ["java-xpath-injection"],                      # xpathi
}

OWASP_CATEGORY_NAMES = {
    22:  "Path Traversal",
    78:  "Command Injection",
    79:  "Cross-Site Scripting",
    89:  "SQL Injection",
    90:  "LDAP Injection",
    327: "Weak Cryptography",
    328: "Weak Hashing",
    330: "Weak Randomness",
    501: "Trust Boundary",
    614: "Insecure Cookie",
    643: "XPath Injection",
}


def load_expected(path: str) -> dict:
    """Load expectedresults CSV → {test_name: {category, real_vuln, cwe}}."""
    expected = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            name, category, real_vuln, cwe = parts[0], parts[1], parts[2], int(parts[3])
            expected[name] = {
                "category": category,
                "real_vuln": real_vuln == "true",
                "cwe": cwe,
            }
    return expected


def load_dojigiri(path: str) -> dict:
    """Load Dojigiri JSON → {test_name: set_of_rules_fired}."""
    with open(path, "r") as f:
        data = json.load(f)

    detections = defaultdict(set)
    for file_entry in data["files"]:
        m = re.search(r"BenchmarkTest(\d+)", file_entry["path"])
        if not m:
            continue
        test_name = f"BenchmarkTest{m.group(1)}"
        for finding in file_entry.get("findings", []):
            if finding.get("category") == "security":
                detections[test_name].add(finding["rule"])
    return detections


def score(expected: dict, detections: dict) -> list:
    """Compute TPR / FPR per CWE category."""
    # Accumulators: {cwe: {TP, FP, FN, TN}}
    counters = {}
    for cwe in CWE_TO_DOJI_RULES:
        counters[cwe] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    for test_name, info in expected.items():
        cwe = info["cwe"]
        if cwe not in counters:
            continue

        rules = CWE_TO_DOJI_RULES[cwe]
        # Did Dojigiri flag this test with a relevant rule?
        flagged = bool(rules and detections.get(test_name, set()) & set(rules))

        if info["real_vuln"]:
            if flagged:
                counters[cwe]["TP"] += 1
            else:
                counters[cwe]["FN"] += 1
        else:
            if flagged:
                counters[cwe]["FP"] += 1
            else:
                counters[cwe]["TN"] += 1

    results = []
    for cwe, c in sorted(counters.items()):
        total_pos = c["TP"] + c["FN"]
        total_neg = c["FP"] + c["TN"]
        tpr = c["TP"] / total_pos if total_pos else 0.0
        fpr = c["FP"] / total_neg if total_neg else 0.0
        youden = tpr - fpr
        covered = bool(CWE_TO_DOJI_RULES[cwe])
        results.append({
            "cwe": cwe,
            "name": OWASP_CATEGORY_NAMES[cwe],
            "covered": covered,
            "TP": c["TP"],
            "FP": c["FP"],
            "FN": c["FN"],
            "TN": c["TN"],
            "TPR": tpr,
            "FPR": fpr,
            "Youden": youden,
        })
    return results


def print_table(results: list, file=sys.stdout):
    """Print a formatted results table."""
    # Header
    fmt = "| {:<22} | {:>7} | {:>4} | {:>4} | {:>4} | {:>4} | {:>7} | {:>7} | {:>7} |"
    sep = "|" + "-" * 24 + "|" + "-" * 9 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 6 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|"

    print(fmt.format("Category", "CWE", "TP", "FP", "FN", "TN", "TPR", "FPR", "Youden"), file=file)
    print(sep, file=file)

    covered_results = [r for r in results if r["covered"]]
    uncovered_results = [r for r in results if not r["covered"]]

    for r in covered_results:
        print(fmt.format(
            r["name"], r["cwe"],
            r["TP"], r["FP"], r["FN"], r["TN"],
            f"{r['TPR']:.1%}", f"{r['FPR']:.1%}", f"{r['Youden']:+.1%}",
        ), file=file)

    if uncovered_results:
        print(sep, file=file)
        for r in uncovered_results:
            total = r["TP"] + r["FP"] + r["FN"] + r["TN"]
            print(fmt.format(
                r["name"] + " *", r["cwe"],
                "-", "-", "-", "-",
                "n/a", "n/a", "n/a",
            ), file=file)

    print(file=file)
    print("* = category not covered by Dojigiri (no matching rule)", file=file)


def compute_overall(results: list) -> dict:
    """Compute overall scores across covered categories only."""
    covered = [r for r in results if r["covered"]]
    if not covered:
        return {"TPR": 0, "FPR": 0, "Youden": 0}

    total_tp = sum(r["TP"] for r in covered)
    total_fp = sum(r["FP"] for r in covered)
    total_fn = sum(r["FN"] for r in covered)
    total_tn = sum(r["TN"] for r in covered)

    total_pos = total_tp + total_fn
    total_neg = total_fp + total_tn
    tpr = total_tp / total_pos if total_pos else 0
    fpr = total_fp / total_neg if total_neg else 0

    # Also compute macro-average (average of per-category rates) —
    # this is what the official OWASP scorecard uses.
    macro_tpr = sum(r["TPR"] for r in covered) / len(covered)
    macro_fpr = sum(r["FPR"] for r in covered) / len(covered)

    return {
        "micro_TPR": tpr,
        "micro_FPR": fpr,
        "micro_Youden": tpr - fpr,
        "macro_TPR": macro_tpr,
        "macro_FPR": macro_fpr,
        "macro_Youden": macro_tpr - macro_fpr,
        "categories_covered": len(covered),
        "categories_total": len(results),
    }


def generate_markdown(results: list, overall: dict, output_path: str):
    """Write scorecard results as Markdown."""
    with open(output_path, "w") as f:
        f.write("# OWASP Benchmark v1.2 - Dojigiri Scorecard\n\n")
        f.write(f"**Categories covered:** {overall['categories_covered']}/{overall['categories_total']}\n\n")

        f.write("## Per-Category Results (Covered)\n\n")
        print_table(results, file=f)

        f.write("\n## Overall Scores (Covered Categories Only)\n\n")

        f.write("### Micro-average (pooled TP/FP/FN/TN across all test cases)\n\n")
        f.write(f"- **TPR:** {overall['micro_TPR']:.1%}\n")
        f.write(f"- **FPR:** {overall['micro_FPR']:.1%}\n")
        f.write(f"- **Youden Index:** {overall['micro_Youden']:+.1%}\n\n")

        f.write("### Macro-average (average of per-category rates - OWASP standard)\n\n")
        f.write(f"- **TPR:** {overall['macro_TPR']:.1%}\n")
        f.write(f"- **FPR:** {overall['macro_FPR']:.1%}\n")
        f.write(f"- **Youden Index:** {overall['macro_Youden']:+.1%}\n\n")

        f.write("## Interpretation\n\n")
        y = overall["macro_Youden"]
        if y > 0:
            f.write(f"Dojigiri scores above the random-guess line (Youden > 0) on covered categories.\n")
        elif y == 0:
            f.write(f"Dojigiri scores at the random-guess line on covered categories.\n")
        else:
            f.write(f"Dojigiri scores below the random-guess line on covered categories.\n")

        f.write(f"\nAcross **all 11 OWASP categories**, Dojigiri currently covers "
                f"**{overall['categories_covered']}** ({overall['categories_covered']}/{overall['categories_total']}). "
                f"Uncovered categories score 0% TPR / 0% FPR by definition.\n\n")

        # Full-benchmark score (all 11 cats, uncovered = 0/0)
        all_macro_tpr = sum(r["TPR"] for r in results) / len(results)
        all_macro_fpr = sum(r["FPR"] for r in results) / len(results)
        all_youden = all_macro_tpr - all_macro_fpr

        f.write("### Full-Benchmark Score (all 11 categories, uncovered = 0%/0%)\n\n")
        f.write(f"- **TPR:** {all_macro_tpr:.1%}\n")
        f.write(f"- **FPR:** {all_macro_fpr:.1%}\n")
        f.write(f"- **Youden Index:** {all_youden:+.1%}\n\n")

        f.write("---\n")
        f.write("*Generated by `owasp_scorecard.py` against Dojigiri scan output.*\n")


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Scorecard for Dojigiri")
    parser.add_argument("--results", default=str(Path(__file__).parent.parent.parent.parent / "temp" / "owasp-benchmark-doji.json"),
                        help="Path to Dojigiri JSON results")
    parser.add_argument("--expected", default=str(Path(__file__).parent.parent.parent.parent / "temp" / "owasp-benchmark" / "expectedresults-1.2.csv"),
                        help="Path to OWASP expected results CSV")
    parser.add_argument("--output", default=str(Path(__file__).parent / "owasp-scorecard-results.md"),
                        help="Path for Markdown output")
    args = parser.parse_args()

    print(f"Loading expected results from: {args.expected}")
    expected = load_expected(args.expected)
    print(f"  {len(expected)} test cases")

    print(f"Loading Dojigiri results from: {args.results}")
    detections = load_dojigiri(args.results)
    print(f"  {len(detections)} test files with security findings")

    print("\nScoring...\n")
    results = score(expected, detections)
    overall = compute_overall(results)

    print_table(results)
    print()
    print(f"Macro-average (OWASP standard, covered categories):")
    print(f"  TPR: {overall['macro_TPR']:.1%}  |  FPR: {overall['macro_FPR']:.1%}  |  Youden: {overall['macro_Youden']:+.1%}")
    print()

    generate_markdown(results, overall, args.output)
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
