"""CLI entry point: scan, debug, optimize, report, cost, setup."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import get_api_key, Severity, Confidence, LANGUAGE_EXTENSIONS, load_project_config
from .analyzer import scan_quick, scan_deep, cost_estimate, detect_language, filter_report, diff_reports
from .detector import analyze_file_static
from .storage import load_latest_report, load_baseline_report, list_reports
from . import report as rpt

SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
CONFIDENCE_MAP = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


def cmd_scan(args):
    """Run a code scan (quick or deep)."""
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path '{args.path}' does not exist", file=sys.stderr)
        return 1

    lang = args.lang
    if lang and lang not in set(LANGUAGE_EXTENSIONS.values()):
        print(f"Error: unknown language '{lang}'", file=sys.stderr)
        print(f"Supported: {', '.join(sorted(set(LANGUAGE_EXTENSIONS.values())))}")
        return 1

    # Load project config from .wiz.toml (if exists)
    scan_root = root if root.is_dir() else root.parent
    project_config = load_project_config(scan_root)
    
    use_cache = not args.no_cache
    output_format = getattr(args, "output", "text")
    is_json = output_format == "json"

    try:
        if args.deep:
            if not is_json:
                print(f"Deep scanning {root} ...\n")
            try:
                report_obj = scan_deep(root, language_filter=lang)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
        else:
            if not is_json:
                print(f"Quick scanning {root} ...\n")
            # Use config file workers if not specified on CLI
            workers = getattr(args, "workers", None)
            if workers is None:
                workers = project_config.get("workers", 4)
            report_obj = scan_quick(root, language_filter=lang, use_cache=use_cache, max_workers=workers)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.", file=sys.stderr)
        print("Partial results may have been saved.", file=sys.stderr)
        return 130  # 128 + SIGINT(2)

    # Apply baseline diff if requested
    baseline_arg = getattr(args, "baseline", None)
    if baseline_arg:
        baseline_dict = load_baseline_report(baseline_arg)
        if baseline_dict:
            if not is_json:
                print(f"Comparing against baseline: {baseline_arg}")
            report_obj = diff_reports(report_obj, baseline_dict)
        else:
            print(f"Warning: baseline '{baseline_arg}' not found, showing all findings", file=sys.stderr)
    
    # Apply post-scan filters (CLI args override config file)
    ignore_rules = set(args.ignore.split(",")) if getattr(args, "ignore", None) else None
    if not ignore_rules and "ignore_rules" in project_config:
        ignore_rules = set(project_config["ignore_rules"])
    
    min_severity = SEVERITY_MAP.get(getattr(args, "min_severity", None))
    if not min_severity and "min_severity" in project_config:
        min_severity = SEVERITY_MAP.get(project_config["min_severity"])
    
    min_confidence = CONFIDENCE_MAP.get(getattr(args, "min_confidence", None))
    if not min_confidence and "min_confidence" in project_config:
        min_confidence = CONFIDENCE_MAP.get(project_config["min_confidence"])
    report_obj = filter_report(
        report_obj,
        ignore_rules=ignore_rules,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )

    if output_format == "json":
        rpt.print_json(report_obj)
    elif output_format == "sarif":
        rpt.print_sarif(report_obj)
    else:
        rpt.print_report(report_obj)

    if report_obj.critical > 0:
        return 2  # exit code 2 = critical issues found
    return 0


def cmd_debug(args):
    """Debug a specific file (always uses LLM)."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(f"Error: '{args.file}' is not a file", file=sys.stderr)
        return 1

    lang = detect_language(filepath)
    if not lang:
        print(f"Error: unsupported file type '{filepath.suffix}'", file=sys.stderr)
        return 1

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    # Static analysis first
    static_findings = analyze_file_static(str(filepath), content, lang)

    # LLM analysis
    print(f"Analyzing {filepath} with Claude ...\n")
    try:
        from .llm import debug_file
        llm_response, tracker = debug_file(
            content, str(filepath), lang,
            error_msg=args.error,
        )
        rpt.print_debug_result(str(filepath), static_findings, llm_response)
        print(f"  Cost: ${tracker.total_cost:.4f}")
    except Exception as e:
        # Fall back to static-only
        print(f"LLM error: {e}", file=sys.stderr)
        rpt.print_debug_result(str(filepath), static_findings)

    return 0


def cmd_optimize(args):
    """Optimize a specific file (always uses LLM)."""
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(f"Error: '{args.file}' is not a file", file=sys.stderr)
        return 1

    lang = detect_language(filepath)
    if not lang:
        print(f"Error: unsupported file type '{filepath.suffix}'", file=sys.stderr)
        return 1

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    print(f"Analyzing {filepath} for optimization with Claude ...\n")
    try:
        from .llm import optimize_file
        llm_response, tracker = optimize_file(content, str(filepath), lang)
        rpt.print_optimize_result(str(filepath), llm_response)
        print(f"  Cost: ${tracker.total_cost:.4f}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


def cmd_report(args):
    """Show latest scan report."""
    data = load_latest_report()
    if not data:
        print("No scan reports found. Run a scan first:")
        print("  python -m wiz scan .")
        return 1

    print(f"\nLatest report: {data.get('timestamp', 'unknown')}")
    print(f"Root: {data.get('root', 'unknown')}")
    print(f"Mode: {data.get('mode', 'unknown')}")
    print(f"Files: {data.get('files_scanned', 0)}")
    print("\nFindings:")
    print(f"  Critical: {data.get('critical', 0)}")
    print(f"  Warnings: {data.get('warnings', 0)}")
    print(f"  Info:     {data.get('info', 0)}")
    print(f"  Total:    {data.get('total_findings', 0)}")

    if data.get("llm_cost_usd", 0) > 0:
        print(f"\nLLM cost: ${data['llm_cost_usd']:.4f}")

    # Show top findings
    files = data.get("files", [])
    for f in files:
        findings = f.get("findings", [])
        critical = [x for x in findings if x.get("severity") == "critical"]
        if critical:
            print(f"\n  {f['path']}:")
            for c in critical[:5]:
                print(f"    line {c['line']}: {c['message']}")

    reports = list_reports()
    if len(reports) > 1:
        print(f"\n{len(reports)} reports saved. Latest shown.")

    return 0


def cmd_cost(args):
    """Estimate deep scan cost."""
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path '{args.path}' does not exist", file=sys.stderr)
        return 1

    lang = args.lang if hasattr(args, "lang") else None
    total_lines, total_files, est_tokens, est_cost = cost_estimate(root, lang)

    if total_files == 0:
        print("No analyzable files found.")
        return 1

    rpt.print_cost_estimate(total_lines, total_files, est_tokens, est_cost)
    return 0


def cmd_setup(args):
    """Check environment setup."""
    api_key_set = get_api_key() is not None

    anthropic_installed = False
    try:
        import importlib
        importlib.import_module("anthropic")
        anthropic_installed = True
    except ImportError:
        pass  # Not installed - that's fine, we just report it

    rpt.print_setup_status(api_key_set, anthropic_installed)
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="wiz",
        description="Code debugging & optimization agent",
    )
    parser.add_argument("--version", action="version", version=f"wiz {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan code for issues")
    p_scan.add_argument("path", help="File or directory to scan")
    p_scan.add_argument("--deep", action="store_true", help="Deep scan with Claude API (paid)")
    p_scan.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p_scan.add_argument("--no-cache", action="store_true", help="Skip file hash cache (rescan all files)")
    p_scan.add_argument("--ignore", help="Comma-separated rule names to suppress (e.g., todo-marker,long-line)")
    p_scan.add_argument("--min-severity", choices=["critical", "warning", "info"],
                         help="Minimum severity to display (filters lower)")
    p_scan.add_argument("--min-confidence", choices=["high", "medium", "low"],
                         default=None,
                         help="Minimum LLM confidence to display (default: show all)")
    p_scan.add_argument("--output", choices=["text", "json", "sarif"], default="text",
                         help="Output format: text (console), json (CI/CD), sarif (GitHub Code Scanning)")
    p_scan.add_argument("--baseline", help="Compare against baseline (use 'latest' or report path)")
    p_scan.add_argument("--workers", type=int, default=None, metavar="N",
                         help="Number of parallel workers for quick scan (default: 4 or from .wiz.toml, use 1 for sequential)")
    p_scan.set_defaults(func=cmd_scan)

    # debug
    p_debug = subparsers.add_parser("debug", help="Debug a specific file (uses Claude API)")
    p_debug.add_argument("file", help="File to debug")
    p_debug.add_argument("--error", "-e", help="Error message for context")
    p_debug.set_defaults(func=cmd_debug)

    # optimize
    p_opt = subparsers.add_parser("optimize", help="Get optimization suggestions (uses Claude API)")
    p_opt.add_argument("file", help="File to optimize")
    p_opt.set_defaults(func=cmd_optimize)

    # report
    p_report = subparsers.add_parser("report", help="Show latest scan report")
    p_report.set_defaults(func=cmd_report)

    # cost
    p_cost = subparsers.add_parser("cost", help="Estimate deep scan cost")
    p_cost.add_argument("path", help="File or directory to estimate")
    p_cost.add_argument("--lang", help="Filter by language")
    p_cost.set_defaults(func=cmd_cost)

    # setup
    p_setup = subparsers.add_parser("setup", help="Check environment setup")
    p_setup.set_defaults(func=cmd_setup)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        sys.exit(args.func(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
