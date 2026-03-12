"""Scan lifecycle commands: scan, cost, stats, report, clean.

Orchestrator module with intentionally high coupling — CLI entry point that
dispatches to analyzer, config, reporting, and output subsystems.
"""

from __future__ import annotations  # noqa

import argparse
import logging
import sys
import time
from pathlib import Path

from .. import report as rpt
from ..analyzer import cost_estimate, diff_reports, filter_report, scan_deep, scan_diff, scan_quick
from ..bundling import is_bundled
from ..config import LANGUAGE_EXTENSIONS, compile_custom_rules, load_project_config
from ..storage import list_reports, load_baseline_report, load_latest_report
from ..types import ScanReport, Severity
from .common import CONFIDENCE_MAP, SEVERITY_MAP, _apply_profile, _confirm_llm_usage, _setup_llm_backend

logger = logging.getLogger(__name__)

_SECURITY_RULES = {
    "eval-usage",
    "exec-usage",
    "hardcoded-secret",
    "sql-injection",
    "os-system",
    "shell-true",
    "pickle-unsafe",
    "yaml-unsafe",
    "command-injection",
    "path-traversal",
    "insecure-crypto",
    "insecure-deserialization",
    "insecure-http",
    "xss",
}


def _load_scan_config(args: argparse.Namespace, scan_root: Path) -> tuple[dict, list]:
    """Load project config and custom rules, warn about suppressed security rules.

    Returns (project_config, custom_rules).
    """
    if getattr(args, "no_config", False):
        return {}, []

    project_config = load_project_config(scan_root)
    custom_rules = compile_custom_rules(project_config)
    suppressed = _SECURITY_RULES & set(project_config.get("ignore_rules", []))
    if suppressed:
        print(
            f"Warning: .doji.toml is suppressing {len(suppressed)} security rule(s): "
            f"{', '.join(sorted(suppressed))}",
            file=sys.stderr,
        )
        print("  Use --no-config to override when scanning untrusted code.", file=sys.stderr)
    return project_config, custom_rules


def _execute_scan(args: argparse.Namespace, root: Path, lang: str | None, use_cache: bool, is_json: bool, project_config: dict, custom_rules: list) -> tuple[ScanReport | None, int | None]:
    """Execute the appropriate scan mode (diff, deep, or quick).

    Returns (report_obj, error_code) where error_code is None on success.
    """
    diff_base = getattr(args, "diff", None)

    if diff_base is not None:
        try:
            report_obj, resolved_ref = scan_diff(
                root,
                base_ref=diff_base if diff_base != "" else None,
                language_filter=lang,
                custom_rules=custom_rules,
            )
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return None, 1
        if not is_json:
            print(f"Diff scan vs {resolved_ref} ({report_obj.files_scanned} changed file(s)) ...\n")
        return report_obj, None
    elif args.deep:
        if not is_json:
            print(f"Deep scanning {root} ...\n")
        workers = getattr(args, "workers", None)
        if workers is None:
            workers = project_config.get("workers", 4)
        max_cost = getattr(args, "max_cost", None)
        try:
            report_obj = scan_deep(
                root,
                language_filter=lang,
                use_cache=use_cache,
                max_workers=workers,
                custom_rules=custom_rules,
                max_cost=max_cost,
            )
        except Exception as e:  # CLI boundary: catch-all for user-facing error
            print(f"Error: {e}", file=sys.stderr)
            return None, 1
        return report_obj, None
    else:
        if not is_json:
            print(f"Quick scanning {root} ...\n")
        workers = getattr(args, "workers", None)
        if workers is None:
            workers = project_config.get("workers", 4)
        report_obj = scan_quick(
            root, language_filter=lang, use_cache=use_cache, max_workers=workers, custom_rules=custom_rules
        )
        return report_obj, None


def _output_report(report_obj, output_format, scan_duration, args) -> int | None:
    """Format and output the scan report. Returns error code or None on success."""
    classification = getattr(args, "classification", None)

    if output_format == "json":
        rpt.print_json(report_obj)
    elif output_format == "sarif":
        rpt.print_sarif(report_obj)
    elif output_format == "html":
        from ..report_html import render_html

        html_content = render_html(
            report_obj,
            classification=classification,
            project_name=getattr(args, "project_name", None),
        )
        output_file = getattr(args, "output_file", None)
        if output_file:
            Path(output_file).write_text(html_content, encoding="utf-8")
            print(f"HTML report written to {output_file}")
        else:
            print(html_content)
    elif output_format == "pdf":
        from ..report_html import render_pdf

        output_file = getattr(args, "output_file", None) or "dojigiri-report.pdf"
        try:
            render_pdf(
                report_obj,
                output_file,
                classification=classification,
                project_name=getattr(args, "project_name", None),
            )
            print(f"PDF report written to {output_file}")
        except ImportError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        rpt.print_report(report_obj, duration=scan_duration, classification=classification)
    return None


def _apply_baseline_and_filters(args: argparse.Namespace, report_obj: ScanReport, project_config: dict, is_json: bool) -> ScanReport:
    """Apply baseline diff and post-scan severity/confidence/rule filters."""
    baseline_arg = getattr(args, "baseline", None)
    if baseline_arg:
        baseline_dict = load_baseline_report(baseline_arg)
        if baseline_dict:
            if not is_json:
                print(f"Comparing against baseline: {baseline_arg}")
            report_obj = diff_reports(report_obj, baseline_dict)
        else:
            print(f"Warning: baseline '{baseline_arg}' not found, showing all findings", file=sys.stderr)

    ignore_rules = set(args.ignore.split(",")) if getattr(args, "ignore", None) else None
    if not ignore_rules and "ignore_rules" in project_config:
        ignore_rules = set(project_config["ignore_rules"])

    min_severity = SEVERITY_MAP.get(getattr(args, "min_severity", None))  # type: ignore[arg-type]  # getattr returns str | None; dict.get accepts both
    if not min_severity and "min_severity" in project_config:
        min_severity = SEVERITY_MAP.get(project_config["min_severity"])
    if not min_severity and is_bundled():
        min_severity = Severity.WARNING

    min_confidence = CONFIDENCE_MAP.get(getattr(args, "min_confidence", None))  # type: ignore[arg-type]  # getattr returns str | None; dict.get accepts both
    if not min_confidence and "min_confidence" in project_config:
        min_confidence = CONFIDENCE_MAP.get(project_config["min_confidence"])

    return filter_report(
        report_obj,
        ignore_rules=ignore_rules,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a code scan (quick or deep)."""
    from ..metrics import end_session, save_session, start_session

    session = start_session()

    _apply_profile(args)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path '{args.path}' does not exist", file=sys.stderr)
        return 1

    lang = args.lang
    if lang and lang not in set(LANGUAGE_EXTENSIONS.values()):
        print(f"Error: unknown language '{lang}'", file=sys.stderr)
        print(f"Supported: {', '.join(sorted(set(LANGUAGE_EXTENSIONS.values())))}")
        return 1

    scan_root = root if root.is_dir() else root.parent
    project_config, custom_rules = _load_scan_config(args, scan_root)

    use_cache = not args.no_cache
    output_format = getattr(args, "output", "text")
    is_json = output_format == "json"

    # LLM confirmation for deep scan
    if args.deep:
        from ..plugin import has_llm_plugin

        if not has_llm_plugin():
            print(
                "Error: Deep scan requires dojigiri-ai. Install with: pip install dojigiri-ai",
                file=sys.stderr,
            )
            return 1
        _setup_llm_backend(args, project_config)
        if not _confirm_llm_usage(args):
            return 1

    scan_start = time.monotonic()
    try:
        report_obj, err = _execute_scan(args, root, lang, use_cache, is_json, project_config, custom_rules)
        if err is not None:
            return err
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.", file=sys.stderr)
        print("Partial results may have been saved.", file=sys.stderr)
        return 130  # 128 + SIGINT(2)

    # Apply baseline diff and post-scan filters
    report_obj = _apply_baseline_and_filters(args, report_obj, project_config, is_json)

    scan_duration = time.monotonic() - scan_start

    output_err = _output_report(report_obj, output_format, scan_duration, args)
    if output_err is not None:
        return output_err

    # Save metrics
    session = end_session()
    if session:
        try:
            save_session(session)
        except OSError as e:
            logger.debug("Failed to save metrics session: %s", e)

    if report_obj.critical > 0:
        return 2  # exit code 2 = critical issues found
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Show latest scan report."""
    data = load_latest_report()
    if not data:
        print("No scan reports found. Run a scan first:")
        print("  python -m dojigiri scan .")
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


def cmd_cost(args: argparse.Namespace) -> int:
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


def cmd_stats(args) -> int:
    """Show metrics history and trend analysis."""
    from ..metrics import format_history_summary, load_history

    days = getattr(args, "days", 30)
    limit = getattr(args, "limit", 10)
    sessions = load_history(days=days)
    print(format_history_summary(sessions, limit=limit))
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove .doji.bak and .doji.tmp files."""
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: '{args.path}' is not a directory", file=sys.stderr)
        return 1

    dry_run = getattr(args, "dry_run", False)
    patterns = ["**/*.doji.bak", "**/*.doji.tmp"]
    found = []
    for pattern in patterns:
        found.extend(root.glob(pattern))

    if not found:
        print("No .doji.bak or .doji.tmp files found.")
        return 0

    total_size = sum(f.stat().st_size for f in found if f.exists())
    size_mb = total_size / (1024 * 1024)

    if dry_run:
        print(f"Would remove {len(found)} file(s) ({size_mb:.2f} MB):")
        for f in sorted(found):
            print(f"  {f}")
    else:
        removed = 0
        for f in found:
            try:
                f.unlink()
                removed += 1
            except OSError as e:
                print(f"  Warning: could not remove {f}: {e}", file=sys.stderr)
        print(f"Removed {removed} file(s) ({size_mb:.2f} MB).")

    return 0
