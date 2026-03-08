"""CLI entry point for the `doji` command.

Parses arguments and dispatches to subcommands: scan, debug, optimize,
analyze (project-level), fix, report, cost, setup, and hooks. Orchestrates
the full pipeline from file discovery through analysis to output/reporting.

Called by: user (python -m dojigiri / doji command)
Calls into: config.py, analyzer.py, detector.py, storage.py, report.py,
            report_html.py, fixer.py, hooks.py, graph/project.py,
            semantic/explain.py, compliance.py, llm.py, metrics.py
Data in -> Data out: CLI args -> console output + saved reports
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from . import __version__

logger = logging.getLogger(__name__)
from . import report as rpt
from .analyzer import cost_estimate, diff_reports, filter_report, scan_deep, scan_diff, scan_quick
from .bundling import get_exe_path, is_bundled
from .config import (
    CLASSIFICATION_LEVELS,
    LANGUAGE_EXTENSIONS,
    PROFILES,
    compile_custom_rules,
    get_api_key,
    get_llm_config,
    load_project_config,
)
from .detector import analyze_file_static
from .discovery import detect_language
from .storage import list_reports, load_baseline_report, load_latest_report
from .types import Confidence, Severity

SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
CONFIDENCE_MAP = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


def _confirm_llm_usage(args) -> bool:
    """Confirm that the user consents to sending code to an LLM API.

    Returns True if the user accepts (or --accept-remote is set).
    Returns False if declined, offline mode, or non-interactive without --accept-remote.
    Skips confirmation for local backends (ollama).
    """
    # Offline mode blocks all network LLM calls
    if getattr(args, "offline", False):
        print(
            "Error: --offline mode blocks all LLM/network calls. "
            "Use --backend ollama for local models, or remove --offline.",
            file=sys.stderr,
        )
        return False

    # Local backends don't need confirmation — check by locality, not by name.
    # An OpenAI-compatible backend pointed at a remote URL must still confirm.
    backend_type = getattr(args, "backend", None) or ""
    base_url = getattr(args, "base_url", None) or ""
    if backend_type.lower() == "ollama":
        return True
    if backend_type.lower() in ("openai", "openai-compatible") and base_url:
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            return True

    if getattr(args, "accept_remote", False):
        return True
    if not sys.stdin.isatty():
        print(
            "Error: LLM features send code to an API. Use --accept-remote to allow this in non-interactive mode.",
            file=sys.stderr,
        )
        return False
    print("Warning: This command will send code snippets to an LLM API for analysis.")
    try:
        response = input("Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(
            "\nError: No input available. Use --accept-remote to allow LLM usage in non-interactive mode.",
            file=sys.stderr,
        )
        return False
    return response in ("y", "yes")


def _apply_profile(args: argparse.Namespace) -> None:
    """Apply profile defaults to args (CLI args always win)."""
    profile_name = getattr(args, "profile", None)
    if not profile_name:
        return
    profile = PROFILES.get(profile_name)
    if not profile:
        print(f"Warning: unknown profile '{profile_name}'. Available: {', '.join(PROFILES.keys())}", file=sys.stderr)
        return

    # Apply defaults only when CLI arg not explicitly set
    if not getattr(args, "min_severity", None) and "min_severity" in profile:
        args.min_severity = profile["min_severity"]
    if not getattr(args, "ignore", None) and "ignore_rules" in profile:
        args.ignore = ",".join(profile["ignore_rules"])
    if not getattr(args, "classification", None) and "classification" in profile:
        args.classification = profile["classification"]


def _setup_llm_backend(args: argparse.Namespace, project_config: dict | None = None) -> None:
    """Configure LLM backend from CLI args + project config."""
    from .llm import set_backend_config

    llm_config = get_llm_config(project_config)

    # CLI args override
    if getattr(args, "backend", None):
        llm_config["backend"] = args.backend
    if getattr(args, "model", None):
        llm_config["model"] = args.model
    if getattr(args, "base_url", None):
        llm_config["base_url"] = args.base_url

    set_backend_config(llm_config)


from .config import DEFAULT_DOJI_IGNORE as _DEFAULT_DOJI_IGNORE


def cmd_init(args: argparse.Namespace) -> int:
    """Create starter .doji-ignore in the current directory."""
    root = Path(".").resolve()

    ignorefile = root / ".doji-ignore"
    if ignorefile.exists():
        print(f".doji-ignore already exists at {ignorefile}")
        return 0

    ignorefile.write_text(_DEFAULT_DOJI_IGNORE, encoding="utf-8")
    print(f"Created {ignorefile}")
    print("Edit it to exclude folders you don't want scanned.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a code scan (quick or deep)."""
    from .metrics import end_session, save_session, start_session

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

    # Load project config from .doji.toml (if exists)
    scan_root = root if root.is_dir() else root.parent
    if getattr(args, "no_config", False):
        project_config = {}
        custom_rules = []
    else:
        project_config = load_project_config(scan_root)
        custom_rules = compile_custom_rules(project_config)
        # Warn if config suppresses security-relevant rules
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
        suppressed = _SECURITY_RULES & set(project_config.get("ignore_rules", []))
        if suppressed:
            print(
                f"Warning: .doji.toml is suppressing {len(suppressed)} security rule(s): "
                f"{', '.join(sorted(suppressed))}",
                file=sys.stderr,
            )
            print("  Use --no-config to override when scanning untrusted code.", file=sys.stderr)

    use_cache = not args.no_cache
    output_format = getattr(args, "output", "text")
    is_json = output_format == "json"

    diff_base = getattr(args, "diff", None)

    # LLM confirmation for deep scan
    if args.deep:
        _setup_llm_backend(args, project_config)
        if not _confirm_llm_usage(args):
            return 1

    scan_start = time.monotonic()
    try:
        if diff_base is not None:
            # Diff mode: only scan changed lines vs git ref
            try:
                report_obj, resolved_ref = scan_diff(
                    root,
                    base_ref=diff_base if diff_base != "" else None,
                    language_filter=lang,
                    custom_rules=custom_rules,
                )
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            if not is_json:
                print(f"Diff scan vs {resolved_ref} ({report_obj.files_scanned} changed file(s)) ...\n")
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
                return 1
        else:
            if not is_json:
                print(f"Quick scanning {root} ...\n")
            # Use config file workers if not specified on CLI
            workers = getattr(args, "workers", None)
            if workers is None:
                workers = project_config.get("workers", 4)
            report_obj = scan_quick(
                root, language_filter=lang, use_cache=use_cache, max_workers=workers, custom_rules=custom_rules
            )
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

    min_severity = SEVERITY_MAP.get(getattr(args, "min_severity", None))  # type: ignore[arg-type]  # getattr returns str | None; dict.get accepts both
    if not min_severity and "min_severity" in project_config:
        min_severity = SEVERITY_MAP.get(project_config["min_severity"])
    # Bundled .exe default: warning (reduce noise for new users)
    if not min_severity and is_bundled():
        min_severity = Severity.WARNING

    min_confidence = CONFIDENCE_MAP.get(getattr(args, "min_confidence", None))  # type: ignore[arg-type]  # getattr returns str | None; dict.get accepts both
    if not min_confidence and "min_confidence" in project_config:
        min_confidence = CONFIDENCE_MAP.get(project_config["min_confidence"])
    report_obj = filter_report(
        report_obj,
        ignore_rules=ignore_rules,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )

    scan_duration = time.monotonic() - scan_start

    classification = getattr(args, "classification", None)

    if output_format == "json":
        rpt.print_json(report_obj)
    elif output_format == "sarif":
        rpt.print_sarif(report_obj)
    elif output_format == "html":
        from .report_html import render_html

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
        from .report_html import render_pdf

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


# Context discovery extracted to context.py — reusable by MCP and programmatic API
from .context import collect_context_files as _collect_context_files


def _run_llm_subcommand(
    args: argparse.Namespace,
    llm_func_name: str,
    status_msg: str,
    print_text,
    print_json,
    **extra_llm_kwargs,
) -> int:
    """Shared pipeline for LLM subcommands (debug, optimize).

    Handles file validation, LLM setup, static analysis, context collection,
    LLM invocation with error handling, and output formatting.

    Args:
        args: Parsed CLI arguments (must have .file; may have .output, .context).
        llm_func_name: Name of the function to import from .llm (e.g. "debug_file").
        status_msg: Status line printed before the LLM call (receives filepath via .format).
        print_text: Callable(filepath, static_findings[, llm_result]) for text output.
        print_json: Callable(filepath, static_findings[, llm_result, tracker]) for JSON output.
        **extra_llm_kwargs: Additional keyword arguments forwarded to the LLM function.
    """
    filepath = Path(args.file).resolve()
    if not filepath.is_file():
        print(f"Error: '{args.file}' is not a file", file=sys.stderr)
        return 1

    lang = detect_language(filepath)
    if not lang:
        print(f"Error: unsupported file type '{filepath.suffix}'", file=sys.stderr)
        return 1

    _setup_llm_backend(args)
    if not _confirm_llm_usage(args):
        return 1

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    output_format = getattr(args, "output", "text")
    static_findings = analyze_file_static(str(filepath), content, lang).findings

    context_files = None
    context_arg = getattr(args, "context", None)
    if context_arg:
        context_files = _collect_context_files(context_arg, str(filepath), lang, content)

    if output_format != "json":
        print(status_msg.format(filepath))

    try:
        from . import llm as _llm

        llm_func = getattr(_llm, llm_func_name)
        llm_result, tracker = llm_func(
            content,
            str(filepath),
            lang,
            static_findings=static_findings,
            context_files=context_files,
            **extra_llm_kwargs,
        )
        if output_format == "json":
            print_json(str(filepath), static_findings, llm_result, tracker)
        else:
            print_text(str(filepath), static_findings, llm_result)
            print(f"  Cost: ${tracker.total_cost:.4f}")
    except Exception as e:  # LLM can fail many ways (network, API, parse); graceful fallback
        if output_format != "json":
            print(f"LLM error: {e}", file=sys.stderr)
        if output_format == "json":
            print_json(str(filepath), static_findings, None)
        else:
            print_text(str(filepath), static_findings)

    return 0


def cmd_debug(args: argparse.Namespace) -> int:
    """Debug a specific file (always uses LLM)."""
    return _run_llm_subcommand(
        args,
        llm_func_name="debug_file",
        status_msg="Analyzing {} with Claude ...\n",
        print_text=rpt.print_debug_result,
        print_json=rpt.print_debug_json,
        error_msg=args.error,
    )


def cmd_optimize(args: argparse.Namespace) -> int:
    """Optimize a specific file (always uses LLM)."""
    return _run_llm_subcommand(
        args,
        llm_func_name="optimize_file",
        status_msg="Analyzing {} for optimization with Claude ...\n",
        print_text=rpt.print_optimize_result,
        print_json=rpt.print_optimize_json,
    )


def cmd_fix(args: argparse.Namespace) -> int:
    """Fix detected issues in code (deterministic + optional LLM)."""
    from .metrics import end_session, save_session, start_session

    session = start_session()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path '{args.path}' does not exist", file=sys.stderr)
        return 1

    lang = getattr(args, "lang", None)
    if lang and lang not in set(LANGUAGE_EXTENSIONS.values()):
        print(f"Error: unknown language '{lang}'", file=sys.stderr)
        return 1

    dry_run = not getattr(args, "apply", False)
    use_llm = getattr(args, "llm", False)
    accept_llm_fixes = getattr(args, "accept_llm_fixes", False)

    # Block LLM fix application in non-interactive mode without explicit opt-in
    if use_llm and not dry_run and not accept_llm_fixes:
        if not sys.stdin.isatty():
            print(
                "Error: LLM-generated fixes require --accept-llm-fixes in non-interactive mode.\n"
                "  LLM fixes are AI-generated and may introduce subtle logic changes.\n"
                "  Add --accept-llm-fixes to acknowledge this risk.",
                file=sys.stderr,
            )
            return 1
        print(
            "Warning: LLM-generated fixes will be applied alongside deterministic fixes.\n"
            "  LLM fixes are AI-generated and may introduce subtle logic changes.\n"
            "  Review the .doji.bak backup after applying.\n"
            "  To suppress this warning, use --accept-llm-fixes.\n",
            file=sys.stderr,
        )

    create_backup = not getattr(args, "no_backup", False)
    verify = not getattr(args, "no_verify", False)
    output_format = getattr(args, "output", "text")
    rules_arg = getattr(args, "rules", None)
    rules = [r.strip() for r in rules_arg.split(",")] if rules_arg else None
    min_severity_str = getattr(args, "min_severity", None)
    min_severity = SEVERITY_MAP.get(min_severity_str) if min_severity_str else None

    # Load custom rules
    fix_root = root if root.is_dir() else root.parent
    fix_config = load_project_config(fix_root)
    custom_rules = compile_custom_rules(fix_config)

    if use_llm:
        _setup_llm_backend(args, fix_config)
        if not _confirm_llm_usage(args):
            return 1

    # Collect files to fix
    from .discovery import collect_files_with_lang
    from .fixer import fix_file as fixer_fix_file
    from .types import FixReport

    files_to_fix = collect_files_with_lang(root, language_filter=lang)

    if not files_to_fix:
        print("No fixable files found.", file=sys.stderr)
        return 0

    if output_format != "json" and not dry_run:
        print(f"Fixing {len(files_to_fix)} file(s) ...")
    elif output_format != "json":
        print(f"Scanning {len(files_to_fix)} file(s) for fixes (dry run) ...")

    # Severity filter
    from .types import SEVERITY_ORDER as severity_order

    cost_tracker = None
    if use_llm:
        from .llm import CostTracker

        cost_tracker = CostTracker()

    all_fixes = []
    total_applied = 0
    total_skipped = 0
    total_failed = 0
    files_fixed = 0
    aggregate_verification = None

    for filepath, file_lang in files_to_fix:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"  Warning: cannot read {filepath}: {e}", file=sys.stderr)
            continue

        # Get findings via static analysis (with semantics for context-aware fixing)
        result = analyze_file_static(str(filepath), content, file_lang)
        findings, file_semantics, file_type_map = result.findings, result.semantics, result.type_map

        # Apply severity filter
        if min_severity:
            min_ord = severity_order[min_severity]
            findings = [f for f in findings if severity_order[f.severity] <= min_ord]

        if not findings:
            continue

        report = fixer_fix_file(
            str(filepath),
            content,
            file_lang,
            findings,
            use_llm=use_llm,
            dry_run=dry_run,
            create_backup=create_backup,
            rules=rules,
            cost_tracker=cost_tracker,
            verify=verify,
            custom_rules=custom_rules,
            semantics=file_semantics,
            type_map=file_type_map,
        )

        all_fixes.extend(report.fixes)
        total_applied += report.applied
        total_skipped += report.skipped
        total_failed += report.failed
        if report.files_fixed > 0:
            files_fixed += 1
        # Merge verification results
        if report.verification:
            if aggregate_verification is None:
                aggregate_verification = {"resolved": 0, "remaining": 0, "new_issues": 0, "new_findings": []}
            aggregate_verification["resolved"] += report.verification.get("resolved", 0)
            aggregate_verification["remaining"] += report.verification.get("remaining", 0)
            aggregate_verification["new_issues"] += report.verification.get("new_issues", 0)
            aggregate_verification["new_findings"].extend(report.verification.get("new_findings", []))  # type: ignore[attr-defined]  # aggregate_verification values are heterogeneous (int and list)

    # Build aggregate report
    aggregate = FixReport(
        root=str(root),
        files_fixed=files_fixed,
        total_fixes=len(all_fixes),
        applied=total_applied,
        skipped=total_skipped,
        failed=total_failed,
        fixes=all_fixes,
        llm_cost_usd=cost_tracker.total_cost if cost_tracker else 0.0,
        verification=aggregate_verification,
    )

    if output_format == "json":
        rpt.print_fix_json(aggregate)
    else:
        rpt.print_fix_report(aggregate, dry_run=dry_run)

    # Save metrics
    session = end_session()
    if session:
        try:
            save_session(session)
        except OSError as e:
            logger.debug("Failed to save metrics session: %s", e)

    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze a project for cross-file issues."""
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: '{args.path}' is not a directory", file=sys.stderr)
        return 1

    lang = getattr(args, "lang", None)
    if lang and lang not in set(LANGUAGE_EXTENSIONS.values()):
        print(f"Error: unknown language '{lang}'", file=sys.stderr)
        return 1

    depth = getattr(args, "depth", 2)
    output_format = getattr(args, "output", "text")
    use_llm = not getattr(args, "no_llm", False)

    if use_llm:
        _setup_llm_backend(args)
        if not _confirm_llm_usage(args):
            return 1

    if output_format != "json":
        mode = "full (graph + LLM)" if use_llm else "graph only (no LLM)"
        print(f"Analyzing project {root} [{mode}] ...\n")

    try:
        from .graph.project import analyze_project

        analysis = analyze_project(
            str(root),
            language_filter=lang,
            depth=depth,
            use_llm=use_llm,
        )
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted.", file=sys.stderr)
        return 130
    except Exception as e:  # CLI boundary: catch-all for user-facing error
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if output_format == "json":
        rpt.print_project_json(analysis)
    else:
        rpt.print_project_analysis(analysis)

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


def cmd_hook(args: argparse.Namespace) -> int:
    """Install or uninstall doji pre-commit hook."""
    from .hooks import install_hook, uninstall_hook

    root = Path(".").resolve()
    action = args.hook_action

    try:
        if action == "install":
            force = getattr(args, "force", False)
            msg = install_hook(root, force=force)
            print(msg)
            return 0
        elif action == "uninstall":
            msg = uninstall_hook(root)
            print(msg)
            return 0
        else:
            print(f"Unknown hook action: {action}", file=sys.stderr)
            return 1
    except (FileNotFoundError, FileExistsError, PermissionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_explain(args: argparse.Namespace) -> int:
    """Explain a code file in beginner-friendly language."""
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

    output_format = getattr(args, "output", "text")
    deep = getattr(args, "deep", False)

    if deep:
        _setup_llm_backend(args)
        if not _confirm_llm_usage(args):
            return 1

    # Static analysis (includes semantics + type inference — no need to redo)
    result = analyze_file_static(str(filepath), content, lang)

    # Generate explanation
    from .semantic.explain import explain_file

    explanation = explain_file(
        content,
        str(filepath),
        lang,
        semantics=result.semantics,
        findings=result.findings,
        type_map=result.type_map,
    )

    if output_format == "json":
        rpt.print_explain_json(explanation)
    else:
        rpt.print_explanation(explanation)

    # Deep mode: enhance with LLM
    if deep:
        try:
            api_key = get_api_key()
            if not api_key:
                print("\n  --deep requires ANTHROPIC_API_KEY. Showing offline analysis only.", file=sys.stderr)
            else:
                from .llm import CostTracker, explain_file_llm

                tracker = CostTracker()
                llm_result, tracker = explain_file_llm(
                    content,
                    str(filepath),
                    lang,
                    static_findings=result.findings,
                    cost_tracker=tracker,
                )
                if llm_result and output_format != "json":
                    print(f"\n{'=' * 70}")
                    print("  Deep Analysis (LLM-powered)")
                    print(f"{'=' * 70}\n")
                    if isinstance(llm_result, dict):
                        # Purpose
                        if llm_result.get("purpose"):
                            print(f"  Purpose: {llm_result['purpose']}\n")
                        # Data flow
                        if llm_result.get("data_flow"):
                            print(f"  Data flow: {llm_result['data_flow']}\n")
                        # Key concepts
                        concepts = llm_result.get("key_concepts", [])
                        if concepts:
                            print("  Key concepts:")
                            for c in concepts:
                                lines = f" (lines {c['lines']})" if c.get("lines") else ""
                                print(f"    - {c.get('concept', '?')}{lines}")
                                print(f"      {c.get('explanation', '')}")
                            print()
                        # Gotchas
                        gotchas = llm_result.get("gotchas", [])
                        if gotchas:
                            print("  Gotchas:")
                            for g in gotchas:
                                print(f"    - {g}")
                            print()
                        # Findings explained
                        findings_ex = llm_result.get("findings_explained", [])
                        if findings_ex:
                            print("  Findings explained:")
                            for fe in findings_ex:
                                print(f"    [{fe.get('rule', '?')}] {fe.get('plain_english', '')}")
                            print()
                    print(f"  Cost: ${tracker.total_cost:.4f}")
        except Exception as e:  # LLM can fail many ways (network, API, parse); graceful fallback
            if output_format != "json":
                print(f"\n  LLM analysis unavailable: {e}", file=sys.stderr)

    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    """Check environment setup."""
    api_key_set = get_api_key() is not None

    anthropic_installed = False
    try:
        import anthropic  # noqa: F401  # doji:ignore(unused-import)

        anthropic_installed = True
    except ImportError as e:
        logger.debug("Failed to import anthropic: %s", e)

    rpt.print_setup_status(api_key_set, anthropic_installed)
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP server (stdio transport)."""
    try:
        from .mcp_server import mcp as mcp_app
    except ImportError:
        print("Error: MCP support requires the 'mcp' package.", file=sys.stderr)
        print("Install with: pip install dojigiri[mcp]", file=sys.stderr)
        return 1
    mcp_app.run()
    return 0


def cmd_setup_claude(args: argparse.Namespace) -> int:
    """Print MCP config for Claude Code setup."""
    import json

    if is_bundled():
        config = {
            "mcpServers": {
                "dojigiri": {
                    "command": str(get_exe_path()),
                    "args": ["mcp"],
                }
            }
        }
    else:
        config = {
            "mcpServers": {
                "dojigiri": {
                    "command": "python",
                    "args": ["-m", "dojigiri", "mcp"],
                }
            }
        }

    print("Add to your Claude Code MCP settings:\n")
    print(json.dumps(config, indent=2))
    print()
    print("---")
    print()
    print("Optionally add this to your CLAUDE.md:\n")
    print("""## Dojigiri Static Analyzer (MCP)

You have access to Dojigiri via MCP tools. Use them proactively:

- **doji_scan** — Scan files/dirs for bugs, security issues, code quality.
  Use after writing code or when reviewing a project.
- **doji_scan_file** — Quick single-file scan. Faster for one file.
- **doji_fix** — Preview available auto-fixes (dry run). Apply with Edit tool.
- **doji_explain** — Understand file structure, patterns, and design.
- **doji_analyze_project** — Cross-file analysis: dependencies, dead code, cycles.

When to use Dojigiri vs your own analysis:
- Dojigiri catches systematic issues (taint flow, null deref, scope bugs) that are
  easy to miss in manual review. Use it as a second pair of eyes.
- For security-sensitive code, always run doji_scan.
- After fixing issues, re-scan to verify they're resolved.""")
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


def cmd_privacy(args: argparse.Namespace) -> int:
    """Show privacy and data handling information."""
    privacy_path = Path(__file__).parent.parent / "PRIVACY.md"
    if privacy_path.exists():
        print(privacy_path.read_text(encoding="utf-8"))
    else:
        print("Dojigiri Privacy Information")
        print("=" * 40)
        print()
        print("Static scan (doji scan .):  No data leaves your machine.")
        print("Deep scan (--deep):         Source code is sent to the configured LLM API.")
        print("                            Default: Anthropic (Claude) at api.anthropic.com")
        print("                            See Anthropic's privacy policy for data handling.")
        print("Local backends (ollama):    No data leaves your machine.")
        print()
        print("API keys should be set via environment variables, not .doji.toml.")
        print("Scan reports are stored locally in ~/.dojigiri/reports/.")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    """List all available rules."""
    import json

    from .languages import list_all_rules

    rules = list_all_rules()
    if args.lang:
        lang_filter = args.lang.lower()
        rules = [r for r in rules if "all" in r["languages"] or lang_filter in r["languages"]]

    if args.output == "json":
        print(json.dumps(rules, indent=2))
        return 0

    # Text table output
    if not rules:
        print("No rules found.")
        return 0

    # Column widths
    name_w = max(len(r["name"]) for r in rules)
    sev_w = max(len(r["severity"]) for r in rules)
    cat_w = max(len(r["category"]) for r in rules)
    cwe_w = max((len(r.get("cwe", "")) for r in rules), default=3)
    name_w = max(name_w, 4)  # min header width
    cwe_w = max(cwe_w, 3)

    header = f"{'RULE':<{name_w}}  {'SEVERITY':<{sev_w}}  {'CATEGORY':<{cat_w}}  {'CWE':<{cwe_w}}  LANGUAGES"
    print(header)
    print("\u2500" * len(header))
    for r in rules:
        langs = ", ".join(r["languages"])
        cwe = r.get("cwe", "")
        print(f"{r['name']:<{name_w}}  {r['severity']:<{sev_w}}  {r['category']:<{cat_w}}  {cwe:<{cwe_w}}  {langs}")

    # Summary
    from collections import Counter

    sev_counts = Counter(r["severity"] for r in rules)
    sev_order = {"critical": 0, "warning": 1, "info": 2}
    parts = [f"{count} {sev}" for sev, count in sorted(sev_counts.items(), key=lambda x: sev_order.get(x[0], 9))]
    print(f"\n{len(rules)} rules ({', '.join(parts)})")
    return 0


def cmd_stats(args) -> int:
    """Show metrics history and trend analysis."""
    from .metrics import format_history_summary, load_history

    days = getattr(args, "days", 30)
    limit = getattr(args, "limit", 10)
    sessions = load_history(days=days)
    print(format_history_summary(sessions, limit=limit))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="doji",
        description="Dojigiri — static analysis engine",
    )
    parser.add_argument("--version", action="version", version=f"dojigiri {__version__}")
    parser.add_argument(
        "--offline", action="store_true", help="Offline mode — block all network/LLM calls (static analysis only)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # init
    p_init = subparsers.add_parser("init", help="Create starter .doji-ignore file")
    p_init.set_defaults(func=cmd_init)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan code for issues")
    p_scan.add_argument("path", help="File or directory to scan")
    p_scan.add_argument("--deep", action="store_true", help="Deep scan with Claude API (paid)")
    p_scan.add_argument(
        "--diff",
        nargs="?",
        const="",
        default=None,
        metavar="REF",
        help="Only scan lines changed vs git ref (default: main/master)",
    )
    p_scan.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p_scan.add_argument("--no-cache", action="store_true", help="Skip file hash cache (rescan all files)")
    p_scan.add_argument(
        "--no-config", action="store_true", help="Ignore .doji.toml project config (use when scanning untrusted code)"
    )
    p_scan.add_argument("--ignore", help="Comma-separated rule names to suppress (e.g., todo-marker,long-line)")
    p_scan.add_argument(
        "--min-severity", choices=["critical", "warning", "info"], help="Minimum severity to display (filters lower)"
    )
    p_scan.add_argument(
        "--min-confidence",
        choices=["high", "medium", "low"],
        default=None,
        help="Minimum LLM confidence to display (default: show all)",
    )
    p_scan.add_argument(
        "--output",
        choices=["text", "json", "sarif", "html", "pdf"],
        default="text",
        help="Output format: text, json, sarif, html, pdf",
    )
    p_scan.add_argument("--output-file", metavar="PATH", help="Write HTML/PDF output to file instead of stdout")
    p_scan.add_argument("--project-name", metavar="NAME", help="Project name for HTML/PDF reports")
    p_scan.add_argument(
        "--classification",
        choices=CLASSIFICATION_LEVELS,
        default=None,
        help="Classification marking for reports (e.g., CUI, SECRET)",
    )
    p_scan.add_argument(
        "--profile", choices=list(PROFILES.keys()), default=None, help="Compliance profile preset (owasp, dod, ci)"
    )
    p_scan.add_argument(
        "--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend for deep scans"
    )
    p_scan.add_argument("--model", default=None, help="LLM model name")
    p_scan.add_argument("--base-url", default=None, help="LLM API base URL (for openai-compatible)")
    p_scan.add_argument("--baseline", help="Compare against baseline (use 'latest' or report path)")
    p_scan.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Number of parallel workers for quick scan (default: 4 or from .doji.toml, use 1 for sequential)",
    )
    p_scan.add_argument(
        "--max-cost",
        type=float,
        default=None,
        metavar="USD",
        help="Maximum LLM cost in USD before pausing (deep scan only)",
    )
    p_scan.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_scan.set_defaults(func=cmd_scan)

    # debug
    p_debug = subparsers.add_parser("debug", help="Debug a specific file (uses Claude API)")
    p_debug.add_argument("file", help="File to debug")
    p_debug.add_argument("--error", "-e", help="Error message or traceback for context")
    p_debug.add_argument(
        "--context", "-c", help="Related files for multi-file debugging: comma-separated paths or 'auto' (Python only)"
    )
    p_debug.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_debug.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_debug.add_argument("--model", default=None, help="LLM model name")
    p_debug.add_argument("--base-url", default=None, help="LLM API base URL")
    p_debug.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_debug.set_defaults(func=cmd_debug)

    # optimize
    p_opt = subparsers.add_parser("optimize", help="Get optimization suggestions (uses Claude API)")
    p_opt.add_argument("file", help="File to optimize")
    p_opt.add_argument("--context", "-c", help="Related files for context: comma-separated paths or 'auto'")
    p_opt.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_opt.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_opt.add_argument("--model", default=None, help="LLM model name")
    p_opt.add_argument("--base-url", default=None, help="LLM API base URL")
    p_opt.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_opt.set_defaults(func=cmd_optimize)

    # fix
    p_fix = subparsers.add_parser("fix", help="Auto-fix detected issues")
    p_fix.add_argument("path", help="File or directory to fix")
    p_fix.add_argument("--apply", action="store_true", help="Actually apply fixes (default is dry-run)")
    p_fix.add_argument("--llm", action="store_true", help="Include LLM-generated fixes (costs money)")
    p_fix.add_argument(
        "--accept-llm-fixes",
        action="store_true",
        help="Apply LLM-generated fixes without extra confirmation (use with --apply --llm)",
    )
    p_fix.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating .doji.bak backup files (backups accumulate and are not auto-cleaned)",
    )
    p_fix.add_argument("--no-verify", action="store_true", help="Skip re-scanning file after applying fixes")
    p_fix.add_argument("--rules", help="Only fix specific rules (comma-separated, e.g., bare-except,var-usage)")
    p_fix.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p_fix.add_argument(
        "--min-severity", choices=["critical", "warning", "info"], help="Only fix issues at this severity or above"
    )
    p_fix.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_fix.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_fix.add_argument("--model", default=None, help="LLM model name")
    p_fix.add_argument("--base-url", default=None, help="LLM API base URL")
    p_fix.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_fix.set_defaults(func=cmd_fix)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze project for cross-file issues")
    p_analyze.add_argument("path", help="Project directory to analyze")
    p_analyze.add_argument("--depth", type=int, default=2, metavar="N", help="Dependency traversal depth (default: 2)")
    p_analyze.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_analyze.add_argument("--no-llm", action="store_true", help="Graph + metrics only, no API key needed (free)")
    p_analyze.add_argument("--lang", help="Filter by language (e.g., python)")
    p_analyze.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_analyze.add_argument("--model", default=None, help="LLM model name")
    p_analyze.add_argument("--base-url", default=None, help="LLM API base URL")
    p_analyze.add_argument(
        "--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)"
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain a code file (beginner-friendly tutorial)")
    p_explain.add_argument("file", help="File to explain")
    p_explain.add_argument("--deep", action="store_true", help="Use LLM for richer explanations (costs money)")
    p_explain.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_explain.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_explain.add_argument("--model", default=None, help="LLM model name")
    p_explain.add_argument("--base-url", default=None, help="LLM API base URL")
    p_explain.add_argument(
        "--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)"
    )
    p_explain.set_defaults(func=cmd_explain)

    # report
    p_report = subparsers.add_parser("report", help="Show latest scan report")
    p_report.set_defaults(func=cmd_report)

    # cost
    p_cost = subparsers.add_parser("cost", help="Estimate deep scan cost")
    p_cost.add_argument("path", help="File or directory to estimate")
    p_cost.add_argument("--lang", help="Filter by language")
    p_cost.set_defaults(func=cmd_cost)

    # hook
    p_hook = subparsers.add_parser("hook", help="Manage pre-commit hook")
    p_hook.add_argument(
        "hook_action", choices=["install", "uninstall"], help="Install or uninstall doji pre-commit hook"
    )
    p_hook.add_argument("--force", action="store_true", help="Overwrite existing non-doji hooks")
    p_hook.set_defaults(func=cmd_hook)

    # setup
    p_setup = subparsers.add_parser("setup", help="Check environment setup")
    p_setup.set_defaults(func=cmd_setup)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Start the MCP server (for Claude Code integration)")
    p_mcp.set_defaults(func=cmd_mcp)

    # stats
    p_stats = subparsers.add_parser("stats", help="Show scan/fix metrics history and trends")
    p_stats.add_argument("--days", type=int, default=30, help="How many days of history (default: 30)")
    p_stats.add_argument("--limit", type=int, default=10, help="Number of sessions to show (default: 10)")
    p_stats.set_defaults(func=cmd_stats)

    # rules
    p_rules = subparsers.add_parser("rules", help="List all available rules")
    p_rules.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p_rules.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p_rules.set_defaults(func=cmd_rules)

    # setup-claude
    p_setup_claude = subparsers.add_parser("setup-claude", help="Print MCP config for Claude Code")
    p_setup_claude.set_defaults(func=cmd_setup_claude)

    # clean
    p_clean = subparsers.add_parser("clean", help="Remove .doji.bak backup files and .doji.tmp temp files")
    p_clean.add_argument("path", nargs="?", default=".", help="Directory to clean (default: current directory)")
    p_clean.add_argument("--dry-run", action="store_true", help="Show what would be removed without deleting")
    p_clean.set_defaults(func=cmd_clean)

    # privacy
    p_privacy = subparsers.add_parser("privacy", help="Show data handling and privacy information")
    p_privacy.set_defaults(func=cmd_privacy)

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
