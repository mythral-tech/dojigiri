"""Project-level commands: analyze, review, sca, fix."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from .. import report as rpt
from ..config import LANGUAGE_EXTENSIONS, compile_custom_rules, load_project_config
from ..detector import analyze_file_static
from ..types import SEVERITY_ORDER, Severity
from .common import SEVERITY_MAP, _confirm_llm_usage, _setup_llm_backend

logger = logging.getLogger(__name__)


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
        from ..graph.project import analyze_project

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


def cmd_review(args: argparse.Namespace) -> int:
    """Review a PR or branch diff like a senior security engineer."""
    from ..pr_review import format_pr_comment, review_diff

    root = Path(".").resolve()

    # Load project config
    if getattr(args, "no_config", False):
        project_config = {}
        custom_rules = []
    else:
        project_config = load_project_config(root)
        custom_rules = compile_custom_rules(project_config)

    use_llm = getattr(args, "llm", False)
    pr_number = getattr(args, "pr", None)
    base_ref = getattr(args, "base", None)
    output_format = getattr(args, "output", "text")

    # LLM setup and confirmation
    if use_llm:
        _setup_llm_backend(args, project_config)
        if not _confirm_llm_usage(args):
            return 1

    is_json = output_format == "json"
    is_comment = output_format == "comment"

    if not is_json:
        if pr_number is not None:
            print(f"Reviewing PR #{pr_number} ...\n")
        else:
            print("Reviewing branch diff ...\n")

    try:
        review = review_diff(
            root,
            base_ref=base_ref,
            pr_number=pr_number,
            use_llm=use_llm,
            custom_rules=custom_rules,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if is_json:
        rpt.print_pr_review_json(review)
    elif is_comment:
        print(format_pr_comment(review))
    else:
        rpt.print_pr_review(review)

    if review.critical > 0:
        return 2
    return 0


def cmd_sca(args: argparse.Namespace) -> int:
    """Scan dependencies for known vulnerabilities via OSV."""
    from ..sca.scanner import scan_sca
    from ..types import ScanReport

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: {root} does not exist", file=sys.stderr)
        return 1

    offline = getattr(args, "offline", False)
    if offline:
        print("Error: SCA requires network access to query the OSV vulnerability database.", file=sys.stderr)
        print("Remove --offline to use SCA.", file=sys.stderr)
        return 1

    min_sev = SEVERITY_MAP.get(args.min_severity, Severity.INFO)
    t0 = time.time()

    analyses = scan_sca(root, timeout=args.timeout)

    # Filter by severity
    for fa in analyses:
        fa.findings = [f for f in fa.findings if SEVERITY_ORDER.get(f.severity, 2) <= SEVERITY_ORDER.get(min_sev, 2)]
    analyses = [fa for fa in analyses if fa.findings]

    elapsed = time.time() - t0

    if args.output == "json":
        import json as json_mod

        report = ScanReport(
            root=str(root),
            mode="sca",
            files_scanned=len(analyses),
            files_skipped=0,
            file_analyses=analyses,
        )
        print(json_mod.dumps(report.to_dict(), indent=2))
    elif args.output == "sarif":
        import json as json_mod

        from ..sarif import findings_to_sarif

        all_findings = [f for fa in analyses for f in fa.findings]
        sarif = findings_to_sarif(all_findings, str(root))
        print(json_mod.dumps(sarif, indent=2))
    else:
        # Text output
        total_vulns = sum(len(fa.findings) for fa in analyses)
        if not analyses:
            print(f"No vulnerable dependencies found. ({elapsed:.1f}s)")
            return 0

        critical = sum(1 for fa in analyses for f in fa.findings if f.severity == Severity.CRITICAL)
        warnings = sum(1 for fa in analyses for f in fa.findings if f.severity == Severity.WARNING)
        info = sum(1 for fa in analyses for f in fa.findings if f.severity == Severity.INFO)

        print(f"\n{'=' * 60}")
        print(f"  SCA Results — {total_vulns} vulnerable dependencies found")
        print(f"  {critical} critical · {warnings} warning · {info} info")
        print(f"{'=' * 60}\n")

        for fa in analyses:
            print(f"  {fa.path}")
            for f in fa.findings:
                sev_tag = f.severity.value.upper()
                color = "\033[91m" if f.severity == Severity.CRITICAL else "\033[93m" if f.severity == Severity.WARNING else "\033[94m"
                reset = "\033[0m"
                print(f"    {color}[{sev_tag}]{reset} {f.message}")
                if f.suggestion:
                    print(f"           → {f.suggestion}")
            print()

        print(f"  Scanned in {elapsed:.1f}s")
        print()

    if any(f.severity == Severity.CRITICAL for fa in analyses for f in fa.findings):
        return 2
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Fix detected issues in code (deterministic + optional LLM)."""
    from ..metrics import end_session, save_session, start_session

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
    from ..discovery import collect_files_with_lang
    from ..fixer import fix_file as fixer_fix_file
    from ..types import FixReport

    files_to_fix = collect_files_with_lang(root, language_filter=lang)

    if not files_to_fix:
        print("No fixable files found.", file=sys.stderr)
        return 0

    if output_format != "json" and not dry_run:
        print(f"Fixing {len(files_to_fix)} file(s) ...")
    elif output_format != "json":
        print(f"Scanning {len(files_to_fix)} file(s) for fixes (dry run) ...")

    # Severity filter
    from ..types import SEVERITY_ORDER as severity_order

    cost_tracker = None
    if use_llm:
        from ..llm import CostTracker

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
