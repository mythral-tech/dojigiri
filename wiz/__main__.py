"""CLI entry point: scan, debug, optimize, analyze, fix, report, cost, setup."""

import argparse
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .config import get_api_key, Severity, Confidence, LANGUAGE_EXTENSIONS, load_project_config, compile_custom_rules
from .analyzer import scan_quick, scan_deep, scan_diff, cost_estimate, detect_language, filter_report, diff_reports
from .detector import analyze_file_static
from .storage import load_latest_report, load_baseline_report, list_reports
from . import report as rpt

SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
CONFIDENCE_MAP = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


def _confirm_llm_usage(args) -> bool:
    """Confirm that the user consents to sending code to the Anthropic API.

    Returns True if the user accepts (or --accept-remote is set).
    Returns False if declined or non-interactive without --accept-remote.
    """
    if getattr(args, "accept_remote", False):
        return True
    if not sys.stdin.isatty():
        print("Error: LLM features send code to the Anthropic API. "
              "Use --accept-remote to allow this in non-interactive mode.",
              file=sys.stderr)
        return False
    print("Warning: This command will send code snippets to the Anthropic API for analysis.")
    try:
        response = input("Continue? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nError: No input available. "
              "Use --accept-remote to allow LLM usage in non-interactive mode.",
              file=sys.stderr)
        return False
    return response in ("y", "yes")


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
    custom_rules = compile_custom_rules(project_config)

    use_cache = not args.no_cache
    output_format = getattr(args, "output", "text")
    is_json = output_format == "json"

    diff_base = getattr(args, "diff", None)

    # LLM confirmation for deep scan
    if args.deep and not _confirm_llm_usage(args):
        return 1

    try:
        if diff_base is not None:
            # Diff mode: only scan changed lines vs git ref
            try:
                report_obj, resolved_ref = scan_diff(
                    root, base_ref=diff_base if diff_base != "" else None,
                    language_filter=lang, custom_rules=custom_rules,
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
            try:
                report_obj = scan_deep(root, language_filter=lang, use_cache=use_cache,
                                       max_workers=workers, custom_rules=custom_rules)
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
            report_obj = scan_quick(root, language_filter=lang, use_cache=use_cache,
                                    max_workers=workers, custom_rules=custom_rules)
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


def _auto_discover_python_imports(filepath: str, content: str) -> dict[str, str]:
    """Discover local Python imports and read their contents (legacy fallback).

    Parses AST for import/from-import statements, resolves to local files
    in the same directory or relative paths. Returns {filepath: content} dict.
    Caps at 50KB total to avoid blowing token budget.
    """
    import ast as ast_mod

    try:
        tree = ast_mod.parse(content)
    except SyntaxError:
        return {}

    base_dir = Path(filepath).parent
    candidates = set()

    for node in ast_mod.walk(tree):
        if isinstance(node, ast_mod.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                candidates.add(parts[0])
        elif isinstance(node, ast_mod.ImportFrom):
            if node.module and node.level == 0:
                parts = node.module.split(".")
                candidates.add(parts[0])
            elif node.level > 0 and node.module:
                candidates.add(node.module.split(".")[0])

    result = {}
    total_size = 0
    max_size = 50_000

    for mod_name in sorted(candidates):
        mod_path = base_dir / f"{mod_name}.py"
        if mod_path.is_file():
            try:
                mod_content = mod_path.read_text(encoding="utf-8", errors="replace")
                if total_size + len(mod_content) > max_size:
                    break
                result[str(mod_path)] = mod_content
                total_size += len(mod_content)
            except OSError:
                continue

    return result


def _auto_discover_imports_v2(filepath: str, content: str, lang: str) -> dict[str, str]:
    """Enhanced context discovery using depgraph — transitive deps, ranked by importance.

    Falls back to legacy _auto_discover_python_imports if depgraph fails.
    Works for Python, JS, and TS (not just Python).
    """
    try:
        from .graph.depgraph import build_dependency_graph
        from .analyzer import collect_files

        fp = Path(filepath).resolve()
        project_root = fp.parent

        # Try to find the actual project root (look for common markers)
        for parent in [fp.parent] + list(fp.parents):
            if any((parent / marker).exists() for marker in
                   [".git", "pyproject.toml", "setup.py", "package.json", ".wiz.toml"]):
                project_root = parent
                break

        # Collect sibling files in the project
        files, _ = collect_files(project_root, language_filter=lang)
        if not files:
            raise ValueError("No files found")

        graph = build_dependency_graph([str(f) for f in files], str(project_root))

        # Find our file in the graph
        try:
            rel = str(fp.relative_to(project_root)).replace("\\", "/")
        except ValueError:
            raise ValueError("File not in project root")

        if rel not in graph.nodes:
            raise ValueError(f"File {rel} not in graph")

        # Get transitive deps (depth 2) + direct dependents
        deps = graph.get_dependencies(rel, depth=2)
        dependents = graph.get_dependents(rel, depth=1)
        all_related = deps | dependents

        if not all_related:
            return {}

        # Rank by fan_in (most important first)
        ranked = []
        for r in all_related:
            if r in graph.nodes:
                ranked.append((r, graph.nodes[r].fan_in))
        ranked.sort(key=lambda x: (-x[1], x[0]))

        result = {}
        total_size = 0
        max_size = 50_000

        for r, _fi in ranked:
            abs_path = project_root / r
            if abs_path.is_file():
                try:
                    ctx_content = abs_path.read_text(encoding="utf-8", errors="replace")
                    if total_size + len(ctx_content) > max_size:
                        break
                    result[str(abs_path)] = ctx_content
                    total_size += len(ctx_content)
                except OSError:
                    continue

        return result

    except Exception:
        # Fall back to legacy method for Python
        if lang == "python":
            return _auto_discover_python_imports(filepath, content)
        return {}


def _collect_context_files(context_arg: str, filepath: str, lang: str,
                           content: str) -> Optional[dict[str, str]]:
    """Collect context files based on --context argument.

    "auto" → auto-discover imports using depgraph (v2) with legacy fallback
    comma-separated paths → read each file
    """
    if context_arg == "auto":
        return _auto_discover_imports_v2(filepath, content, lang)

    result = {}
    total_size = 0
    max_size = 50_000

    for path_str in context_arg.split(","):
        path_str = path_str.strip()
        if not path_str:
            continue
        ctx_path = Path(path_str).resolve()
        if ctx_path.is_file():
            try:
                ctx_content = ctx_path.read_text(encoding="utf-8", errors="replace")
                if total_size + len(ctx_content) > max_size:
                    print(f"  Skipping {path_str} (context size cap reached)", file=sys.stderr)
                    break
                result[str(ctx_path)] = ctx_content
                total_size += len(ctx_content)
            except OSError as e:
                print(f"  Warning: couldn't read context file {path_str}: {e}", file=sys.stderr)
        else:
            print(f"  Warning: context file not found: {path_str}", file=sys.stderr)

    return result if result else None


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

    if not _confirm_llm_usage(args):
        return 1

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    output_format = getattr(args, "output", "text")

    # Static analysis first
    static_findings = analyze_file_static(str(filepath), content, lang)

    # Collect context files if requested
    context_files = None
    context_arg = getattr(args, "context", None)
    if context_arg:
        context_files = _collect_context_files(context_arg, str(filepath), lang, content)

    # LLM analysis
    if output_format != "json":
        print(f"Analyzing {filepath} with Claude ...\n")

    try:
        from .llm import debug_file
        llm_result, tracker = debug_file(
            content, str(filepath), lang,
            error_msg=args.error,
            static_findings=static_findings,
            context_files=context_files,
        )
        if output_format == "json":
            rpt.print_debug_json(str(filepath), static_findings, llm_result, tracker)
        else:
            rpt.print_debug_result(str(filepath), static_findings, llm_result)
            print(f"  Cost: ${tracker.total_cost:.4f}")
    except Exception as e:
        # Fall back to static-only
        if output_format != "json":
            print(f"LLM error: {e}", file=sys.stderr)
        if output_format == "json":
            rpt.print_debug_json(str(filepath), static_findings, None)
        else:
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

    if not _confirm_llm_usage(args):
        return 1

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    output_format = getattr(args, "output", "text")

    # Static analysis
    static_findings = analyze_file_static(str(filepath), content, lang)

    # Collect context files if requested
    context_files = None
    context_arg = getattr(args, "context", None)
    if context_arg:
        context_files = _collect_context_files(context_arg, str(filepath), lang, content)

    if output_format != "json":
        print(f"Analyzing {filepath} for optimization with Claude ...\n")

    try:
        from .llm import optimize_file
        llm_result, tracker = optimize_file(
            content, str(filepath), lang,
            static_findings=static_findings,
            context_files=context_files,
        )
        if output_format == "json":
            rpt.print_optimize_json(str(filepath), static_findings, llm_result, tracker)
        else:
            rpt.print_optimize_result(str(filepath), static_findings, llm_result)
            print(f"  Cost: ${tracker.total_cost:.4f}")
    except Exception as e:
        if output_format != "json":
            print(f"LLM error: {e}", file=sys.stderr)
        if output_format == "json":
            rpt.print_optimize_json(str(filepath), static_findings, None)
        else:
            rpt.print_optimize_result(str(filepath), static_findings)

    return 0


def cmd_fix(args):
    """Fix detected issues in code (deterministic + optional LLM)."""
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

    if use_llm and not _confirm_llm_usage(args):
        return 1

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

    from .fixer import fix_file as fixer_fix_file
    from .config import FixReport

    # Collect files to fix
    if root.is_file():
        file_lang = detect_language(root)
        if not file_lang:
            print(f"Error: unsupported file type '{root.suffix}'", file=sys.stderr)
            return 1
        files_to_fix = [(root, file_lang)]
    else:
        from .analyzer import collect_files
        collected, _ = collect_files(root, language_filter=lang)
        files_to_fix = []
        for fp in collected:
            fl = detect_language(fp)
            if fl:
                files_to_fix.append((fp, fl))

    if not files_to_fix:
        print("No fixable files found.", file=sys.stderr)
        return 0

    if output_format != "json" and not dry_run:
        print(f"Fixing {len(files_to_fix)} file(s) ...")
    elif output_format != "json":
        print(f"Scanning {len(files_to_fix)} file(s) for fixes (dry run) ...")

    # Severity filter helper
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}

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

        # Get findings via static analysis
        findings = analyze_file_static(str(filepath), content, file_lang)

        # Apply severity filter
        if min_severity:
            min_ord = severity_order[min_severity]
            findings = [f for f in findings if severity_order[f.severity] <= min_ord]

        if not findings:
            continue

        report = fixer_fix_file(
            str(filepath), content, file_lang, findings,
            use_llm=use_llm, dry_run=dry_run,
            create_backup=create_backup, rules=rules,
            cost_tracker=cost_tracker,
            verify=verify, custom_rules=custom_rules,
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
            aggregate_verification["new_findings"].extend(report.verification.get("new_findings", []))

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

    return 0


def cmd_analyze(args):
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

    if use_llm and not _confirm_llm_usage(args):
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
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if output_format == "json":
        rpt.print_project_json(analysis)
    else:
        rpt.print_project_analysis(analysis)

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


def cmd_hook(args):
    """Install or uninstall wiz pre-commit hook."""
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


def cmd_explain(args):
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

    if deep and not _confirm_llm_usage(args):
        return 1

    # Static analysis for findings context
    static_findings = analyze_file_static(str(filepath), content, lang)

    # Extract semantics
    from .semantic.core import extract_semantics
    semantics = extract_semantics(content, str(filepath), lang)

    # Type inference
    type_map = None
    if semantics:
        from .semantic.lang_config import get_config
        config = get_config(lang)
        if config:
            from .semantic.types import infer_types
            source_bytes = content.encode("utf-8")
            type_map = infer_types(semantics, source_bytes, config)

    # Generate explanation
    from .semantic.explain import explain_file
    explanation = explain_file(
        content, str(filepath), lang,
        semantics=semantics,
        findings=static_findings,
        type_map=type_map,
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
                from .llm import explain_file_llm, CostTracker
                tracker = CostTracker()
                llm_result, tracker = explain_file_llm(
                    content, str(filepath), lang,
                    static_findings=static_findings,
                    cost_tracker=tracker,
                )
                if llm_result and output_format != "json":
                    print(f"\n{'=' * 70}")
                    print("  Deep Analysis (LLM-powered)")
                    print(f"{'=' * 70}\n")
                    if isinstance(llm_result, dict):
                        for key, value in llm_result.items():
                            if value:
                                print(f"  {key}:")
                                print(f"    {value}\n")
                    print(f"  Cost: ${tracker.total_cost:.4f}")
        except Exception as e:
            if output_format != "json":
                print(f"\n  LLM analysis unavailable: {e}", file=sys.stderr)

    return 0


def cmd_setup(args):
    """Check environment setup."""
    api_key_set = get_api_key() is not None

    anthropic_installed = False
    try:
        import anthropic  # noqa: F401
        anthropic_installed = True
    except ImportError:
        pass

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
    p_scan.add_argument("--diff", nargs="?", const="", default=None, metavar="REF",
                         help="Only scan lines changed vs git ref (default: main/master)")
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
    p_scan.add_argument("--accept-remote", action="store_true",
                         help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_scan.set_defaults(func=cmd_scan)

    # debug
    p_debug = subparsers.add_parser("debug", help="Debug a specific file (uses Claude API)")
    p_debug.add_argument("file", help="File to debug")
    p_debug.add_argument("--error", "-e", help="Error message or traceback for context")
    p_debug.add_argument("--context", "-c",
                         help="Related files for multi-file debugging: comma-separated paths or 'auto' (Python only)")
    p_debug.add_argument("--output", choices=["text", "json"], default="text",
                         help="Output format (default: text)")
    p_debug.add_argument("--accept-remote", action="store_true",
                         help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_debug.set_defaults(func=cmd_debug)

    # optimize
    p_opt = subparsers.add_parser("optimize", help="Get optimization suggestions (uses Claude API)")
    p_opt.add_argument("file", help="File to optimize")
    p_opt.add_argument("--context", "-c",
                       help="Related files for context: comma-separated paths or 'auto'")
    p_opt.add_argument("--output", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    p_opt.add_argument("--accept-remote", action="store_true",
                       help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_opt.set_defaults(func=cmd_optimize)

    # fix
    p_fix = subparsers.add_parser("fix", help="Auto-fix detected issues")
    p_fix.add_argument("path", help="File or directory to fix")
    p_fix.add_argument("--apply", action="store_true",
                        help="Actually apply fixes (default is dry-run)")
    p_fix.add_argument("--llm", action="store_true",
                        help="Include LLM-generated fixes (costs money)")
    p_fix.add_argument("--no-backup", action="store_true",
                        help="Skip creating .wiz.bak backup files (backups accumulate and are not auto-cleaned)")
    p_fix.add_argument("--no-verify", action="store_true",
                        help="Skip re-scanning file after applying fixes")
    p_fix.add_argument("--rules",
                        help="Only fix specific rules (comma-separated, e.g., bare-except,var-usage)")
    p_fix.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p_fix.add_argument("--min-severity", choices=["critical", "warning", "info"],
                        help="Only fix issues at this severity or above")
    p_fix.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    p_fix.add_argument("--accept-remote", action="store_true",
                        help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_fix.set_defaults(func=cmd_fix)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze project for cross-file issues")
    p_analyze.add_argument("path", help="Project directory to analyze")
    p_analyze.add_argument("--depth", type=int, default=2, metavar="N",
                           help="Dependency traversal depth (default: 2)")
    p_analyze.add_argument("--output", choices=["text", "json"], default="text",
                           help="Output format (default: text)")
    p_analyze.add_argument("--no-llm", action="store_true",
                           help="Graph + metrics only, no API key needed (free)")
    p_analyze.add_argument("--lang", help="Filter by language (e.g., python)")
    p_analyze.add_argument("--accept-remote", action="store_true",
                           help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_analyze.set_defaults(func=cmd_analyze)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain a code file (beginner-friendly tutorial)")
    p_explain.add_argument("file", help="File to explain")
    p_explain.add_argument("--deep", action="store_true",
                           help="Use LLM for richer explanations (costs money)")
    p_explain.add_argument("--output", choices=["text", "json"], default="text",
                           help="Output format (default: text)")
    p_explain.add_argument("--accept-remote", action="store_true",
                           help="Skip LLM data-sharing confirmation (for CI/CD)")
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
    p_hook.add_argument("hook_action", choices=["install", "uninstall"],
                         help="Install or uninstall wiz pre-commit hook")
    p_hook.add_argument("--force", action="store_true",
                         help="Overwrite existing non-wiz hooks")
    p_hook.set_defaults(func=cmd_hook)

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
