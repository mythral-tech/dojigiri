"""LLM-powered commands: debug, optimize, explain."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import report as rpt
from ..config import get_api_key
from ..context import collect_context_files as _collect_context_files
from ..detector import analyze_file_static
from ..discovery import detect_language
from .common import _confirm_llm_usage, _setup_llm_backend


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
        from .. import llm as _llm

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
        print_json=rpt.print_analysis_json,
        error_msg=args.error,
    )


def cmd_optimize(args: argparse.Namespace) -> int:
    """Optimize a specific file (always uses LLM)."""
    return _run_llm_subcommand(
        args,
        llm_func_name="optimize_file",
        status_msg="Analyzing {} for optimization with Claude ...\n",
        print_text=rpt.print_optimize_result,
        print_json=rpt.print_analysis_json,
    )


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
    from ..semantic.explain import explain_file

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
                from ..llm import CostTracker, explain_file_llm

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
