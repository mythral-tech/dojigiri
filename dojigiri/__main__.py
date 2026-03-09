"""CLI entry point for the `doji` command.

Parses arguments and dispatches to subcommands: scan, debug, optimize,
analyze (project-level), review (PR security review), fix, report, cost,
setup, and hooks. Orchestrates the full pipeline from file discovery through
analysis to output/reporting.

Called by: user (python -m dojigiri / doji command)
Calls into: cli/ package for all subcommand implementations
Data in -> Data out: CLI args -> console output + saved reports
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .cli import (
    cmd_analyze,
    cmd_clean,
    cmd_cost,
    cmd_debug,
    cmd_explain,
    cmd_fix,
    cmd_hook,
    cmd_init,
    cmd_mcp,
    cmd_optimize,
    cmd_privacy,
    cmd_report,
    cmd_review,
    cmd_rules,
    cmd_sca,
    cmd_scan,
    cmd_setup,
    cmd_setup_claude,
    cmd_stats,
)
from .config import CLASSIFICATION_LEVELS, PROFILES


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

    # review
    p_review = subparsers.add_parser("review", help="Security review of PR or branch diff")
    p_review.add_argument(
        "--pr",
        type=int,
        default=None,
        metavar="NUMBER",
        help="GitHub PR number to review (requires gh CLI)",
    )
    p_review.add_argument("--base", default=None, metavar="REF", help="Git ref to diff against (default: main/master)")
    p_review.add_argument("--llm", action="store_true", help="Enrich review with LLM analysis (costs money)")
    p_review.add_argument(
        "--output",
        choices=["text", "json", "comment"],
        default="text",
        help="Output format: text (terminal), json (structured), comment (GitHub PR comment markdown)",
    )
    p_review.add_argument(
        "--no-config", action="store_true", help="Ignore .doji.toml project config"
    )
    p_review.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p_review.add_argument("--model", default=None, help="LLM model name")
    p_review.add_argument("--base-url", default=None, help="LLM API base URL")
    p_review.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")
    p_review.set_defaults(func=cmd_review)

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

    # sca
    p_sca = subparsers.add_parser("sca", help="Scan dependencies for known vulnerabilities (CVEs)")
    p_sca.add_argument("path", nargs="?", default=".", help="Project directory to scan (default: current directory)")
    p_sca.add_argument("--output", choices=["text", "json", "sarif"], default="text", help="Output format")
    p_sca.add_argument("--min-severity", choices=["critical", "warning", "info"], default="info", help="Minimum severity to report")
    p_sca.add_argument("--timeout", type=int, default=30, help="HTTP timeout for OSV API in seconds (default: 30)")
    p_sca.set_defaults(func=cmd_sca)

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
