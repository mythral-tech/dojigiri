"""CLI entry point for the `doji` command.

Parses arguments and dispatches to subcommands: scan, debug, optimize,
analyze (project-level), review (PR security review), fix, report, cost,
setup, and hooks. Orchestrates the full pipeline from file discovery through
analysis to output/reporting.

Called by: user (python -m dojigiri / doji command)
Calls into: cli/ package for all subcommand implementations
Data in -> Data out: CLI args -> console output + saved reports
"""

from __future__ import annotations  # noqa

import argparse
import sys
import threading

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


def _add_llm_args(p) -> None:
    """Add common LLM-related arguments to a subparser."""
    p.add_argument("--backend", choices=["anthropic", "ollama", "openai"], default=None, help="LLM backend")
    p.add_argument("--model", default=None, help="LLM model name")
    p.add_argument("--base-url", default=None, help="LLM API base URL")
    p.add_argument("--accept-remote", action="store_true", help="Skip LLM data-sharing confirmation (for CI/CD)")


def _register_scan(subparsers) -> None:
    """Register the scan subcommand."""
    p = subparsers.add_parser("scan", help="Scan code for issues")
    p.add_argument("path", help="File or directory to scan")
    p.add_argument("--deep", action="store_true", help="Deep scan with Claude API (paid)")
    p.add_argument("--diff", nargs="?", const="", default=None, metavar="REF",
                   help="Only scan lines changed vs git ref (default: main/master)")
    p.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p.add_argument("--no-cache", action="store_true", help="Skip file hash cache (rescan all files)")
    p.add_argument("--no-config", action="store_true",
                   help="Ignore .doji.toml project config (use when scanning untrusted code)")
    p.add_argument("--ignore", help="Comma-separated rule names to suppress (e.g., todo-marker,long-line)")
    p.add_argument("--min-severity", choices=["critical", "warning", "info"],
                   help="Minimum severity to display (filters lower)")
    p.add_argument("--min-confidence", choices=["high", "medium", "low"], default=None,
                   help="Minimum LLM confidence to display (default: show all)")
    p.add_argument("--output", choices=["text", "json", "sarif", "html", "pdf"], default="text",
                   help="Output format: text, json, sarif, html, pdf")
    p.add_argument("--output-file", metavar="PATH", help="Write JSON/HTML/PDF output to file instead of stdout")
    p.add_argument("--project-name", metavar="NAME", help="Project name for HTML/PDF reports")
    p.add_argument("--classification", choices=CLASSIFICATION_LEVELS, default=None,
                   help="Classification marking for reports (e.g., CUI, SECRET)")
    p.add_argument("--profile", choices=list(PROFILES.keys()), default=None,
                   help="Compliance profile preset (owasp, dod, ci)")
    p.add_argument("--baseline", help="Compare against baseline (use 'latest' or report path)")
    p.add_argument("--workers", type=int, default=None, metavar="N",
                   help="Number of parallel workers for quick scan (default: 4 or from .doji.toml)")
    p.add_argument("--max-cost", type=float, default=None, metavar="USD",
                   help="Maximum LLM cost in USD before pausing (deep scan only)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_scan)


def _register_fix(subparsers) -> None:
    """Register the fix subcommand."""
    p = subparsers.add_parser("fix", help="Auto-fix detected issues")
    p.add_argument("path", help="File or directory to fix")
    p.add_argument("--apply", action="store_true", help="Actually apply fixes (default is dry-run)")
    p.add_argument("--llm", action="store_true", help="Include LLM-generated fixes (costs money)")
    p.add_argument("--accept-llm-fixes", action="store_true",
                   help="Apply LLM-generated fixes without extra confirmation (use with --apply --llm)")
    p.add_argument("--no-backup", action="store_true",
                   help="Skip creating .doji.bak backup files (backups accumulate and are not auto-cleaned)")
    p.add_argument("--no-verify", action="store_true", help="Skip re-scanning file after applying fixes")
    p.add_argument("--rules", help="Only fix specific rules (comma-separated, e.g., bare-except,var-usage)")
    p.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p.add_argument("--min-severity", choices=["critical", "warning", "info"],
                   help="Only fix issues at this severity or above")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_fix)


def _register_review(subparsers) -> None:
    """Register the review subcommand."""
    p = subparsers.add_parser("review", help="Security review of PR or branch diff")
    p.add_argument("--pr", type=int, default=None, metavar="NUMBER",
                   help="GitHub PR number to review (requires gh CLI)")
    p.add_argument("--base", default=None, metavar="REF", help="Git ref to diff against (default: main/master)")
    p.add_argument("--llm", action="store_true", help="Enrich review with LLM analysis (costs money)")
    p.add_argument("--output", choices=["text", "json", "comment"], default="text",
                   help="Output format: text (terminal), json (structured), comment (GitHub PR comment markdown)")
    p.add_argument("--no-config", action="store_true", help="Ignore .doji.toml project config")
    _add_llm_args(p)
    p.set_defaults(func=cmd_review)


def _register_simple_subcommands(subparsers) -> None:
    """Register simple subcommands with few or no arguments."""
    # init
    p = subparsers.add_parser("init", help="Create starter .doji-ignore file")
    p.set_defaults(func=cmd_init)

    # debug
    p = subparsers.add_parser("debug", help="Debug a specific file (uses Claude API)")
    p.add_argument("file", help="File to debug")
    p.add_argument("--error", "-e", help="Error message or traceback for context")
    p.add_argument("--context", "-c",
                   help="Related files for multi-file debugging: comma-separated paths or 'auto' (Python only)")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_debug)

    # optimize
    p = subparsers.add_parser("optimize", help="Get optimization suggestions (uses Claude API)")
    p.add_argument("file", help="File to optimize")
    p.add_argument("--context", "-c", help="Related files for context: comma-separated paths or 'auto'")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_optimize)

    # analyze
    p = subparsers.add_parser("analyze", help="Analyze project for cross-file issues")
    p.add_argument("path", help="Project directory to analyze")
    p.add_argument("--depth", type=int, default=2, metavar="N", help="Dependency traversal depth (default: 2)")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p.add_argument("--no-llm", action="store_true", help="Graph + metrics only, no API key needed (free)")
    p.add_argument("--lang", help="Filter by language (e.g., python)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_analyze)

    # explain
    p = subparsers.add_parser("explain", help="Explain a code file (beginner-friendly tutorial)")
    p.add_argument("file", help="File to explain")
    p.add_argument("--deep", action="store_true", help="Use LLM for richer explanations (costs money)")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    _add_llm_args(p)
    p.set_defaults(func=cmd_explain)

    # report
    p = subparsers.add_parser("report", help="Show latest scan report")
    p.set_defaults(func=cmd_report)

    # cost
    p = subparsers.add_parser("cost", help="Estimate deep scan cost")
    p.add_argument("path", help="File or directory to estimate")
    p.add_argument("--lang", help="Filter by language")
    p.set_defaults(func=cmd_cost)

    # hook
    p = subparsers.add_parser("hook", help="Manage pre-commit hook")
    p.add_argument("hook_action", choices=["install", "uninstall"], help="Install or uninstall doji pre-commit hook")
    p.add_argument("--force", action="store_true", help="Overwrite existing non-doji hooks")
    p.set_defaults(func=cmd_hook)

    # setup / mcp / stats / rules / setup-claude / clean / privacy / sca
    subparsers.add_parser("setup", help="Check environment setup").set_defaults(func=cmd_setup)
    subparsers.add_parser("mcp", help="Start the MCP server (for Claude Code integration)").set_defaults(func=cmd_mcp)

    p = subparsers.add_parser("stats", help="Show scan/fix metrics history and trends")
    p.add_argument("--days", type=int, default=30, help="How many days of history (default: 30)")
    p.add_argument("--limit", type=int, default=10, help="Number of sessions to show (default: 10)")
    p.set_defaults(func=cmd_stats)

    p = subparsers.add_parser("rules", help="List all available rules")
    p.add_argument("--lang", help="Filter by language (e.g., python, javascript)")
    p.add_argument("--output", choices=["text", "json"], default="text", help="Output format (default: text)")
    p.set_defaults(func=cmd_rules)

    subparsers.add_parser("setup-claude", help="Print MCP config for Claude Code").set_defaults(func=cmd_setup_claude)

    p = subparsers.add_parser("clean", help="Remove .doji.bak backup files and .doji.tmp temp files")
    p.add_argument("path", nargs="?", default=".", help="Directory to clean (default: current directory)")
    p.add_argument("--dry-run", action="store_true", help="Show what would be removed without deleting")
    p.set_defaults(func=cmd_clean)

    subparsers.add_parser("privacy", help="Show data handling and privacy information").set_defaults(func=cmd_privacy)

    p = subparsers.add_parser("sca", help="Scan dependencies for known vulnerabilities (CVEs)")
    p.add_argument("path", nargs="?", default=".", help="Project directory to scan (default: current directory)")
    p.add_argument("--output", choices=["text", "json", "sarif"], default="text", help="Output format")
    p.add_argument("--min-severity", choices=["critical", "warning", "info"], default="info",
                   help="Minimum severity to report")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout for OSV API in seconds (default: 30)")
    p.set_defaults(func=cmd_sca)


def _check_version() -> str | None:
    """Fetch latest version from API. Returns message if update available, None otherwise."""
    try:
        from urllib.request import urlopen
        import json
        with urlopen("https://api.dojigiri.com/health", timeout=3) as resp:  # doji:ignore(url-scheme-audit) — hardcoded https URL
            data = json.loads(resp.read())
        latest = data.get("dojigiri_version", "")
        if latest and latest != __version__:
            return f"\n  Update available: {__version__} → {latest}  —  pip install --upgrade dojigiri-cli\n"
    except Exception:  # doji:ignore(empty-exception-handler) — intentional: version check must never disrupt CLI
        pass
    return None


def main() -> None:
    parser = argparse.ArgumentParser(prog="doji", description="Dojigiri — static analysis engine")
    parser.add_argument("--version", action="version", version=f"dojigiri {__version__}")
    parser.add_argument("--offline", action="store_true",
                        help="Offline mode — block all network/LLM calls (static analysis only)")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    _register_scan(subparsers)
    _register_fix(subparsers)
    _register_review(subparsers)
    _register_simple_subcommands(subparsers)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Non-blocking version check (skipped in offline mode)
    version_msg: list[str | None] = [None]
    if not getattr(args, "offline", False):
        def _bg_check() -> None:
            version_msg[0] = _check_version()
        t = threading.Thread(target=_bg_check, daemon=True)
        t.start()
    else:
        t = None

    try:
        exit_code = args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)

    # Show update notice after command output
    if t is not None:
        t.join(timeout=1)
    if version_msg[0]:
        print(version_msg[0], file=sys.stderr)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
