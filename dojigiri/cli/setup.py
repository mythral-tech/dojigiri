"""Setup and config commands: setup, setup-claude, mcp, hook, init, privacy, rules."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .. import report as rpt
from ..bundling import get_exe_path, is_bundled
from ..config import DEFAULT_DOJI_IGNORE as _DEFAULT_DOJI_IGNORE
from ..config import get_api_key

logger = logging.getLogger(__name__)


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
        from ..mcp_server import mcp as mcp_app
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


def cmd_hook(args: argparse.Namespace) -> int:
    """Install or uninstall doji pre-commit hook."""
    from ..hooks import install_hook, uninstall_hook

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


def cmd_privacy(args: argparse.Namespace) -> int:
    """Show privacy and data handling information."""
    privacy_path = Path(__file__).parent.parent.parent / "PRIVACY.md"
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

    from ..languages import list_all_rules

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
