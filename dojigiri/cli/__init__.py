"""CLI subcommand package — re-exports all cmd_* functions for the main dispatcher."""

from .common import SEVERITY_MAP, _apply_profile, _confirm_llm_usage, _setup_llm_backend  # doji:ignore(unused-import) — re-export
from .llm import cmd_debug, cmd_explain, cmd_optimize  # doji:ignore(unused-import) — re-export
from .project import cmd_analyze, cmd_fix, cmd_review, cmd_sca  # doji:ignore(unused-import) — re-export
from .scan import cmd_clean, cmd_cost, cmd_report, cmd_scan, cmd_stats  # doji:ignore(unused-import) — re-export
from .setup import cmd_hook, cmd_init, cmd_mcp, cmd_privacy, cmd_rules, cmd_setup, cmd_setup_claude  # doji:ignore(unused-import) — re-export

__all__ = [
    "SEVERITY_MAP",
    "_apply_profile",
    "_confirm_llm_usage",
    "_setup_llm_backend",
    "cmd_analyze",
    "cmd_clean",
    "cmd_cost",
    "cmd_debug",
    "cmd_explain",
    "cmd_fix",
    "cmd_hook",
    "cmd_init",
    "cmd_mcp",
    "cmd_optimize",
    "cmd_privacy",
    "cmd_report",
    "cmd_review",
    "cmd_rules",
    "cmd_scan",
    "cmd_sca",
    "cmd_setup",
    "cmd_setup_claude",
    "cmd_stats",
]
