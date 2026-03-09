"""CLI subcommand package — re-exports all cmd_* functions for the main dispatcher."""

from .common import CONFIDENCE_MAP, SEVERITY_MAP, _apply_profile, _confirm_llm_usage, _setup_llm_backend
from .llm import cmd_debug, cmd_explain, cmd_optimize
from .project import cmd_analyze, cmd_fix, cmd_review, cmd_sca
from .scan import cmd_clean, cmd_cost, cmd_report, cmd_scan, cmd_stats
from .setup import cmd_hook, cmd_init, cmd_mcp, cmd_privacy, cmd_rules, cmd_setup, cmd_setup_claude

__all__ = [
    "CONFIDENCE_MAP",
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
