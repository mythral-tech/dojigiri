"""Shared helpers for CLI subcommand modules."""

from __future__ import annotations

import argparse
import sys

from ..config import PROFILES, get_llm_config
from ..types import Confidence, Severity

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
    from ..plugin import require_llm_plugin

    llm = require_llm_plugin()
    set_backend_config = llm.set_backend_config

    llm_config = get_llm_config(project_config)

    # CLI args override
    if getattr(args, "backend", None):
        llm_config["backend"] = args.backend
    if getattr(args, "model", None):
        llm_config["model"] = args.model
    if getattr(args, "base_url", None):
        llm_config["base_url"] = args.base_url

    set_backend_config(llm_config)
