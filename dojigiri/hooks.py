"""Git pre-commit hook management — install and uninstall doji hooks.

Writes a shell script into .git/hooks/pre-commit that runs doji on staged
files before each commit. Detects bundled exe vs. pip install for the command.

Called by: __main__.py
Calls into: config.py (is_bundled, get_exe_path)
Data in -> Data out: git repo path -> hook file written/removed on disk
"""

import re
import stat
import sys
from pathlib import Path

from .bundling import get_exe_path, is_bundled

HOOK_MARKER = "# doji-managed-hook"

# Shell metacharacters that must never appear unquoted in a hook script.
# Even with quoting, some characters (backtick, $, !) can break out of
# single quotes in certain shells, so we reject paths containing them.
_SHELL_UNSAFE_RE = re.compile(r"[`$!\\]")


def _shell_quote(s: str) -> str:
    """Shell-quote a string using single quotes (POSIX-safe).

    Handles embedded single quotes by ending the quoted segment,
    inserting an escaped single quote, and re-opening.
    Example: /it's/path -> '/it'"'"'s/path'
    """
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _doji_command() -> str:
    """Return the shell command to invoke doji, depending on install mode.

    SECURITY: In bundled mode, the exe path is shell-quoted to prevent
    injection via directory names containing spaces or metacharacters.
    Paths with truly dangerous characters ($, `, !, \\) are rejected
    outright since they can break out of quoting in some shells.
    """
    if is_bundled():
        raw_path = str(get_exe_path())
        if _SHELL_UNSAFE_RE.search(raw_path):
            raise ValueError(
                f"Refusing to install hook — exe path contains shell metacharacters: {raw_path!r}. "
                "Move the binary to a path without $, `, !, or \\ characters."
            )
        return _shell_quote(raw_path)
    return "python -m dojigiri"


def _make_hook_script() -> str:
    """Generate the hook script with the correct doji invocation.

    SECURITY: The command is shell-quoted by _doji_command() to prevent
    injection via paths with spaces or special characters. Paths with
    truly dangerous metacharacters are rejected before reaching here.
    """
    cmd = _doji_command()
    # For the uninstall hint shown in comments, strip quotes for readability
    # (comments are not executed, so no injection risk)
    cmd_display = cmd.strip("'")
    uninstall_hint = f"{cmd_display} hook uninstall"
    return f"""\
#!/bin/sh
# doji-managed-hook
# Pre-commit hook installed by dojigiri — blocks commits with critical issues.
# To uninstall: {uninstall_hint}

{cmd} scan . --diff --min-severity warning --output text
status=$?

if [ $status -eq 2 ]; then
    echo ""
    echo "dojigiri: critical issues found — commit blocked."
    echo "Fix them or bypass with: git commit --no-verify"
    exit 1
fi

exit 0
"""


def _find_git_root(path: Path) -> Path:
    """Walk up from path to find .git directory."""
    current = path.resolve()
    while current != current.parent:
        if (current / ".git").is_dir():
            return current
        current = current.parent
    raise FileNotFoundError("Not inside a git repository")


def _hook_path(git_root: Path) -> Path:
    """Return path to pre-commit hook."""
    return git_root / ".git" / "hooks" / "pre-commit"


def _is_doji_hook(path: Path) -> bool:
    """Check if existing hook was installed by dojigiri."""
    if not path.exists():
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return HOOK_MARKER in content
    except OSError:
        return False


def install_hook(root: Path, force: bool = False) -> str:
    """Install doji pre-commit hook.

    Args:
        root: Directory inside a git repo
        force: Overwrite existing non-doji hooks

    Returns:
        Status message string.

    Raises:
        FileNotFoundError: Not a git repository
        FileExistsError: Hook exists and is not a doji hook (unless force=True)
    """
    git_root = _find_git_root(root)
    hook = _hook_path(git_root)

    # Create hooks directory if needed
    hook.parent.mkdir(parents=True, exist_ok=True)

    if hook.exists():
        if _is_doji_hook(hook):
            # Update existing doji hook
            hook.write_text(_make_hook_script(), encoding="utf-8")
            return f"Updated doji pre-commit hook at {hook}"
        elif not force:
            raise FileExistsError(
                f"Pre-commit hook already exists at {hook} (not managed by dojigiri). Use --force to overwrite."
            )
        # force=True: overwrite foreign hook

    hook.write_text(_make_hook_script(), encoding="utf-8")

    # Make executable (Unix)
    if sys.platform != "win32":
        hook.chmod(hook.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return f"Installed doji pre-commit hook at {hook}"


def uninstall_hook(root: Path) -> str:
    """Remove doji pre-commit hook.

    Only removes hooks that have the doji marker. Refuses to delete
    hooks installed by other tools.

    Returns:
        Status message string.

    Raises:
        FileNotFoundError: Not a git repository or no hook exists
        PermissionError: Hook exists but was not installed by dojigiri
    """
    git_root = _find_git_root(root)
    hook = _hook_path(git_root)

    if not hook.exists():
        raise FileNotFoundError("No pre-commit hook found")

    if not _is_doji_hook(hook):
        raise PermissionError(
            "Pre-commit hook exists but was not installed by dojigiri. Refusing to remove a foreign hook."
        )

    hook.unlink()
    return f"Removed doji pre-commit hook from {hook}"
