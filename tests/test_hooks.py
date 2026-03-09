"""Tests for hooks module — git pre-commit hook install/uninstall."""

import stat
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

from dojigiri.hooks import (
    _shell_quote,
    _doji_command,
    _find_git_root,
    _hook_path,
    _is_doji_hook,
    _make_hook_script,
    install_hook,
    uninstall_hook,
    HOOK_MARKER,
    _SHELL_UNSAFE_RE,
)


# ─── Shell quoting ────────────────────────────────────────────────────


def test_shell_quote_simple():
    """Simple string gets wrapped in single quotes."""
    assert _shell_quote("/usr/bin/doji") == "'/usr/bin/doji'"


def test_shell_quote_with_spaces():
    """Paths with spaces are properly quoted."""
    assert _shell_quote("/path with spaces/doji") == "'/path with spaces/doji'"


def test_shell_quote_with_single_quote():
    """Embedded single quotes are escaped correctly."""
    result = _shell_quote("/it's/path")
    # Should produce: '/it'"'"'s/path'
    assert "'" in result
    assert "it" in result
    assert "s/path" in result
    # Validate it's a valid shell-safe construction
    assert result == "'/it'\"'\"'s/path'"


# ─── Shell unsafe regex ──────────────────────────────────────────────


def test_shell_unsafe_regex_backtick():
    """Backtick in path is detected as unsafe."""
    assert _SHELL_UNSAFE_RE.search("/path/with`cmd`/doji")


def test_shell_unsafe_regex_dollar():
    """Dollar sign in path is detected as unsafe."""
    assert _SHELL_UNSAFE_RE.search("/path/$HOME/doji")


def test_shell_unsafe_regex_safe_path():
    """Normal path with spaces passes safety check."""
    assert _SHELL_UNSAFE_RE.search("/normal path/to/doji") is None


# ─── Hook install/uninstall with tmp_path ─────────────────────────────


@pytest.fixture
def fake_git_repo(tmp_path):
    """Create a fake git repo structure."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir()
    return tmp_path


def test_install_hook_creates_file(fake_git_repo):
    """install_hook writes a pre-commit hook file."""
    with patch("dojigiri.hooks.is_bundled", return_value=False):
        result = install_hook(fake_git_repo)
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    content = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in content
    assert "Installed" in result


def test_install_hook_update_existing_doji_hook(fake_git_repo):
    """Reinstalling overwrites an existing doji hook."""
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\n{HOOK_MARKER}\nold content\n", encoding="utf-8")

    with patch("dojigiri.hooks.is_bundled", return_value=False):
        result = install_hook(fake_git_repo)
    assert "Updated" in result
    content = hook.read_text(encoding="utf-8")
    assert "old content" not in content
    assert "doji" in content


def test_install_hook_refuses_foreign_hook(fake_git_repo):
    """install_hook refuses to overwrite a non-doji hook without --force."""
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'foreign hook'\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="not managed by dojigiri"):
        with patch("dojigiri.hooks.is_bundled", return_value=False):
            install_hook(fake_git_repo)


def test_install_hook_force_overwrites_foreign(fake_git_repo):
    """install_hook with force=True overwrites a foreign hook."""
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'foreign hook'\n", encoding="utf-8")

    with patch("dojigiri.hooks.is_bundled", return_value=False):
        result = install_hook(fake_git_repo, force=True)
    content = hook.read_text(encoding="utf-8")
    assert HOOK_MARKER in content
    assert "Installed" in result


def test_uninstall_hook_removes_doji_hook(fake_git_repo):
    """uninstall_hook removes a doji-managed hook."""
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\n{HOOK_MARKER}\ndoji scan\n", encoding="utf-8")

    result = uninstall_hook(fake_git_repo)
    assert not hook.exists()
    assert "Removed" in result


def test_uninstall_hook_refuses_foreign(fake_git_repo):
    """uninstall_hook refuses to remove a non-doji hook."""
    hook = fake_git_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'foreign'\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="not installed by dojigiri"):
        uninstall_hook(fake_git_repo)


def test_uninstall_hook_no_hook(fake_git_repo):
    """uninstall_hook raises when no hook exists."""
    with pytest.raises(FileNotFoundError, match="No pre-commit hook found"):
        uninstall_hook(fake_git_repo)


def test_find_git_root_not_a_repo(tmp_path):
    """_find_git_root raises FileNotFoundError when not in a git repo."""
    with pytest.raises(FileNotFoundError, match="Not inside a git repository"):
        _find_git_root(tmp_path)


def test_doji_command_pip_mode():
    """In non-bundled mode, _doji_command returns python -m dojigiri."""
    with patch("dojigiri.hooks.is_bundled", return_value=False):
        assert _doji_command() == "python -m dojigiri"


def test_doji_command_bundled_with_unsafe_path():
    """Bundled mode rejects paths with shell metacharacters."""
    with patch("dojigiri.hooks.is_bundled", return_value=True), \
         patch("dojigiri.hooks.get_exe_path", return_value=Path("/path/$bad/doji")):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _doji_command()
