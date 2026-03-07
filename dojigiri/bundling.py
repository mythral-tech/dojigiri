"""Nuitka/bundled-mode utilities.

Handles detection and patching for standalone .exe builds.

Called by: __init__.py, hooks.py, __main__.py
Calls into: nothing (pure stdlib)
Data in → Data out: no I/O; runtime detection helpers.
"""

import sys
from pathlib import Path


def is_bundled() -> bool:
    """Return True if running as a Nuitka-compiled standalone binary."""
    return "__compiled__" in globals() or getattr(sys, "frozen", False)


def get_exe_path() -> Path:
    """Return the path to the running executable (for bundled mode)."""
    return Path(sys.executable).resolve()


def patch_tree_sitter_for_bundled() -> None:
    """Pre-load tree-sitter .pyd bindings into sys.modules for Nuitka onefile mode.

    In bundled mode, the .pyd data files are extracted to a temp directory.
    Nuitka's import system doesn't know about them (they're data files, not
    compiled modules), so import_module() fails. We use spec_from_file_location
    to manually load each .pyd and register it in sys.modules before any
    tree-sitter code runs.
    """
    if not is_bundled():
        return

    import importlib
    import importlib.util

    try:
        tslp = importlib.import_module("tree_sitter_language_pack")
    except ImportError:
        return

    tslp_file = getattr(tslp, "__file__", None)
    if not tslp_file:
        return

    bindings_dir = Path(tslp_file).parent / "bindings"
    if not bindings_dir.is_dir():
        return

    # Pre-load each .pyd binding into sys.modules so import_module() finds them
    for pyd_path in bindings_dir.glob("*.pyd"):
        lang_name = pyd_path.stem  # e.g. "python", "javascript"
        mod_name = f"tree_sitter_language_pack.bindings.{lang_name}"
        if mod_name in sys.modules:
            continue
        spec = importlib.util.spec_from_file_location(mod_name, str(pyd_path))
        if spec and spec.loader:
            try:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)
            except Exception:
                sys.modules.pop(mod_name, None)
