"""Tests for context module — file discovery and import resolution."""

import pytest
from pathlib import Path

from dojigiri.context import (
    auto_discover_python_imports,
    auto_discover_imports,
    collect_context_files,
    _MAX_CONTEXT_BYTES,
)


# ─── auto_discover_python_imports ─────────────────────────────────────


def test_discover_python_import_local_module(tmp_path):
    """Discovers a local module imported via `import helpers`."""
    main = tmp_path / "main.py"
    helpers = tmp_path / "helpers.py"
    main.write_text("import helpers\n\nhelpers.do_stuff()\n", encoding="utf-8")
    helpers.write_text("def do_stuff(): pass\n", encoding="utf-8")

    result = auto_discover_python_imports(str(main), main.read_text(encoding="utf-8"))
    assert str(helpers) in result
    assert "do_stuff" in result[str(helpers)]


def test_discover_python_from_import(tmp_path):
    """Discovers a local module imported via `from utils import func`."""
    main = tmp_path / "main.py"
    utils = tmp_path / "utils.py"
    main.write_text("from utils import something\n", encoding="utf-8")
    utils.write_text("something = 42\n", encoding="utf-8")

    result = auto_discover_python_imports(str(main), main.read_text(encoding="utf-8"))
    assert str(utils) in result


def test_discover_python_skips_stdlib(tmp_path):
    """Standard library imports (os, sys) should not produce results."""
    main = tmp_path / "main.py"
    main.write_text("import os\nimport sys\nimport json\n", encoding="utf-8")

    result = auto_discover_python_imports(str(main), main.read_text(encoding="utf-8"))
    # os.py, sys.py, json.py don't exist in tmp_path
    assert len(result) == 0


def test_discover_python_syntax_error():
    """Syntax errors in the file produce an empty result."""
    result = auto_discover_python_imports("/fake/broken.py", "def broken(\n")
    assert result == {}


def test_discover_python_respects_size_cap(tmp_path):
    """Context discovery stops before exceeding _MAX_CONTEXT_BYTES."""
    main = tmp_path / "main.py"
    # Create two large modules that together exceed the cap
    mod_a = tmp_path / "aaa.py"
    mod_b = tmp_path / "bbb.py"
    main.write_text("import aaa\nimport bbb\n", encoding="utf-8")
    # Each module is slightly over half the cap
    big_content = "x = 1\n" * (_MAX_CONTEXT_BYTES // 6 + 1000)
    mod_a.write_text(big_content, encoding="utf-8")
    mod_b.write_text(big_content, encoding="utf-8")

    result = auto_discover_python_imports(str(main), main.read_text(encoding="utf-8"))
    total = sum(len(v) for v in result.values())
    assert total <= _MAX_CONTEXT_BYTES


# ─── collect_context_files ────────────────────────────────────────────


def test_collect_context_auto_mode(tmp_path):
    """Auto mode discovers local imports."""
    main = tmp_path / "main.py"
    helper = tmp_path / "helper.py"
    main.write_text("import helper\n", encoding="utf-8")
    helper.write_text("def help(): pass\n", encoding="utf-8")

    result = collect_context_files("auto", str(main), "python", main.read_text(encoding="utf-8"))
    assert result is not None
    assert any("helper" in k for k in result)


def test_collect_context_explicit_paths(tmp_path):
    """Comma-separated paths are read directly."""
    ctx_file = tmp_path / "extra.py"
    ctx_file.write_text("extra_data = True\n", encoding="utf-8")

    result = collect_context_files(str(ctx_file), "/fake/main.py", "python", "")
    assert result is not None
    assert str(ctx_file.resolve()) in result


def test_collect_context_missing_file(tmp_path, capsys):
    """Missing context file prints a warning and returns None."""
    result = collect_context_files(
        str(tmp_path / "nonexistent.py"),
        "/fake/main.py", "python", "",
    )
    assert result is None
    captured = capsys.readouterr()
    assert "not found" in captured.err


def test_collect_context_empty_string():
    """Empty context arg returns None."""
    result = collect_context_files("", "/fake/main.py", "python", "")
    assert result is None
