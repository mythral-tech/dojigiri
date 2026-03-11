"""Tests for dojigiri/context.py — context file discovery."""

import pytest
from pathlib import Path

from dojigiri.context import (
    auto_discover_python_imports,
    collect_context_files,
)


class TestAutoDiscoverPythonImports:
    def test_finds_local_imports(self, tmp_path):
        # Create a module to import
        helper = tmp_path / "helper.py"
        helper.write_text("def greet(): pass\n", encoding="utf-8")

        main_file = tmp_path / "main.py"
        content = "import helper\nhelper.greet()\n"
        main_file.write_text(content, encoding="utf-8")

        result = auto_discover_python_imports(str(main_file), content)
        assert str(helper) in result
        assert "def greet" in result[str(helper)]

    def test_from_import(self, tmp_path):
        mod = tmp_path / "utils.py"
        mod.write_text("x = 1\n", encoding="utf-8")

        main = tmp_path / "main.py"
        content = "from utils import x\n"
        main.write_text(content, encoding="utf-8")

        result = auto_discover_python_imports(str(main), content)
        assert str(mod) in result

    def test_syntax_error_returns_empty(self):
        result = auto_discover_python_imports("test.py", "def bad(\n")
        assert result == {}

    def test_no_local_files(self, tmp_path):
        main = tmp_path / "main.py"
        content = "import os\nimport sys\n"
        main.write_text(content, encoding="utf-8")
        result = auto_discover_python_imports(str(main), content)
        assert result == {}

    def test_relative_import(self, tmp_path):
        mod = tmp_path / "sibling.py"
        mod.write_text("y = 2\n", encoding="utf-8")

        main = tmp_path / "main.py"
        content = "from .sibling import y\n"
        main.write_text(content, encoding="utf-8")

        result = auto_discover_python_imports(str(main), content)
        assert str(mod) in result


class TestCollectContextFiles:
    def test_auto_mode(self, tmp_path):
        helper = tmp_path / "helper.py"
        helper.write_text("x = 1\n", encoding="utf-8")

        main = tmp_path / "main.py"
        content = "import helper\n"
        main.write_text(content, encoding="utf-8")

        result = collect_context_files("auto", str(main), "python", content)
        assert result is not None
        assert str(helper) in result

    def test_explicit_paths(self, tmp_path):
        ctx_file = tmp_path / "context.py"
        ctx_file.write_text("CTX = True\n", encoding="utf-8")

        result = collect_context_files(str(ctx_file), "main.py", "python", "x = 1\n")
        assert result is not None
        assert "CTX = True" in list(result.values())[0]

    def test_nonexistent_file(self, tmp_path, capsys):
        result = collect_context_files(
            str(tmp_path / "nonexistent.py"), "main.py", "python", "x = 1"
        )
        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_empty_path_stripped(self, tmp_path):
        ctx = tmp_path / "a.py"
        ctx.write_text("x=1\n", encoding="utf-8")
        result = collect_context_files(f"{ctx}, , ", "main.py", "python", "x=1")
        assert result is not None
