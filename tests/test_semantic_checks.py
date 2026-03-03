"""Tests for tree-sitter cross-language AST checks."""

import pytest
from unittest.mock import patch

from wiz.config import Severity, Category, Source
from wiz.semantic.lang_config import get_config, LANGUAGE_CONFIGS
from wiz.semantic.checks import (
    run_tree_sitter_checks,
    check_unused_imports,
    check_unreachable_code,
    check_empty_catch,
    check_shadowed_builtins,
    check_function_complexity,
    check_too_many_args,
    check_mutable_defaults,
)

# Check if tree-sitter is available
try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


def _parse(code: str, language: str):
    """Parse code and return (tree, source_bytes, config)."""
    config = get_config(language)
    parser = get_parser(config.ts_language_name)
    source_bytes = code.encode("utf-8")
    tree = parser.parse(source_bytes)
    return tree, source_bytes, config


# ───────────────────────────────────────────────────────────────────────────
# LANGUAGE CONFIG TESTS
# ───────────────────────────────────────────────────────────────────────────

class TestLanguageConfig:
    def test_python_config_exists(self):
        config = get_config("python")
        assert config is not None
        assert config.ts_language_name == "python"

    def test_javascript_config_exists(self):
        config = get_config("javascript")
        assert config is not None
        assert config.ts_language_name == "javascript"

    def test_typescript_config_exists(self):
        config = get_config("typescript")
        assert config is not None
        assert config.ts_language_name == "typescript"

    def test_go_config_exists(self):
        config = get_config("go")
        assert config is not None
        assert config.ts_language_name == "go"

    def test_rust_config_exists(self):
        config = get_config("rust")
        assert config is not None
        assert config.ts_language_name == "rust"

    def test_java_config_exists(self):
        config = get_config("java")
        assert config is not None
        assert config.ts_language_name == "java"

    def test_csharp_config_exists(self):
        config = get_config("csharp")
        assert config is not None
        assert config.ts_language_name == "csharp"

    def test_unknown_language_returns_none(self):
        assert get_config("brainfuck") is None
        assert get_config("") is None

    def test_all_configs_have_function_types(self):
        for lang, config in LANGUAGE_CONFIGS.items():
            assert len(config.function_node_types) > 0, f"{lang} has no function_node_types"

    def test_all_configs_have_return_types(self):
        for lang, config in LANGUAGE_CONFIGS.items():
            assert len(config.return_node_types) > 0, f"{lang} has no return_node_types"


# ───────────────────────────────────────────────────────────────────────────
# UNUSED IMPORTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestUnusedImports:
    def test_python_unused_import(self):
        code = "import os\nimport sys\nprint(os.getcwd())\n"
        tree, src, config = _parse(code, "python")
        findings = check_unused_imports(tree, src, config, "test.py")
        rules = [f.message for f in findings]
        assert any("sys" in m for m in rules)
        # os IS used
        assert not any("os" in m for m in rules)

    def test_python_from_import_unused(self):
        code = "from pathlib import Path\nfrom os import getcwd\nx = getcwd()\n"
        tree, src, config = _parse(code, "python")
        findings = check_unused_imports(tree, src, config, "test.py")
        names = [f.message for f in findings]
        assert any("Path" in m for m in names)
        assert not any("getcwd" in m for m in names)

    def test_python_underscore_import_not_flagged(self):
        code = "import _private\nfrom module import __dunder__\n"
        tree, src, config = _parse(code, "python")
        findings = check_unused_imports(tree, src, config, "test.py")
        assert len(findings) == 0

    def test_javascript_unused_import(self):
        code = 'import { useState, useEffect } from "react";\nconsole.log(useState());\n'
        tree, src, config = _parse(code, "javascript")
        findings = check_unused_imports(tree, src, config, "test.js")
        names = [f.message for f in findings]
        assert any("useEffect" in m for m in names)
        assert not any("useState" in m for m in names)

    def test_go_unused_import(self):
        code = 'package main\n\nimport (\n\t"fmt"\n\t"os"\n)\n\nfunc main() {\n\tfmt.Println("hi")\n}\n'
        tree, src, config = _parse(code, "go")
        findings = check_unused_imports(tree, src, config, "test.go")
        names = [f.message for f in findings]
        assert any("os" in m for m in names)
        assert not any("fmt" in m for m in names)

    def test_used_import_not_flagged(self):
        code = "import os\nresult = os.path.exists('file')\n"
        tree, src, config = _parse(code, "python")
        findings = check_unused_imports(tree, src, config, "test.py")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# UNREACHABLE CODE
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestUnreachableCode:
    def test_python_unreachable_after_return(self):
        code = "def f():\n    return 1\n    print('dead')\n"
        tree, src, config = _parse(code, "python")
        findings = check_unreachable_code(tree, src, config, "test.py")
        assert len(findings) >= 1
        assert findings[0].rule == "unreachable-code"

    def test_javascript_unreachable_after_return(self):
        code = "function f() {\n    return 1;\n    console.log('dead');\n}\n"
        tree, src, config = _parse(code, "javascript")
        findings = check_unreachable_code(tree, src, config, "test.js")
        assert len(findings) >= 1
        assert findings[0].rule == "unreachable-code"

    def test_go_unreachable_after_return(self):
        code = 'package main\n\nfunc f() int {\n\treturn 1\n\tx := 5\n\t_ = x\n}\n'
        tree, src, config = _parse(code, "go")
        findings = check_unreachable_code(tree, src, config, "test.go")
        assert len(findings) >= 1
        assert findings[0].rule == "unreachable-code"

    def test_java_unreachable_after_return(self):
        code = "class Foo {\n    int f() {\n        return 1;\n        int x = 5;\n    }\n}\n"
        tree, src, config = _parse(code, "java")
        findings = check_unreachable_code(tree, src, config, "test.java")
        assert len(findings) >= 1
        assert findings[0].rule == "unreachable-code"

    def test_no_unreachable_code(self):
        code = "def f():\n    x = 1\n    return x\n"
        tree, src, config = _parse(code, "python")
        findings = check_unreachable_code(tree, src, config, "test.py")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# EMPTY CATCH
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestEmptyCatch:
    def test_python_empty_except_pass(self):
        code = "try:\n    x = 1\nexcept Exception:\n    pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_empty_catch(tree, src, config, "test.py")
        assert len(findings) == 1
        assert findings[0].rule == "empty-exception-handler"

    def test_python_except_with_body_not_flagged(self):
        code = "try:\n    x = 1\nexcept Exception as e:\n    print(e)\n"
        tree, src, config = _parse(code, "python")
        findings = check_empty_catch(tree, src, config, "test.py")
        assert len(findings) == 0

    def test_javascript_empty_catch(self):
        code = "try {\n    x = 1;\n} catch(e) {\n}\n"
        tree, src, config = _parse(code, "javascript")
        findings = check_empty_catch(tree, src, config, "test.js")
        assert len(findings) == 1
        assert findings[0].rule == "empty-exception-handler"

    def test_java_empty_catch(self):
        code = "class Foo {\n    void f() {\n        try {\n            int x = 1;\n        } catch (Exception e) {\n        }\n    }\n}\n"
        tree, src, config = _parse(code, "java")
        findings = check_empty_catch(tree, src, config, "test.java")
        assert len(findings) == 1
        assert findings[0].rule == "empty-exception-handler"

    def test_go_no_catch_types(self):
        """Go doesn't have catch blocks — check should return empty."""
        code = "package main\n\nfunc f() {\n\tdefer func() {\n\t\trecover()\n\t}()\n}\n"
        tree, src, config = _parse(code, "go")
        findings = check_empty_catch(tree, src, config, "test.go")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# SHADOWED BUILTINS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestShadowedBuiltins:
    def test_python_shadowed_param(self):
        code = "def f(list, dict):\n    return list\n"
        tree, src, config = _parse(code, "python")
        findings = check_shadowed_builtins(tree, src, config, "test.py")
        names = [f.message for f in findings]
        assert any("list" in m for m in names)
        assert any("dict" in m for m in names)

    def test_python_self_cls_not_flagged(self):
        code = "class C:\n    def f(self, x):\n        pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_shadowed_builtins(tree, src, config, "test.py")
        assert len(findings) == 0

    def test_non_builtin_not_flagged(self):
        code = "def f(my_var, another_param):\n    return my_var\n"
        tree, src, config = _parse(code, "python")
        findings = check_shadowed_builtins(tree, src, config, "test.py")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# FUNCTION COMPLEXITY
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestFunctionComplexity:
    def test_simple_function_ok(self):
        code = "def f():\n    return 1\n"
        tree, src, config = _parse(code, "python")
        findings = check_function_complexity(tree, src, config, "test.py")
        assert len(findings) == 0

    def test_complex_function_flagged(self):
        # Build a function with 16+ branches
        branches = "\n".join(
            f"    if x{i}:\n        pass" for i in range(17)
        )
        code = f"def complex_func():\n{branches}\n"
        tree, src, config = _parse(code, "python")
        findings = check_function_complexity(tree, src, config, "test.py")
        assert len(findings) == 1
        assert "complex_func" in findings[0].message
        assert findings[0].rule == "high-complexity"

    def test_threshold_boundary(self):
        """15 branches should NOT be flagged (threshold is > 15)."""
        branches = "\n".join(
            f"    if x{i}:\n        pass" for i in range(15)
        )
        code = f"def boundary_func():\n{branches}\n"
        tree, src, config = _parse(code, "python")
        findings = check_function_complexity(tree, src, config, "test.py")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# TOO MANY ARGUMENTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestTooManyArgs:
    def test_too_many_params_flagged(self):
        code = "def f(a, b, c, d, e, f, g, h):\n    pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_too_many_args(tree, src, config, "test.py")
        assert len(findings) == 1
        assert findings[0].rule == "too-many-args"

    def test_seven_params_ok(self):
        code = "def f(a, b, c, d, e, f, g):\n    pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_too_many_args(tree, src, config, "test.py")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# MUTABLE DEFAULTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestMutableDefaults:
    def test_python_list_default_flagged(self):
        code = "def f(x=[]):\n    x.append(1)\n"
        tree, src, config = _parse(code, "python")
        findings = check_mutable_defaults(tree, src, config, "test.py")
        assert len(findings) == 1
        assert findings[0].rule == "mutable-default"

    def test_python_dict_default_flagged(self):
        code = "def f(x={}):\n    pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_mutable_defaults(tree, src, config, "test.py")
        assert len(findings) == 1

    def test_python_immutable_default_not_flagged(self):
        code = "def f(x=None, y=0, z='hello'):\n    pass\n"
        tree, src, config = _parse(code, "python")
        findings = check_mutable_defaults(tree, src, config, "test.py")
        assert len(findings) == 0

    def test_go_no_mutable_defaults(self):
        """Go doesn't have default parameters — check should return empty."""
        code = "package main\n\nfunc f(x int) int {\n\treturn x\n}\n"
        tree, src, config = _parse(code, "go")
        findings = check_mutable_defaults(tree, src, config, "test.go")
        assert len(findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# FALLBACK BEHAVIOR
# ───────────────────────────────────────────────────────────────────────────

class TestFallback:
    def test_no_tree_sitter_returns_empty(self):
        """When tree-sitter not installed, run_tree_sitter_checks returns []."""
        with patch.dict("sys.modules", {"tree_sitter_language_pack": None}):
            # Force reimport to pick up the mock
            import importlib
            from wiz.semantic import checks as ts_checks
            importlib.reload(ts_checks)
            result = ts_checks.run_tree_sitter_checks(
                "import os\n", "test.py", "python"
            )
            # Restore
            importlib.reload(ts_checks)
        assert result == []

    def test_unknown_language_returns_empty(self):
        """Unknown language should return empty list."""
        result = run_tree_sitter_checks("some code", "test.xyz", "brainfuck")
        assert result == []

    @needs_tree_sitter
    def test_tree_sitter_preferred_for_python(self):
        """When tree-sitter is available, Python gets tree-sitter findings."""
        code = "import os\nimport sys\nprint(os.getcwd())\n"
        findings = run_tree_sitter_checks(code, "test.py", "python")
        # Should find unused sys import
        assert any(f.rule == "unused-import" and "sys" in f.message
                   for f in findings)


# ───────────────────────────────────────────────────────────────────────────
# INTEGRATION / PARITY TESTS
# ───────────────────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestIntegration:
    def test_run_tree_sitter_checks_python(self):
        """Full run on Python code should find multiple issues."""
        code = (
            "import os\nimport sys\n\n"
            "def f(list):\n    return 1\n    print('dead')\n\n"
            "try:\n    x = 1\nexcept Exception:\n    pass\n"
        )
        findings = run_tree_sitter_checks(code, "test.py", "python")
        rules = {f.rule for f in findings}
        assert "unused-import" in rules
        assert "unreachable-code" in rules
        assert "empty-exception-handler" in rules
        assert "shadowed-builtin" in rules

    def test_run_tree_sitter_checks_javascript(self):
        """Full run on JavaScript code."""
        code = (
            'import { useState, useEffect } from "react";\n'
            "function f() {\n"
            "    return 1;\n"
            "    console.log('dead');\n"
            "}\n"
            "try {\n    x = 1;\n} catch(e) {\n}\n"
            "console.log(useState());\n"
        )
        findings = run_tree_sitter_checks(code, "test.js", "javascript")
        rules = {f.rule for f in findings}
        assert "unused-import" in rules
        assert "unreachable-code" in rules
        assert "empty-exception-handler" in rules

    def test_python_parity_unused_imports(self):
        """Tree-sitter should find the same unused imports as Python AST."""
        from wiz.detector import run_python_ast_checks

        code = "import os\nimport sys\nimport json\nresult = os.getcwd()\n"

        ts_findings = run_tree_sitter_checks(code, "test.py", "python")
        py_findings = run_python_ast_checks(code, "test.py")

        ts_unused = {f.message for f in ts_findings if f.rule == "unused-import"}
        py_unused = {f.message for f in py_findings if f.rule == "unused-import"}

        # Both should flag sys and json as unused
        assert any("sys" in m for m in ts_unused)
        assert any("sys" in m for m in py_unused)
        assert any("json" in m for m in ts_unused)
        assert any("json" in m for m in py_unused)

    def test_python_parity_unreachable_code(self):
        """Tree-sitter should find unreachable code same as Python AST."""
        from wiz.detector import run_python_ast_checks

        code = "def f():\n    return 1\n    print('dead')\n"

        ts_findings = run_tree_sitter_checks(code, "test.py", "python")
        py_findings = run_python_ast_checks(code, "test.py")

        ts_rules = {f.rule for f in ts_findings}
        py_rules = {f.rule for f in py_findings}

        assert "unreachable-code" in ts_rules
        assert "unreachable-code" in py_rules

    def test_detector_integration_with_tree_sitter(self):
        """analyze_file_static should use tree-sitter when available."""
        from wiz.detector import analyze_file_static

        code = (
            "import os\nimport sys\n\n"
            "def f():\n    return 1\n    print('dead')\n\n"
            "result = os.getcwd()\n"
        )
        findings = analyze_file_static("test.py", code, "python")
        rules = {f.rule for f in findings}
        assert "unused-import" in rules
        assert "unreachable-code" in rules

    def test_javascript_gets_ast_findings(self):
        """JavaScript should get AST findings from tree-sitter."""
        from wiz.detector import analyze_file_static

        code = "function f() {\n    return 1;\n    console.log('dead');\n}\n"
        findings = analyze_file_static("test.js", code, "javascript")
        rules = {f.rule for f in findings}
        assert "unreachable-code" in rules
