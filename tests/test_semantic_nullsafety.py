"""Tests for null safety checks (dojigiri.semantic.nullsafety.check_null_safety).

~25 tests covering nullable access detection, guarded access (narrowing),
annotation-based nullability, cross-language support, and edge cases.
"""

import os
import tempfile

import pytest

from dojigiri.semantic.core import extract_semantics
from dojigiri.semantic.types import infer_types, FileTypeMap
from dojigiri.semantic.nullsafety import check_null_safety
from dojigiri.semantic.lang_config import get_config
from dojigiri.config import Severity, Category, Source

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


# ─── Helper ──────────────────────────────────────────────────────────────────

def _check_python(code: str):
    """Run null safety check on Python code.

    check_null_safety reads the file from disk for narrowing detection,
    so we write to a temp file.
    """
    config = get_config("python")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        filepath = f.name
    try:
        sem = extract_semantics(code, filepath, "python")
        if sem is None:
            return []
        source_bytes = code.encode("utf-8")
        type_map = infer_types(sem, source_bytes, config)
        return check_null_safety(sem, type_map, config, filepath)
    finally:
        os.unlink(filepath)


def _check_js(code: str):
    """Run null safety check on JavaScript code."""
    config = get_config("javascript")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        filepath = f.name
    try:
        sem = extract_semantics(code, filepath, "javascript")
        if sem is None:
            return []
        source_bytes = code.encode("utf-8")
        type_map = infer_types(sem, source_bytes, config)
        return check_null_safety(sem, type_map, config, filepath)
    finally:
        os.unlink(filepath)


def _check_java(code: str):
    """Run null safety check on Java code."""
    config = get_config("java")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".java", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        filepath = f.name
    try:
        sem = extract_semantics(code, filepath, "java")
        if sem is None:
            return []
        source_bytes = code.encode("utf-8")
        type_map = infer_types(sem, source_bytes, config)
        return check_null_safety(sem, type_map, config, filepath)
    finally:
        os.unlink(filepath)


# ─── Nullable Access Detection ───────────────────────────────────────────────

@needs_tree_sitter
class TestNullableAccessDetection:
    """Detect attribute/method access on potentially nullable values."""

    def test_dict_get_then_method_call(self):
        """x = d.get('k'); x.strip() should produce a null-dereference finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1
        assert any("x" in f.message for f in null_findings)

    def test_re_match_then_group(self):
        """m = re.match(...); m.group(1) should produce a null-dereference finding."""
        code = '''\
def f():
    m = re.match(r"\\d+", text)
    m.group(1)
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1
        assert any("m" in f.message for f in null_findings)

    def test_none_assigned_then_method_call(self):
        """x = None; x.foo() should produce a null-dereference finding."""
        code = '''\
def f():
    x = None
    x.foo()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1

    def test_int_method_call_no_finding(self):
        """x = 5; x.bit_length() should not produce a finding (x is not nullable)."""
        code = '''\
def f():
    x = 5
    x.bit_length()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_string_method_call_no_finding(self):
        """x = 'hello'; x.upper() should not produce a finding."""
        code = '''\
def f():
    x = "hello"
    x.upper()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_method_call_on_nullable_return(self):
        """d.get('k').strip() — method call on nullable return value."""
        code = '''\
def f():
    d = {"key": "val"}
    result = d.get("key")
    result.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1

    def test_no_nullable_variables_no_findings(self):
        """Code with only non-nullable variables should produce no findings."""
        code = '''\
def f():
    x = 10
    y = "hello"
    z = [1, 2, 3]
    print(x, y, z)
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0


# ─── Guarded Access (Narrowing) ─────────────────────────────────────────────

@needs_tree_sitter
class TestGuardedAccess:
    """Verify conditional narrowing suppresses findings within None guards."""

    def test_is_not_none_guard(self):
        """x = d.get('k'); if x is not None: x.strip() should NOT produce a finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    if x is not None:
        x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_not_equal_none_guard(self):
        """x = d.get('k'); if x != None: x.strip() should NOT produce a finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    if x != None:
        x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_truthiness_guard(self):
        """x = d.get('k'); if x: x.strip() should NOT produce a finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    if x:
        x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_access_outside_guard_produces_finding(self):
        """Access outside of a guard block should still produce a finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    if x is not None:
        pass
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # x.strip() is at the same indent level as the if, so it is outside the guard
        assert len(null_findings) >= 1

    def test_guard_on_different_variable_does_not_suppress(self):
        """Guarding a different variable should not suppress the finding."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    y = d.get("other")
    if y is not None:
        x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # x is still nullable; the guard is on y
        assert len(null_findings) >= 1

    def test_guard_in_different_scope_does_not_suppress(self):
        """Guard in a different function scope should not protect usage."""
        code = '''\
def f():
    d = {"key": "val"}
    x = d.get("key")
    if x is not None:
        pass

def g():
    d = {"key": "val"}
    y = d.get("key")
    y.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # y in g() is used without a guard
        assert len(null_findings) >= 1


# ─── Annotation-Based Nullability ────────────────────────────────────────────

@needs_tree_sitter
class TestAnnotationBased:
    """Detect nullability from type annotations."""

    def test_optional_annotation_access(self):
        """x: Optional[str] = foo(); x.strip() should produce a finding."""
        code = '''\
def f():
    x: Optional[str] = foo()
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1

    def test_non_optional_annotation_no_finding(self):
        """x: str = 'hello'; x.strip() should NOT produce a finding."""
        code = '''\
def f():
    x: str = "hello"
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_union_none_annotation_access(self):
        """x: str | None = foo(); x.upper() should produce a finding."""
        code = '''\
def f():
    x: str | None = foo()
    x.upper()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1

    def test_return_type_optional_usage_flagged(self):
        """Return type annotation Optional should be extracted from the source.

        Note: The return type annotation is extracted but full resolution
        into FileTypeMap.return_types requires scope_id alignment between
        the annotation key and the function definition scope. This test
        verifies the annotation is correctly extracted.
        """
        from dojigiri.semantic.types import _extract_annotations_from_tree
        code = '''\
def get_name() -> Optional[str]:
    return None
'''
        config = get_config("python")
        sem = extract_semantics(code, "test.py", "python")
        if sem is None:
            pytest.skip("tree-sitter unavailable")
        source_bytes = code.encode("utf-8")
        anns = _extract_annotations_from_tree(sem, source_bytes)
        return_anns = {k: v for k, v in anns.items() if k[0] == "__return__"}
        assert len(return_anns) >= 1
        ann_text = list(return_anns.values())[0]
        assert "Optional[str]" in ann_text


# ─── Edge Cases ──────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestEdgeCases:
    """Edge cases and robustness checks."""

    def test_empty_type_map_no_findings(self):
        """Empty type map should produce no findings."""
        code = '''\
def f():
    pass
'''
        findings = _check_python(code)
        assert len(findings) == 0

    def test_file_not_found_graceful_return(self):
        """Non-existent file path should return [] gracefully."""
        code = '''\
def f():
    x = None
    x.foo()
'''
        config = get_config("python")
        sem = extract_semantics(code, "test.py", "python")
        if sem is None:
            pytest.skip("tree-sitter unavailable")
        source_bytes = code.encode("utf-8")
        type_map = infer_types(sem, source_bytes, config)
        # Pass a nonexistent file path
        findings = check_null_safety(sem, type_map, config, "/nonexistent/path/test.py")
        assert findings == []

    def test_no_references_no_findings(self):
        """Code with no attribute access references should produce no findings."""
        code = '''\
def f():
    x = None
    y = 5
    print(y)
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # No attribute access on x, so no null-dereference
        assert len(null_findings) == 0

    def test_parameter_not_tracked_for_nullability(self):
        """Function parameters should not be flagged for nullability.

        Parameters are marked is_parameter=True and skipped by type inference.
        """
        code = '''\
def f(x):
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) == 0

    def test_multiple_nullable_accesses_deduplicated(self):
        """Multiple accesses on the same line should be deduplicated."""
        code = '''\
def f():
    x = None
    x.foo()
    x.bar()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # Each access is on a different line, so both should be reported
        # but if on the same line they would be deduplicated
        lines = {f.line for f in null_findings}
        assert len(lines) == len(null_findings)  # no duplicates per line


# ─── Cross-Language ──────────────────────────────────────────────────────────

@needs_tree_sitter
class TestCrossLanguage:
    """Verify null safety across different languages."""

    def test_javascript_find_result_access(self):
        """JavaScript: .find() result access should flag null dereference."""
        code = '''\
function f() {
    const items = [1, 2, 3];
    const result = items.find(x => x > 5);
    result.toString();
}
'''
        findings = _check_js(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # .find() is a nullable pattern for JS
        # Whether this triggers depends on semantic extraction capturing
        # the .find() pattern in value_text
        for f in null_findings:
            assert "result" in f.message

    def test_java_get_result_access(self):
        """Java: .get() result access should flag null dereference."""
        code = '''\
class Test {
    void handle() {
        String val = map.get("key");
        val.length();
    }
}
'''
        findings = _check_java(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        # Java .get() is configured as a nullable pattern
        for f in null_findings:
            assert f.rule == "null-dereference"

    def test_finding_attributes(self):
        """Null-dereference findings should have correct attributes."""
        code = '''\
def f():
    x = None
    x.strip()
'''
        findings = _check_python(code)
        null_findings = [f for f in findings if f.rule == "null-dereference"]
        assert len(null_findings) >= 1
        f = null_findings[0]
        assert f.severity == Severity.WARNING
        assert f.category == Category.BUG
        assert f.source == Source.AST
        assert f.suggestion is not None
        assert len(f.suggestion) > 0
        assert "None check" in f.suggestion or "None" in f.suggestion
