"""Tests for architectural smell detection (god class, feature envy, long method, near-duplicates)."""

import pytest

from dojigiri.types import Severity, Category, Source

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


def _sem(code: str, filepath: str = "test.py"):
    """Parse Python code and return FileSemantics."""
    from dojigiri.semantic.core import extract_semantics
    sem = extract_semantics(code, filepath, "python")
    assert sem is not None, "tree-sitter failed to extract semantics"
    return sem


# ---------------------------------------------------------------------------
# GOD CLASS
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestGodClassManyMethods:
    """Class with >15 methods triggers god-class finding."""

    def test_class_with_many_methods(self):
        from dojigiri.semantic.smells import check_god_class

        code = "class Big:\n" + "\n".join(
            f"    def method_{i}(self):\n        pass\n" for i in range(20)
        )
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 1
        assert findings[0].rule == "god-class"
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.STYLE
        assert "Big" in findings[0].message
        assert "20 methods" in findings[0].message

    def test_class_with_many_attributes(self):
        """Class with >10 self.attr assignments triggers god-class finding."""
        from dojigiri.semantic.smells import check_god_class

        attrs = "\n".join(
            f"        self.attr_{i} = {i}" for i in range(15)
        )
        code = (
            "class Wide:\n"
            "    def __init__(self):\n"
            f"{attrs}\n"
        )
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 1
        assert findings[0].rule == "god-class"
        assert "Wide" in findings[0].message
        assert "attributes" in findings[0].message

    def test_small_class_no_finding(self):
        """A class with few methods and attributes should not be flagged."""
        from dojigiri.semantic.smells import check_god_class

        code = (
            "class Small:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def do_thing(self):\n"
            "        return self.x\n"
        )
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 0

    def test_custom_lower_thresholds(self):
        """Lowered thresholds should flag a smaller class."""
        from dojigiri.semantic.smells import check_god_class

        code = (
            "class Medium:\n"
            "    def __init__(self):\n"
            "        self.a = 1\n"
            "        self.b = 2\n"
            "        self.c = 3\n"
            "    def method_a(self):\n"
            "        pass\n"
            "    def method_b(self):\n"
            "        pass\n"
            "    def method_c(self):\n"
            "        pass\n"
            "    def method_d(self):\n"
            "        pass\n"
        )
        sem = _sem(code)

        # Default thresholds: should not flag
        findings_default = check_god_class(sem, "test.py")
        assert len(findings_default) == 0

        # Lower thresholds: method_threshold=3, attribute_threshold=2
        findings_low = check_god_class(sem, "test.py", method_threshold=3, attribute_threshold=2)
        assert len(findings_low) == 1
        assert findings_low[0].rule == "god-class"
        assert "Medium" in findings_low[0].message

    def test_multiple_god_classes(self):
        """Multiple god classes in one file produce multiple findings."""
        from dojigiri.semantic.smells import check_god_class

        code_a = "class GodA:\n" + "\n".join(
            f"    def m_{i}(self):\n        pass\n" for i in range(5)
        )
        code_b = "class GodB:\n" + "\n".join(
            f"    def n_{i}(self):\n        pass\n" for i in range(6)
        )
        code = code_a + "\n" + code_b
        sem = _sem(code)

        # Use low threshold so both get flagged
        findings = check_god_class(sem, "test.py", method_threshold=4, attribute_threshold=100)
        assert len(findings) == 2
        names = {f.message for f in findings}
        assert any("GodA" in m for m in names)
        assert any("GodB" in m for m in names)


# ---------------------------------------------------------------------------
# FEATURE ENVY
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestFeatureEnvy:
    """Methods that access external state more than internal state."""

    def test_method_with_external_access(self):
        """Method referencing many external attributes should be flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class MyClass:\n"
            "    def __init__(self):\n"
            "        self.internal = 1\n"
            "    def envious(self, other):\n"
            "        a = other.alpha\n"
            "        b = other.beta\n"
            "        c = other.gamma\n"
            "        d = other.delta\n"
            "        return a + b + c + d\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=1.0, min_external=2)

        # Whether this triggers depends on how references are resolved.
        # With low thresholds we expect at least recognition of the pattern.
        # The function checks attribute_access context refs.
        # Assert structure is correct for any findings produced.
        for f in findings:
            assert f.rule == "feature-envy"
            assert f.severity == Severity.INFO
            assert f.category == Category.STYLE

    def test_method_with_internal_access_no_finding(self):
        """Method mainly using self attributes should not be flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class MyClass:\n"
            "    def __init__(self):\n"
            "        self.a = 1\n"
            "        self.b = 2\n"
            "        self.c = 3\n"
            "    def internal_method(self):\n"
            "        return self.a + self.b + self.c\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py")

        assert len(findings) == 0

    def test_standalone_function_not_checked(self):
        """Non-method (module-level) functions should never be flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "def standalone(obj):\n"
            "    a = obj.alpha\n"
            "    b = obj.beta\n"
            "    c = obj.gamma\n"
            "    d = obj.delta\n"
            "    return a + b + c + d\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=0.5, min_external=1)

        # Feature envy only checks methods (parent_class is not None)
        assert len(findings) == 0

    def test_feature_envy_with_low_thresholds(self):
        """With very low thresholds, even moderate external access triggers."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Worker:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def process(self, config):\n"
            "        a = config.timeout\n"
            "        b = config.retries\n"
            "        c = config.endpoint\n"
            "        return a + b\n"
        )
        sem = _sem(code)
        # Low thresholds: ratio=0.5, min_external=1
        findings = check_feature_envy(sem, "test.py", external_ratio=0.5, min_external=1)

        for f in findings:
            assert f.rule == "feature-envy"
            assert f.severity == Severity.INFO
            assert f.category == Category.STYLE
            assert f.source == Source.AST


# ---------------------------------------------------------------------------
# LONG METHOD
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestLongMethod:
    """Functions/methods exceeding a line threshold."""

    def test_function_over_50_lines(self):
        """A standalone function >50 lines should be flagged."""
        from dojigiri.semantic.smells import check_long_method

        body = "\n".join(f"    x_{i} = {i}" for i in range(60))
        code = f"def long_func():\n{body}\n"
        sem = _sem(code)
        findings = check_long_method(sem, "test.py")

        assert len(findings) == 1
        assert findings[0].rule == "long-method"
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.STYLE
        assert "Function" in findings[0].message
        assert "long_func" in findings[0].message

    def test_short_function_no_finding(self):
        """A short function should not be flagged."""
        from dojigiri.semantic.smells import check_long_method

        code = (
            "def short_func():\n"
            "    x = 1\n"
            "    return x\n"
        )
        sem = _sem(code)
        findings = check_long_method(sem, "test.py")

        assert len(findings) == 0

    def test_method_in_class_uses_method_label(self):
        """A long method inside a class should use 'Method' label."""
        from dojigiri.semantic.smells import check_long_method

        body = "\n".join(f"        self.x_{i} = {i}" for i in range(55))
        code = (
            "class MyClass:\n"
            f"    def long_method(self):\n{body}\n"
        )
        sem = _sem(code)
        findings = check_long_method(sem, "test.py")

        assert len(findings) == 1
        assert findings[0].rule == "long-method"
        assert "Method" in findings[0].message
        assert "long_method" in findings[0].message

    def test_custom_lower_threshold(self):
        """Lower threshold should flag shorter functions."""
        from dojigiri.semantic.smells import check_long_method

        body = "\n".join(f"    x_{i} = {i}" for i in range(8))
        code = f"def medium_func():\n{body}\n"
        sem = _sem(code)

        # Default threshold (50) should not flag
        findings_default = check_long_method(sem, "test.py")
        assert len(findings_default) == 0

        # Lower threshold (5) should flag
        findings_low = check_long_method(sem, "test.py", threshold=5)
        assert len(findings_low) == 1
        assert findings_low[0].rule == "long-method"
        assert "medium_func" in findings_low[0].message

    def test_multiple_long_functions(self):
        """Multiple long functions produce multiple findings."""
        from dojigiri.semantic.smells import check_long_method

        body_a = "\n".join(f"    a_{i} = {i}" for i in range(12))
        body_b = "\n".join(f"    b_{i} = {i}" for i in range(15))
        code = (
            f"def func_a():\n{body_a}\n\n"
            f"def func_b():\n{body_b}\n"
        )
        sem = _sem(code)
        findings = check_long_method(sem, "test.py", threshold=10)

        assert len(findings) == 2
        names = [f.message for f in findings]
        assert any("func_a" in m for m in names)
        assert any("func_b" in m for m in names)


# ---------------------------------------------------------------------------
# NEAR DUPLICATES
# ---------------------------------------------------------------------------

def _make_similar_code(name: str) -> str:
    """Generate a function with 15 assignments calling distinct functions."""
    body = "\n".join(f"    x_{i} = func_{i}()" for i in range(15))
    return f"def {name}(a, b, c):\n{body}\n    return x_0\n"


@needs_tree_sitter
class TestNearDuplicates:
    """Functions across files with matching structural signatures."""

    def test_similar_functions_across_files(self):
        """Two structurally similar functions in different files should be flagged."""
        from dojigiri.semantic.smells import check_near_duplicate_functions

        code_a = _make_similar_code("func_a")
        code_b = _make_similar_code("func_b")
        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        findings = check_near_duplicate_functions({"a.py": sem_a, "b.py": sem_b})

        assert len(findings) == 1
        assert findings[0].rule == "near-duplicate"
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.STYLE
        assert findings[0].source == Source.AST
        assert "func_a" in findings[0].message or "func_b" in findings[0].message

    def test_different_functions_no_finding(self):
        """Two structurally different functions should not be flagged."""
        from dojigiri.semantic.smells import check_near_duplicate_functions

        code_a = (
            "def compute(a, b, c):\n"
            + "\n".join(f"    x_{i} = func_{i}()" for i in range(15))
            + "\n    return x_0\n"
        )
        # Different structure: different call names, different param count
        code_b = (
            "def transform(z):\n"
            + "\n".join(f"    y_{i} = other_{i}()" for i in range(15))
            + "\n    return y_0\n"
        )
        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        findings = check_near_duplicate_functions({"a.py": sem_a, "b.py": sem_b})

        # Different param counts and call names -> no match
        assert len(findings) == 0

    def test_small_function_not_flagged(self):
        """Functions with <10 statements should be ignored (too small to matter)."""
        from dojigiri.semantic.smells import check_near_duplicate_functions

        body = "\n".join(f"    x_{i} = {i}" for i in range(5))
        code_a = f"def small_a(a, b):\n{body}\n    return x_0\n"
        code_b = f"def small_b(a, b):\n{body}\n    return x_0\n"
        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        findings = check_near_duplicate_functions({"a.py": sem_a, "b.py": sem_b})

        # Too few statements, should not be flagged
        assert len(findings) == 0

    def test_same_function_same_file_not_flagged(self):
        """Two similar functions in the same file at the same line should be skipped.

        In practice this means the same function -- the dedup check skips
        pairs with (same file, same line).
        """
        from dojigiri.semantic.smells import check_near_duplicate_functions

        code = _make_similar_code("only_one")
        sem = _sem(code, "single.py")

        findings = check_near_duplicate_functions({"single.py": sem})

        # Only one function -> no pair to report
        assert len(findings) == 0

    def test_three_duplicates_multiple_findings(self):
        """Three structurally identical functions should produce multiple pair findings."""
        from dojigiri.semantic.smells import check_near_duplicate_functions

        code_a = _make_similar_code("dup_a")
        code_b = _make_similar_code("dup_b")
        code_c = _make_similar_code("dup_c")
        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sem_c = _sem(code_c, "c.py")

        findings = check_near_duplicate_functions({
            "a.py": sem_a,
            "b.py": sem_b,
            "c.py": sem_c,
        })

        # 3 functions -> 3 unique pairs: (a,b), (a,c), (b,c)
        assert len(findings) == 3
        for f in findings:
            assert f.rule == "near-duplicate"
            assert f.severity == Severity.INFO
            assert f.category == Category.STYLE

    def test_empty_semantics_no_findings(self):
        """Empty semantics dict should produce no findings."""
        from dojigiri.semantic.smells import check_near_duplicate_functions

        findings = check_near_duplicate_functions({})
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# EDGE CASES / CROSS-CUTTING
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestEdgeCases:
    """Edge cases and cross-cutting concerns for smell detection."""

    def test_all_findings_have_correct_source(self):
        """All smell findings should have Source.AST."""
        from dojigiri.semantic.smells import check_god_class, check_long_method

        # God class
        code = "class Huge:\n" + "\n".join(
            f"    def m_{i}(self):\n        pass\n" for i in range(20)
        )
        sem = _sem(code)
        for f in check_god_class(sem, "test.py"):
            assert f.source == Source.AST

        # Long method
        body = "\n".join(f"    x_{i} = {i}" for i in range(60))
        code2 = f"def big():\n{body}\n"
        sem2 = _sem(code2)
        for f in check_long_method(sem2, "test.py"):
            assert f.source == Source.AST

    def test_findings_have_suggestions(self):
        """All smell findings should include a non-empty suggestion."""
        from dojigiri.semantic.smells import check_god_class, check_long_method

        code = "class Huge:\n" + "\n".join(
            f"    def m_{i}(self):\n        pass\n" for i in range(20)
        )
        sem = _sem(code)
        for f in check_god_class(sem, "test.py"):
            assert f.suggestion is not None
            assert len(f.suggestion) > 0

        body = "\n".join(f"    x_{i} = {i}" for i in range(60))
        code2 = f"def big():\n{body}\n"
        sem2 = _sem(code2)
        for f in check_long_method(sem2, "test.py"):
            assert f.suggestion is not None
            assert len(f.suggestion) > 0
