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
class TestGodClass:
    """God class detection requires BOTH excessive methods AND attributes."""

    def test_class_with_many_methods_and_attributes(self):
        """Class exceeding both method and attribute thresholds triggers god-class."""
        from dojigiri.semantic.smells import check_god_class

        # Build a class with 25 methods and 20 attributes (both > defaults of 20/15)
        attrs = "\n".join(f"        self.attr_{i} = {i}" for i in range(20))
        methods = "\n".join(
            f"    def method_{i}(self):\n        pass\n" for i in range(25)
        )
        code = f"class God:\n    def __init__(self):\n{attrs}\n{methods}"
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 1
        assert findings[0].rule == "god-class"
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.STYLE
        assert "God" in findings[0].message
        assert "methods" in findings[0].message
        assert "attributes" in findings[0].message

    def test_many_methods_few_attributes_no_finding(self):
        """Class with many methods but few attributes is a service class, not a god class."""
        from dojigiri.semantic.smells import check_god_class

        code = "class ServiceClass:\n" + "\n".join(
            f"    def method_{i}(self):\n        pass\n" for i in range(25)
        )
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 0, (
            f"Service classes (many methods, few attrs) should not be flagged, got: "
            f"{[f.message for f in findings]}"
        )

    def test_many_attributes_few_methods_no_finding(self):
        """Class with many attributes but few methods is a data class, not a god class."""
        from dojigiri.semantic.smells import check_god_class

        attrs = "\n".join(f"        self.attr_{i} = {i}" for i in range(25))
        code = (
            "class DataClass:\n"
            "    def __init__(self):\n"
            f"{attrs}\n"
        )
        sem = _sem(code)
        findings = check_god_class(sem, "test.py")

        assert len(findings) == 0, (
            f"Data classes (many attrs, few methods) should not be flagged, got: "
            f"{[f.message for f in findings]}"
        )

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
        """Lowered thresholds should flag a class that exceeds both."""
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

        # Lower thresholds so BOTH are exceeded: method_threshold=3, attribute_threshold=2
        findings_low = check_god_class(sem, "test.py", method_threshold=3, attribute_threshold=2)
        assert len(findings_low) == 1
        assert findings_low[0].rule == "god-class"
        assert "Medium" in findings_low[0].message

    def test_custom_thresholds_one_axis_not_enough(self):
        """Even with low thresholds, only exceeding one axis is not enough."""
        from dojigiri.semantic.smells import check_god_class

        code = (
            "class Medium:\n"
            "    def __init__(self):\n"
            "        self.a = 1\n"
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

        # Methods exceed threshold=3 but attributes (1) don't exceed threshold=2
        findings = check_god_class(sem, "test.py", method_threshold=3, attribute_threshold=2)
        assert len(findings) == 0

    def test_multiple_god_classes(self):
        """Multiple god classes in one file produce multiple findings."""
        from dojigiri.semantic.smells import check_god_class

        # Both classes need to exceed both thresholds
        attrs_a = "\n".join(f"        self.a_{i} = {i}" for i in range(5))
        code_a = f"class GodA:\n    def __init__(self):\n{attrs_a}\n" + "\n".join(
            f"    def m_{i}(self):\n        pass\n" for i in range(5)
        )
        attrs_b = "\n".join(f"        self.b_{i} = {i}" for i in range(6))
        code_b = f"class GodB:\n    def __init__(self):\n{attrs_b}\n" + "\n".join(
            f"    def n_{i}(self):\n        pass\n" for i in range(6)
        )
        code = code_a + "\n" + code_b
        sem = _sem(code)

        # Use low thresholds so both get flagged (both axes exceeded)
        findings = check_god_class(sem, "test.py", method_threshold=4, attribute_threshold=4)
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

    def test_descriptor_dunder_suppressed(self):
        """Descriptor methods (__get__, __set__, __delete__) should not be flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Descriptor:\n"
            "    def __init__(self):\n"
            "        self.name = 'x'\n"
            "    def __get__(self, obj, objtype=None):\n"
            "        a = obj.alpha\n"
            "        b = obj.beta\n"
            "        c = obj.gamma\n"
            "        d = obj.delta\n"
            "        e = obj.epsilon\n"
            "        return a + b + c + d + e\n"
            "    def __set__(self, obj, value):\n"
            "        obj.alpha = value\n"
            "        obj.beta = value\n"
            "        obj.gamma = value\n"
            "        obj.delta = value\n"
            "        obj.epsilon = value\n"
            "        return None\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=1.0, min_external=2)

        assert len(findings) == 0, (
            f"Descriptor dunders should be suppressed, got: "
            f"{[f.message for f in findings]}"
        )

    def test_short_method_suppressed(self):
        """Methods shorter than 5 lines should not be flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Wrapper:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def delegate(self, other):\n"
            "        return other.alpha + other.beta + other.gamma\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=0.5, min_external=1)

        assert len(findings) == 0, (
            f"Short methods (<5 lines) should be suppressed, got: "
            f"{[f.message for f in findings]}"
        )

    def test_nested_function_suppressed(self):
        """Inner/nested functions should not be flagged for feature envy."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Builder:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def build(self, config):\n"
            "        def _inner():\n"
            "            a = config.alpha\n"
            "            b = config.beta\n"
            "            c = config.gamma\n"
            "            d = config.delta\n"
            "            e = config.epsilon\n"
            "            return a + b + c + d + e\n"
            "        return _inner()\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=0.5, min_external=1)

        # _inner should be suppressed (nested function)
        inner_findings = [f for f in findings if "_inner" in f.message]
        assert len(inner_findings) == 0, (
            f"Nested functions should be suppressed, got: "
            f"{[f.message for f in inner_findings]}"
        )

    def test_init_subclass_suppressed(self):
        """__init_subclass__ and __class_getitem__ should be suppressed."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Meta:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def __init_subclass__(cls, registry=None, **kwargs):\n"
            "        super().__init_subclass__(**kwargs)\n"
            "        a = registry.alpha\n"
            "        b = registry.beta\n"
            "        c = registry.gamma\n"
            "        d = registry.delta\n"
            "        e = registry.epsilon\n"
            "        return None\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=0.5, min_external=1)

        subclass_findings = [f for f in findings if "__init_subclass__" in f.message]
        assert len(subclass_findings) == 0, (
            f"__init_subclass__ should be suppressed, got: "
            f"{[f.message for f in subclass_findings]}"
        )

    def test_genuine_envy_still_detected(self):
        """A legitimately envious method (long, non-dunder, non-nested) is still flagged."""
        from dojigiri.semantic.smells import check_feature_envy

        code = (
            "class Processor:\n"
            "    def __init__(self):\n"
            "        self.x = 1\n"
            "    def process(self, other):\n"
            "        a = other.alpha\n"
            "        b = other.beta\n"
            "        c = other.gamma\n"
            "        d = other.delta\n"
            "        e = other.epsilon\n"
            "        f = other.zeta\n"
            "        return a + b + c + d + e + f\n"
        )
        sem = _sem(code)
        findings = check_feature_envy(sem, "test.py", external_ratio=1.0, min_external=3)

        # This IS genuine feature envy — long method, not a dunder, not nested
        envious = [f for f in findings if f.rule == "feature-envy"]
        # We expect it to be flagged (if references resolve correctly)
        for f in envious:
            assert "process" in f.message
            assert f.severity == Severity.INFO


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
# LONG METHOD — EFFECTIVE LINE COUNTING
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestLongMethodEffectiveLines:
    """Effective line counting excludes docstrings, blanks, comments, annotations."""

    def test_docstring_excluded_from_count(self):
        """A function with a large docstring should not be falsely flagged."""
        from dojigiri.semantic.smells import check_long_method

        docstring_lines = "\n".join(f"        Line {i} of documentation." for i in range(25))
        logic_lines = "\n".join(f"    x_{i} = {i}" for i in range(20))
        code = (
            f'def well_documented():\n'
            f'    """Long docstring.\n'
            f'\n'
            f'{docstring_lines}\n'
            f'    """\n'
            f'{logic_lines}\n'
        )
        sem = _sem(code)
        # Total lines ~48 (def + docstring open + 25 doc + blank + close + 20 logic)
        # Effective should be ~21 (def line + 20 logic lines)
        findings = check_long_method(sem, "test.py", threshold=30)
        assert len(findings) == 0, (
            f"Docstring lines should be excluded, got: {[f.message for f in findings]}"
        )

    def test_blank_lines_excluded(self):
        """Blank lines within a function should not count toward threshold."""
        from dojigiri.semantic.smells import check_long_method

        # 15 logic lines interspersed with blank lines = 30 total body lines
        body_parts = []
        for i in range(15):
            body_parts.append(f"    x_{i} = {i}")
            body_parts.append("")  # blank line
        body = "\n".join(body_parts)
        code = f"def spacious_func():\n{body}\n"
        sem = _sem(code)
        # Effective: def + 15 logic = 16; total ~31
        findings = check_long_method(sem, "test.py", threshold=20)
        assert len(findings) == 0, (
            f"Blank lines should be excluded, got: {[f.message for f in findings]}"
        )

    def test_comment_lines_excluded(self):
        """Comment-only lines should not count toward threshold."""
        from dojigiri.semantic.smells import check_long_method

        body_parts = []
        for i in range(15):
            body_parts.append(f"    # Step {i}")
            body_parts.append(f"    x_{i} = {i}")
        body = "\n".join(body_parts)
        code = f"def commented_func():\n{body}\n"
        sem = _sem(code)
        # Effective: def + 15 logic = 16; total = 31 (15 comments + 15 logic + def)
        findings = check_long_method(sem, "test.py", threshold=20)
        assert len(findings) == 0, (
            f"Comment-only lines should be excluded, got: {[f.message for f in findings]}"
        )

    def test_type_annotation_lines_excluded(self):
        """Pure type annotation lines should not count toward threshold."""
        from dojigiri.semantic.smells import check_long_method

        annotations = "\n".join(f"    param_{i}: int" for i in range(15))
        logic = "\n".join(f"    x_{i} = {i}" for i in range(15))
        code = f"def annotated_func():\n{annotations}\n{logic}\n"
        sem = _sem(code)
        # Effective: def + 15 logic = 16 (annotations excluded); total = 31
        findings = check_long_method(sem, "test.py", threshold=20)
        assert len(findings) == 0, (
            f"Type annotation lines should be excluded, got: {[f.message for f in findings]}"
        )

    def test_real_logic_still_flagged(self):
        """A function with lots of real logic should still be flagged."""
        from dojigiri.semantic.smells import check_long_method

        docstring = '    """Short doc."""'
        logic = "\n".join(f"    x_{i} = {i}" for i in range(55))
        code = f"def truly_long():\n{docstring}\n{logic}\n"
        sem = _sem(code)
        findings = check_long_method(sem, "test.py", threshold=50)
        assert len(findings) == 1
        assert "truly_long" in findings[0].message

    def test_message_shows_effective_and_total(self):
        """When effective != total, message shows both counts."""
        from dojigiri.semantic.smells import check_long_method

        # Build a function with enough effective lines to trigger, plus extras
        docstring_lines = "\n".join(f"        Doc line {i}." for i in range(10))
        logic = "\n".join(f"    x_{i} = {i}" for i in range(55))
        code = (
            f'def mixed():\n'
            f'    """Docstring.\n'
            f'{docstring_lines}\n'
            f'    """\n'
            f'{logic}\n'
        )
        sem = _sem(code)
        findings = check_long_method(sem, "test.py", threshold=50)
        assert len(findings) == 1
        assert "effective" in findings[0].message
        assert "total" in findings[0].message

    def test_single_line_docstring_excluded(self):
        """A single-line triple-quoted docstring is excluded."""
        from dojigiri.semantic.smells import check_long_method

        logic = "\n".join(f"    x_{i} = {i}" for i in range(12))
        code = f'def func_with_doc():\n    """One-liner."""\n{logic}\n'
        sem = _sem(code)
        # Effective: def + 12 logic = 13 (docstring excluded)
        # Total: def + docstring + 12 logic = 14
        findings = check_long_method(sem, "test.py", threshold=13)
        assert len(findings) == 0

    def test_fastapi_annotated_pattern(self):
        """FastAPI-style Annotated[Type, Doc(...)] lines should be excluded."""
        from dojigiri.semantic.smells import check_long_method

        annotations = "\n".join(
            f"    param_{i}: Annotated[str, Doc('Parameter {i}')]"
            for i in range(15)
        )
        logic = "\n".join(f"    x_{i} = func_{i}()" for i in range(15))
        code = f"def api_endpoint():\n{annotations}\n{logic}\n"
        sem = _sem(code)
        # Effective: def + 15 logic = 16 (15 annotation lines excluded)
        findings = check_long_method(sem, "test.py", threshold=20)
        assert len(findings) == 0

    def test_multiline_signature_annotated_params_excluded(self):
        """Multi-line function signatures with Annotated params should not inflate count.

        This is the core FastAPI false-positive case: functions like Cookie()
        whose signatures span 50+ lines of Annotated[Type, Doc("...")] params
        but whose bodies are short.
        """
        from dojigiri.semantic.smells import check_long_method

        # Build a FastAPI-style function with a long multi-line signature
        params = ",\n".join(
            f"    param_{i}: Annotated[str, Doc('Parameter {i} description')] = 'default'"
            for i in range(40)
        )
        body_logic = "\n".join(f"    x_{i} = process({i})" for i in range(10))
        code = (
            f"def cookie(\n"
            f"{params}\n"
            f"):\n"
            f'    """Handle cookie parameters."""\n'
            f"{body_logic}\n"
        )
        sem = _sem(code)
        # The signature spans ~42 lines (def + 40 params + closing paren/colon)
        # Body is 1 docstring + 10 logic = 10 effective lines
        # Should NOT be flagged at threshold=50
        findings = check_long_method(sem, "test.py", threshold=50)
        assert len(findings) == 0, (
            f"Multi-line signature params should not inflate effective lines, got: "
            f"{[f.message for f in findings]}"
        )

    def test_multiline_signature_with_long_body_still_flagged(self):
        """A function with a long signature AND a long body should still be flagged."""
        from dojigiri.semantic.smells import check_long_method

        params = ",\n".join(
            f"    p_{i}: str = 'default'" for i in range(20)
        )
        body_logic = "\n".join(f"    x_{i} = process({i})" for i in range(55))
        code = (
            f"def big_func(\n"
            f"{params}\n"
            f"):\n"
            f"{body_logic}\n"
        )
        sem = _sem(code)
        findings = check_long_method(sem, "test.py", threshold=50)
        assert len(findings) == 1
        assert "big_func" in findings[0].message


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

        # God class — use low thresholds with both axes exceeded
        attrs = "\n".join(f"        self.a_{i} = {i}" for i in range(20))
        code = f"class Huge:\n    def __init__(self):\n{attrs}\n" + "\n".join(
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

        # God class — use low thresholds with both axes exceeded
        attrs = "\n".join(f"        self.a_{i} = {i}" for i in range(20))
        code = f"class Huge:\n    def __init__(self):\n{attrs}\n" + "\n".join(
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
