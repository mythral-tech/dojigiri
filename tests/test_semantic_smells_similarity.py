"""Tests for semantic similarity features in dojigiri.semantic.smells."""

import pytest

from dojigiri.config import Severity, Category, Source

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


def _make_function(name: str, call_names: list[str], param_count: int = 3) -> str:
    """Generate a function with assignments and calls (>5 statements for signature)."""
    params = ", ".join(f"p{i}" for i in range(param_count))
    lines = []
    for i, cname in enumerate(call_names):
        lines.append(f"    x_{i} = {cname}()")
    # Pad with assignments to guarantee >5 statements
    for i in range(max(0, 6 - len(call_names))):
        lines.append(f"    y_{i} = {i}")
    lines.append("    return x_0")
    body = "\n".join(lines)
    return f"def {name}({params}):\n{body}\n"


# ---------------------------------------------------------------------------
# SIGNATURE CONSTRUCTION
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestSignatureConstruction:
    """Tests for build_semantic_signature()."""

    def test_simple_function_signature(self):
        """A function with enough statements produces a SemanticSignature."""
        from dojigiri.semantic.smells import build_semantic_signature
        code = _make_function("process", ["fetch", "parse", "validate", "transform", "save"])
        sem = _sem(code)
        fdef = sem.function_defs[0]
        sig = build_semantic_signature(fdef, sem)

        assert sig is not None
        assert sig.param_count == 3
        assert sig.assignment_count >= 5

    def test_function_with_many_statements(self):
        """A function with many calls builds a signature with call sequence."""
        from dojigiri.semantic.smells import build_semantic_signature
        calls = [f"func_{i}" for i in range(8)]
        code = _make_function("big_fn", calls, param_count=2)
        sem = _sem(code)
        fdef = sem.function_defs[0]
        sig = build_semantic_signature(fdef, sem)

        assert sig is not None
        assert sig.param_count == 2
        assert len(sig.call_sequence) >= 8

    def test_function_with_few_statements_returns_none(self):
        """A function with <5 statements returns None (too small to matter)."""
        from dojigiri.semantic.smells import build_semantic_signature
        code = (
            "def tiny(a, b):\n"
            "    return a + b\n"
        )
        sem = _sem(code)
        fdef = sem.function_defs[0]
        sig = build_semantic_signature(fdef, sem)

        assert sig is None

    def test_call_sequence_captured_and_sorted(self):
        """Call names in the signature are captured and sorted alphabetically."""
        from dojigiri.semantic.smells import build_semantic_signature
        # Use calls in non-alphabetical order
        code = _make_function("pipeline", ["zebra", "alpha", "mango", "bravo", "delta", "echo"])
        sem = _sem(code)
        fdef = sem.function_defs[0]
        sig = build_semantic_signature(fdef, sem)

        assert sig is not None
        assert list(sig.call_sequence) == sorted(sig.call_sequence)

    def test_identical_functions_same_data_flow_hash(self):
        """Two identical functions produce the same data_flow_hash."""
        from dojigiri.semantic.smells import build_semantic_signature
        calls = ["read", "process", "write", "log", "cleanup"]
        code_a = _make_function("func_a", calls)
        code_b = _make_function("func_b", calls)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sig_a = build_semantic_signature(sem_a.function_defs[0], sem_a)
        sig_b = build_semantic_signature(sem_b.function_defs[0], sem_b)

        assert sig_a is not None and sig_b is not None
        assert sig_a.data_flow_hash == sig_b.data_flow_hash


# ---------------------------------------------------------------------------
# SIMILARITY SCORING
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestSimilarityScoring:
    """Tests for SemanticSignature.similarity()."""

    def test_identical_signatures_score_one(self):
        """Two identical signatures have similarity 1.0."""
        from dojigiri.semantic.smells import build_semantic_signature
        calls = ["init", "load", "parse", "validate", "execute"]
        code_a = _make_function("dup_a", calls)
        code_b = _make_function("dup_b", calls)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sig_a = build_semantic_signature(sem_a.function_defs[0], sem_a)
        sig_b = build_semantic_signature(sem_b.function_defs[0], sem_b)

        assert sig_a is not None and sig_b is not None
        score = sig_a.similarity(sig_b)
        assert score == pytest.approx(1.0, abs=0.01)

    def test_completely_different_score_low(self):
        """Two very different signatures have similarity near 0."""
        from dojigiri.semantic.smells import build_semantic_signature
        code_a = _make_function("alpha", ["aaa", "bbb", "ccc", "ddd", "eee"], param_count=0)
        code_b = _make_function("omega", ["zzz", "yyy", "xxx", "www", "vvv", "uuu", "ttt", "sss"], param_count=5)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sig_a = build_semantic_signature(sem_a.function_defs[0], sem_a)
        sig_b = build_semantic_signature(sem_b.function_defs[0], sem_b)

        assert sig_a is not None and sig_b is not None
        score = sig_a.similarity(sig_b)
        assert score < 0.5

    def test_same_calls_different_params_high_similarity(self):
        """Same call sequence with different param count is still fairly similar."""
        from dojigiri.semantic.smells import build_semantic_signature
        calls = ["fetch", "parse", "validate", "transform", "save"]
        code_a = _make_function("fn_a", calls, param_count=1)
        code_b = _make_function("fn_b", calls, param_count=4)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sig_a = build_semantic_signature(sem_a.function_defs[0], sem_a)
        sig_b = build_semantic_signature(sem_b.function_defs[0], sem_b)

        assert sig_a is not None and sig_b is not None
        score = sig_a.similarity(sig_b)
        # Calls weigh 0.4 and are identical, so score should be >0.7
        assert score > 0.7

    def test_same_params_different_calls_lower_similarity(self):
        """Same param count but entirely different calls yields lower similarity."""
        from dojigiri.semantic.smells import build_semantic_signature
        code_a = _make_function("fn_a", ["read", "parse", "validate", "store", "notify"], param_count=3)
        code_b = _make_function("fn_b", ["init", "create", "build", "deploy", "cleanup"], param_count=3)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sig_a = build_semantic_signature(sem_a.function_defs[0], sem_a)
        sig_b = build_semantic_signature(sem_b.function_defs[0], sem_b)

        assert sig_a is not None and sig_b is not None
        score = sig_a.similarity(sig_b)
        # Different calls (weight 0.4 = 0) drops score significantly
        assert score < 0.8

    def test_edit_distance_correctness(self):
        """_edit_distance computes correct Levenshtein distance."""
        from dojigiri.semantic.smells import _edit_distance

        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3
        assert _edit_distance("", "xyz") == 3
        assert _edit_distance("kitten", "sitting") == 3
        assert _edit_distance("abc", "abc") == 0
        assert _edit_distance("abc", "abd") == 1


# ---------------------------------------------------------------------------
# CLONE DETECTION
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestCloneDetection:
    """Tests for check_semantic_clones()."""

    def test_similar_functions_across_files_detected(self):
        """Two semantically similar functions in different files produce a finding."""
        from dojigiri.semantic.smells import check_semantic_clones
        calls = ["init", "load", "parse", "validate", "execute"]
        code_a = _make_function("worker_a", calls)
        code_b = _make_function("worker_b", calls)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        findings = check_semantic_clones({"a.py": sem_a, "b.py": sem_b})

        assert len(findings) >= 1
        assert findings[0].rule == "semantic-clone"
        assert findings[0].severity == Severity.INFO
        assert findings[0].category == Category.STYLE
        assert findings[0].source == Source.AST

    def test_different_functions_no_finding(self):
        """Two very different functions do not trigger a clone finding."""
        from dojigiri.semantic.smells import check_semantic_clones
        code_a = _make_function("alpha", ["aaa", "bbb", "ccc", "ddd", "eee"], param_count=0)
        code_b = _make_function("omega", ["zzz", "yyy", "xxx", "www", "vvv", "uuu", "ttt", "sss"], param_count=5)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        findings = check_semantic_clones({"a.py": sem_a, "b.py": sem_b})

        assert len(findings) == 0

    def test_same_function_same_file_no_self_comparison(self):
        """A single function should not be compared with itself."""
        from dojigiri.semantic.smells import check_semantic_clones
        calls = ["init", "load", "parse", "validate", "execute"]
        code = _make_function("solo", calls)
        sem = _sem(code, "solo.py")

        findings = check_semantic_clones({"solo.py": sem})

        assert len(findings) == 0

    def test_below_threshold_no_finding(self):
        """With a very high threshold, even somewhat similar functions are not flagged."""
        from dojigiri.semantic.smells import check_semantic_clones
        # Same calls but different param counts
        code_a = _make_function("fn_a", ["read", "parse", "validate", "store", "done"], param_count=1)
        code_b = _make_function("fn_b", ["read", "parse", "validate", "store", "done"], param_count=5)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")

        # Use threshold=1.0 (exact match only)
        findings = check_semantic_clones(
            {"a.py": sem_a, "b.py": sem_b},
            similarity_threshold=1.0,
        )

        assert len(findings) == 0

    def test_multiple_clones_multiple_findings(self):
        """Three similar functions across files produce multiple findings."""
        from dojigiri.semantic.smells import check_semantic_clones
        calls = ["fetch", "decode", "validate", "transform", "persist"]
        code_a = _make_function("proc_a", calls)
        code_b = _make_function("proc_b", calls)
        code_c = _make_function("proc_c", calls)

        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        sem_c = _sem(code_c, "c.py")

        findings = check_semantic_clones({
            "a.py": sem_a, "b.py": sem_b, "c.py": sem_c,
        })

        # 3 functions -> 3 unique pairs: (a,b), (a,c), (b,c)
        assert len(findings) == 3
        for f in findings:
            assert f.rule == "semantic-clone"
            assert f.severity == Severity.INFO
