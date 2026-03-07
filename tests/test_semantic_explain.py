"""Tests for tutorial mode explanation generation (dojigiri.semantic.explain)."""

import pytest

from dojigiri.types import Finding, Severity, Category, Source

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


def _explain(code: str, filepath: str = "test.py", findings=None):
    """Generate explanation from Python code."""
    from dojigiri.semantic.explain import explain_file
    return explain_file(code, filepath, "python", findings=findings)


# ---------------------------------------------------------------------------
# BASIC EXPLANATION
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestBasicExplanation:
    """Basic FileExplanation construction from code."""

    def test_simple_function_has_summary_and_structure(self):
        """A file with one function produces a summary and structure section."""
        code = (
            "def greet(name):\n"
            "    return f'Hello, {name}'\n"
        )
        exp = _explain(code)

        assert exp.summary
        assert "1" in exp.summary or "function" in exp.summary.lower()
        assert len(exp.structure) >= 1

    def test_class_file_has_class_in_structure(self):
        """A file with a class lists the class in its structure."""
        code = (
            "class Calculator:\n"
            "    def __init__(self):\n"
            "        self.value = 0\n"
            "    def add(self, n):\n"
            "        self.value += n\n"
        )
        exp = _explain(code)

        titles = [s.title for s in exp.structure]
        assert any("Calculator" in t for t in titles)

    def test_empty_file_has_summary_no_structure(self):
        """An empty file still gets a summary but no structure sections."""
        code = ""
        exp = _explain(code)

        assert exp.summary
        assert len(exp.structure) == 0

    def test_returns_correct_filepath_and_language(self):
        """FileExplanation records filepath and language correctly."""
        code = "x = 1\n"
        exp = _explain(code, filepath="src/utils.py")

        assert exp.filepath == "src/utils.py"
        assert exp.language == "python"

    def test_multiple_functions_each_get_structure_section(self):
        """Each function in the file gets its own structure section."""
        code = (
            "def alpha():\n"
            "    pass\n"
            "\n"
            "def beta():\n"
            "    pass\n"
            "\n"
            "def gamma():\n"
            "    pass\n"
        )
        exp = _explain(code)

        func_sections = [s for s in exp.structure if "Function" in s.title]
        assert len(func_sections) >= 3


# ---------------------------------------------------------------------------
# STRUCTURE EXTRACTION
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestStructureExtraction:
    """Structure explanation details for functions and methods."""

    def test_function_with_params_lists_params(self):
        """Function params are listed in the explanation content."""
        code = (
            "def connect(host, port, timeout):\n"
            "    pass\n"
        )
        exp = _explain(code)

        func_section = [s for s in exp.structure if "connect" in s.title][0]
        assert "host" in func_section.content
        assert "port" in func_section.content
        assert "timeout" in func_section.content
        assert "3 parameter" in func_section.content

    def test_method_in_class_labeled_as_method(self):
        """A method inside a class is labeled 'Method of class X'."""
        code = (
            "class Engine:\n"
            "    def start(self):\n"
            "        pass\n"
        )
        exp = _explain(code)

        method_sections = [s for s in exp.structure if "start" in s.title]
        assert len(method_sections) >= 1
        section = method_sections[0]
        assert "Method" in section.title or "Method" in section.content
        assert "Engine" in section.content

    def test_private_function_noted_as_internal(self):
        """A function starting with _ is noted as private/internal."""
        code = (
            "def _helper(data):\n"
            "    return data.strip()\n"
        )
        exp = _explain(code)

        section = [s for s in exp.structure if "_helper" in s.title][0]
        assert "private" in section.content.lower() or "internal" in section.content.lower()

    def test_getter_function_noted_as_retrieval(self):
        """A function starting with get_ is noted as retrieval."""
        code = (
            "def get_user(user_id):\n"
            "    return db.find(user_id)\n"
        )
        exp = _explain(code)

        section = [s for s in exp.structure if "get_user" in s.title][0]
        assert "retrieve" in section.content.lower() or "return" in section.content.lower()

    def test_test_function_noted_as_test(self):
        """A function starting with test_ is noted as a test."""
        code = (
            "def test_connection():\n"
            "    assert True\n"
        )
        exp = _explain(code)

        section = [s for s in exp.structure if "test_connection" in s.title][0]
        assert "test" in section.content.lower()


# ---------------------------------------------------------------------------
# PATTERN RECOGNITION
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestPatternRecognition:
    """Design pattern detection via _detect_patterns."""

    def test_factory_function_detected(self):
        """Function named create_X with multiple returns is detected as Factory."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "def create_shape(kind):\n"
            "    if kind == 'circle':\n"
            "        return Circle()\n"
            "    elif kind == 'square':\n"
            "        return Square()\n"
            "    else:\n"
            "        return Triangle()\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Factory" in t for t in titles)

    def test_singleton_class_detected(self):
        """Class with _instance attribute is detected as Singleton."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "class Logger:\n"
            "    _instance = None\n"
            "    def __new__(cls):\n"
            "        if cls._instance is None:\n"
            "            cls._instance = super().__new__(cls)\n"
            "        return cls._instance\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Singleton" in t for t in titles)

    def test_decorator_function_detected(self):
        """Function with nested wrapper function is detected as Decorator."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "def log_calls(func):\n"
            "    def wrapper(*args, **kwargs):\n"
            "        print(f'Calling {func.__name__}')\n"
            "        return func(*args, **kwargs)\n"
            "    return wrapper\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Decorator" in t for t in titles)

    def test_builder_class_detected(self):
        """Class with 3+ return self methods is detected as Builder."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "class QueryBuilder:\n"
            "    def select(self, fields):\n"
            "        self._fields = fields\n"
            "        return self\n"
            "    def where(self, condition):\n"
            "        self._condition = condition\n"
            "        return self\n"
            "    def order_by(self, field):\n"
            "        self._order = field\n"
            "        return self\n"
            "    def limit(self, n):\n"
            "        self._limit = n\n"
            "        return self\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Builder" in t for t in titles)

    def test_observer_class_detected(self):
        """Class with subscribe/emit methods is detected as Observer."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "class EventBus:\n"
            "    def __init__(self):\n"
            "        self._listeners = []\n"
            "    def subscribe(self, listener):\n"
            "        self._listeners.append(listener)\n"
            "    def emit(self, event):\n"
            "        for listener in self._listeners:\n"
            "            listener(event)\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Observer" in t for t in titles)

    def test_iterator_class_detected(self):
        """Class with __iter__/__next__ is detected as Iterator."""
        from dojigiri.semantic.explain import _detect_patterns
        code = (
            "class Range:\n"
            "    def __init__(self, start, end):\n"
            "        self.current = start\n"
            "        self.end = end\n"
            "    def __iter__(self):\n"
            "        return self\n"
            "    def __next__(self):\n"
            "        if self.current >= self.end:\n"
            "            raise StopIteration\n"
            "        val = self.current\n"
            "        self.current += 1\n"
            "        return val\n"
        )
        sem = _sem(code)
        patterns = _detect_patterns(sem, code)

        titles = [p.title for p in patterns]
        assert any("Iterator" in t for t in titles)


# ---------------------------------------------------------------------------
# FINDING EXPLANATIONS
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestFindingExplanations:
    """Beginner-friendly finding explanation generation."""

    def test_taint_flow_finding_explained(self):
        """taint-flow rule gets a beginner explanation about user input."""
        code = "x = input()\neval(x)\n"
        findings = [Finding(
            file="test.py", line=2, severity=Severity.CRITICAL,
            category=Category.SECURITY, source=Source.AST,
            rule="taint-flow", message="User input reaches eval",
        )]
        exp = _explain(code, findings=findings)

        assert len(exp.findings_explained) >= 1
        section = exp.findings_explained[0]
        assert "taint-flow" in section.title
        assert "user input" in section.content.lower() or "input" in section.content.lower()

    def test_resource_leak_finding_explained(self):
        """resource-leak rule gets an explanation about closing resources."""
        code = "f = open('data.txt')\ndata = f.read()\n"
        findings = [Finding(
            file="test.py", line=1, severity=Severity.WARNING,
            category=Category.BUG, source=Source.AST,
            rule="resource-leak", message="File opened but not closed",
        )]
        exp = _explain(code, findings=findings)

        assert len(exp.findings_explained) >= 1
        section = exp.findings_explained[0]
        assert "resource-leak" in section.title
        assert "close" in section.content.lower() or "context manager" in section.content.lower()

    def test_null_dereference_finding_explained(self):
        """null-dereference rule gets an explanation about None checks."""
        code = "x = d.get('key')\nx.strip()\n"
        findings = [Finding(
            file="test.py", line=2, severity=Severity.WARNING,
            category=Category.BUG, source=Source.AST,
            rule="null-dereference", message="x may be None",
        )]
        exp = _explain(code, findings=findings)

        assert len(exp.findings_explained) >= 1
        section = exp.findings_explained[0]
        assert "null-dereference" in section.title
        assert "none" in section.content.lower() or "null" in section.content.lower()

    def test_unknown_rule_gets_default_explanation(self):
        """An unrecognized rule gets the default explanation text."""
        from dojigiri.semantic.explain import _FINDING_EXPLANATIONS
        code = "x = 1\n"
        findings = [Finding(
            file="test.py", line=1, severity=Severity.INFO,
            category=Category.STYLE, source=Source.STATIC,
            rule="totally-unknown-rule-xyz", message="Something unusual",
        )]
        exp = _explain(code, findings=findings)

        assert len(exp.findings_explained) >= 1
        section = exp.findings_explained[0]
        # Should use the default, not crash
        assert "totally-unknown-rule-xyz" not in _FINDING_EXPLANATIONS
        assert "static analyzer" in section.content.lower() or "review" in section.content.lower()

    def test_multiple_same_rule_findings_explained_once(self):
        """Multiple findings with the same rule are explained only once."""
        code = "a = 1\nb = 2\nc = 3\n"
        findings = [
            Finding(
                file="test.py", line=1, severity=Severity.INFO,
                category=Category.STYLE, source=Source.AST,
                rule="unused-variable", message="'a' is unused",
            ),
            Finding(
                file="test.py", line=2, severity=Severity.INFO,
                category=Category.STYLE, source=Source.AST,
                rule="unused-variable", message="'b' is unused",
            ),
            Finding(
                file="test.py", line=3, severity=Severity.INFO,
                category=Category.STYLE, source=Source.AST,
                rule="unused-variable", message="'c' is unused",
            ),
        ]
        exp = _explain(code, findings=findings)

        # Only one explanation section for unused-variable, not three
        unused_sections = [
            s for s in exp.findings_explained
            if "unused-variable" in s.title
        ]
        assert len(unused_sections) == 1


# ---------------------------------------------------------------------------
# LEARNING NOTES
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestLearningNotes:
    """Learning notes generated from code features."""

    def test_code_with_decorators_generates_note(self):
        """Code using @decorator syntax triggers a learning note about decorators."""
        code = (
            "@staticmethod\n"
            "def helper():\n"
            "    pass\n"
        )
        exp = _explain(code)

        assert any("decorator" in note.lower() for note in exp.learning_notes)

    def test_code_with_yield_generates_note(self):
        """Code using yield triggers a learning note about generators."""
        code = (
            "def counter(n):\n"
            "    i = 0\n"
            "    while i < n:\n"
            "        yield i\n"
            "        i += 1\n"
        )
        exp = _explain(code)

        assert any("generator" in note.lower() for note in exp.learning_notes)

    def test_code_with_async_generates_note(self):
        """Code using async/await triggers a learning note about async."""
        code = (
            "async def fetch_data(url):\n"
            "    result = await get(url)\n"
            "    return result\n"
        )
        exp = _explain(code)

        assert any("async" in note.lower() for note in exp.learning_notes)

    def test_code_with_class_generates_oop_note(self):
        """Code with a class and methods triggers a learning note about OOP."""
        code = (
            "class Animal:\n"
            "    def __init__(self, name):\n"
            "        self.name = name\n"
            "    def speak(self):\n"
            "        return f'{self.name} speaks'\n"
        )
        exp = _explain(code)

        assert any(
            "object-oriented" in note.lower() or "oop" in note.lower()
            for note in exp.learning_notes
        )
