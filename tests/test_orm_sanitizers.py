"""Tests for ORM sanitizer awareness across both taint engines.

Covers:
- Safe ORM patterns (should NOT produce findings)
- Unsafe raw SQL patterns (MUST produce findings)
- Edge cases: variable naming, builtin receiver exclusion, text() handling
- Cross-engine consistency: same code → same result in both engines
- Type inference for ORM factory calls
"""

import pytest

from dojigiri.taint_cross import analyze_taint_ast, _call_is_sanitizer
from dojigiri.semantic.core import extract_semantics
from dojigiri.semantic.taint import analyze_taint
from dojigiri.semantic.lang_config import get_config
from dojigiri.semantic.types import infer_types, InferredType

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


def _analyze_python_semantic(code: str):
    """Run tree-sitter taint analysis on Python code."""
    config = get_config("python")
    sem = extract_semantics(code, "test.py", "python")
    if sem is None:
        return []
    source_bytes = code.encode("utf-8")
    return analyze_taint(sem, source_bytes, config, "test.py")


def _infer_python_types(code: str):
    """Run type inference on Python code, return FileTypeMap."""
    config = get_config("python")
    sem = extract_semantics(code, "test.py", "python")
    if sem is None:
        return None
    source_bytes = code.encode("utf-8")
    return infer_types(sem, source_bytes, config)


# ─── AST Engine: Safe ORM Patterns ──────────────────────────────────────


class TestASTEngineSafeORM:
    """Safe ORM patterns should produce no findings in the AST engine."""

    def test_sqlalchemy_select_where(self):
        code = '''
def process(user_id):
    stmt = select(User).where(User.id == user_id)
    session.execute(stmt)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) == 0

    def test_sqlalchemy_filter_by(self):
        code = '''
def process(name):
    result = session.query(User).filter_by(name=name)
    return result
'''
        findings = analyze_taint_ast("test.py", code)
        assert len([f for f in findings if f.rule == "taint-flow"]) == 0

    def test_django_objects_filter(self):
        code = '''
def process(user_id):
    result = User.objects.filter(id=user_id)
    return result
'''
        findings = analyze_taint_ast("test.py", code)
        assert len([f for f in findings if f.rule == "taint-flow"]) == 0

    def test_sqlalchemy_insert_values(self):
        code = '''
def process(name):
    stmt = insert(User).values(name=name)
    session.execute(stmt)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len([f for f in findings if f.rule == "taint-flow"]) == 0


# ─── AST Engine: Unsafe Raw SQL ─────────────────────────────────────────


class TestASTEngineUnsafeSQL:
    """Unsafe raw SQL patterns MUST produce findings."""

    def test_fstring_sql_execute(self):
        code = '''
def process(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1

    def test_concat_sql_execute(self):
        code = '''
def process(user_input):
    query = "SELECT * FROM users WHERE name = " + user_input
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len([f for f in findings if f.rule == "taint-flow"]) >= 1

    def test_text_with_fstring_unsafe(self):
        """text(f"SELECT {x}") wraps raw SQL — TextClause is NOT in safe list."""
        code = '''
def process(user_input):
    stmt = text(f"SELECT {user_input}")
    conn.execute(stmt)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1

    def test_raw_cursor_execute(self):
        code = '''
def process(user_input):
    cursor.execute(f"DELETE FROM users WHERE id={user_input}")
'''
        findings = analyze_taint_ast("test.py", code)
        assert len([f for f in findings if f.rule == "taint-flow"]) >= 1

    def test_param_to_execute_still_flags(self):
        """def process(query): conn.execute(query) — untyped param MUST flag."""
        code = '''
def process(query):
    conn.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1


# ─── Source-Aware Parameter Taint ────────────────────────────────────────


class TestSourceAwareParamTaint:
    """Parameters with ORM type annotations should be suppressed at SQL sinks."""

    def test_typed_select_param_suppressed(self):
        """def run(stmt: Select): session.execute(stmt) — typed safe, no finding."""
        code = '''
def run(stmt: Select):
    session.execute(stmt)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"
                          and "sql_query" in f.message]
        assert len(taint_findings) == 0

    def test_typed_query_param_suppressed(self):
        code = '''
def run(q: Query):
    session.execute(q)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"
                          and "sql_query" in f.message]
        assert len(taint_findings) == 0

    def test_untyped_param_still_flags(self):
        """Untyped parameter to SQL sink MUST still flag."""
        code = '''
def run(query):
    session.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1

    def test_typed_safe_still_flags_eval(self):
        """ORM-typed param should still flag at eval() — not just SQL sinks."""
        code = '''
def run(stmt: Select):
    eval(stmt)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1


# ─── Builtin Receiver Exclusion ──────────────────────────────────────────


class TestBuiltinReceiverExclusion:
    """list.filter(), dict.update() etc. should NOT be treated as ORM sanitizers."""

    def test_list_filter_not_sanitizer(self):
        assert _call_is_sanitizer("list.filter") is False

    def test_dict_update_not_sanitizer(self):
        assert _call_is_sanitizer("dict.update") is False

    def test_set_update_not_sanitizer(self):
        assert _call_is_sanitizer("set.update") is False

    def test_str_join_not_sanitizer(self):
        assert _call_is_sanitizer("str.join") is False

    def test_queryset_filter_is_sanitizer(self):
        assert _call_is_sanitizer("qs.filter") is True

    def test_stmt_where_is_sanitizer(self):
        assert _call_is_sanitizer("stmt.where") is True

    def test_bare_select_is_sanitizer(self):
        assert _call_is_sanitizer("select") is True

    def test_bare_int_is_sanitizer(self):
        assert _call_is_sanitizer("int") is True


# ─── ORM Type Inference ──────────────────────────────────────────────────


@needs_tree_sitter
class TestORMTypeInference:
    """Type inference should recognize ORM factory calls."""

    def test_select_infers_select_type(self):
        code = '''
def foo():
    stmt = select(User)
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        # Find the stmt variable type
        found = False
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.inferred_type == InferredType.INSTANCE
                assert tinfo.class_name == "Select"
                found = True
        assert found, "stmt not found in type map"

    def test_insert_infers_insert_type(self):
        code = '''
def foo():
    stmt = insert(User).values(name="x")
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        found = False
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.class_name == "Insert"
                found = True
        assert found

    def test_update_infers_update_type(self):
        code = '''
def foo():
    stmt = update(User).where(User.id == 1)
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        found = False
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.class_name == "Update"
                found = True
        assert found

    def test_delete_infers_delete_type(self):
        code = '''
def foo():
    stmt = delete(User).where(User.id == 1)
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        found = False
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.class_name == "Delete"
                found = True
        assert found

    def test_text_not_in_safe_types(self):
        """text() should NOT infer as a safe ORM type."""
        code = '''
def foo():
    stmt = text("SELECT 1")
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                # text() returns TextClause but it's NOT in ORM_FACTORY_CALLS
                # so it should NOT get typed as Select/Insert/etc.
                assert tinfo.class_name not in ("Select", "Insert", "Update", "Delete")

    def test_fstring_not_orm_type(self):
        """f-string SQL should NOT get ORM type."""
        code = '''
def foo():
    x = "test"
    stmt = f"SELECT {x}"
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.inferred_type != InferredType.INSTANCE or tinfo.class_name not in (
                    "Select", "Insert", "Update", "Delete"
                )

    def test_select_with_dotted_prefix(self):
        """sa.select(User) should also infer as Select."""
        code = '''
def foo():
    stmt = sa.select(User)
'''
        type_map = _infer_python_types(code)
        assert type_map is not None
        found = False
        for (name, _), tinfo in type_map.types.items():
            if name == "stmt":
                assert tinfo.class_name == "Select"
                found = True
        assert found


# ─── Semantic Engine: ORM Sanitizer Patterns ─────────────────────────────


@needs_tree_sitter
class TestSemanticEngineORM:
    """ORM patterns in the tree-sitter engine."""

    def test_select_where_sanitizes(self):
        """select(User).where() should suppress taint for the assigned variable."""
        code = '''
def handle():
    user_input = input("Enter ID: ")
    stmt = select(User).where(User.id == user_input)
    session.execute(stmt)
'''
        findings = _analyze_python_semantic(code)
        sql_findings = [f for f in findings if "sql" in f.rule.lower() or "taint" in f.rule.lower()]
        # The select(...).where(...) pattern should sanitize
        assert len(sql_findings) == 0

    def test_raw_fstring_still_flags(self):
        """Raw f-string SQL must still flag even with taint source."""
        code = '''
def handle():
    name = input("Enter name: ")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
'''
        findings = _analyze_python_semantic(code)
        taint_findings = [f for f in findings if "taint" in f.rule.lower() or "sql" in f.rule.lower()]
        assert len(taint_findings) >= 1


# ─── Cross-Engine Consistency ────────────────────────────────────────────


@needs_tree_sitter
class TestCrossEngineConsistency:
    """Both engines should agree on basic safe/unsafe classifications."""

    def test_both_flag_fstring_sql(self):
        code = '''
def handle(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
'''
        ast_findings = [f for f in analyze_taint_ast("test.py", code) if f.rule == "taint-flow"]
        sem_findings = [f for f in _analyze_python_semantic(code) if "taint" in f.rule or "sql" in f.rule]
        # At least one engine must flag
        assert len(ast_findings) >= 1 or len(sem_findings) >= 1

    def test_both_suppress_orm_select(self):
        code = '''
def handle(user_id):
    stmt = select(User).where(User.id == user_id)
    session.execute(stmt)
'''
        ast_findings = [f for f in analyze_taint_ast("test.py", code) if f.rule == "taint-flow"]
        sem_findings = [f for f in _analyze_python_semantic(code) if "taint" in f.rule or "sql" in f.rule]
        # Both should suppress ORM select
        assert len(ast_findings) == 0
        assert len(sem_findings) == 0

    def test_sanitized_int_consistent(self):
        code = '''
def handle(user_input):
    safe = int(user_input)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe}")
'''
        ast_findings = [f for f in analyze_taint_ast("test.py", code) if f.rule == "taint-flow"]
        sem_findings = [f for f in _analyze_python_semantic(code) if "taint" in f.rule or "sql" in f.rule]
        # int() sanitizes in both engines
        assert len(ast_findings) == 0
        assert len(sem_findings) == 0
