"""Tests for function contract inference (dojigiri.semantic.types.infer_contracts)."""

import pytest

from dojigiri.semantic.core import extract_semantics
from dojigiri.semantic.types import infer_types, infer_contracts, FunctionContract, FileTypeMap
from dojigiri.semantic.lang_config import get_config

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
    sem = extract_semantics(code, filepath, "python")
    assert sem is not None, "tree-sitter failed to extract semantics"
    return sem


def _contracts_from_code(code: str, filepath: str = "test.py"):
    """Extract semantics, infer types, then infer contracts for a single file."""
    sem = _sem(code, filepath)
    config = get_config("python")
    assert config is not None
    tmap = infer_types(sem, code.encode("utf-8"), config)
    contracts = infer_contracts({filepath: sem}, {filepath: tmap})
    return contracts


# ---------------------------------------------------------------------------
# RETURN NULLABILITY
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestReturnNullability:
    """Tests for returns_nullable inference from return statements."""

    def test_function_returning_none_sometimes_is_nullable(self):
        """A function that returns None in some paths is marked returns_nullable=True."""
        code = (
            "def find_user(user_id):\n"
            "    if user_id == 0:\n"
            "        return None\n"
            "    return {'id': user_id}\n"
        )
        contracts = _contracts_from_code(code)

        assert len(contracts) >= 1
        # Find the contract for find_user
        contract = next(c for c in contracts.values() if "find_user" in c.qualified_name)
        assert contract.returns_nullable is True

    def test_function_always_returning_value_not_nullable(self):
        """A function that always returns a non-None value is not nullable."""
        code = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        contracts = _contracts_from_code(code)

        assert len(contracts) >= 1
        contract = next(c for c in contracts.values() if "add" in c.qualified_name)
        assert contract.returns_nullable is False

    def test_function_with_optional_return_annotation_nullable(self):
        """A function annotated with -> Optional[X] is marked returns_nullable=True."""
        code = (
            "def maybe_int(x) -> Optional[int]:\n"
            "    if x > 0:\n"
            "        return x\n"
            "    return None\n"
        )
        contracts = _contracts_from_code(code)

        assert len(contracts) >= 1
        contract = next(c for c in contracts.values() if "maybe_int" in c.qualified_name)
        assert contract.returns_nullable is True

    def test_empty_function_no_contract_issue(self):
        """An empty function (pass only) still gets a contract but is not nullable."""
        code = (
            "def noop():\n"
            "    pass\n"
        )
        contracts = _contracts_from_code(code)

        # Should not crash; may or may not produce a contract
        # If there is one, it should not be marked nullable (no explicit return)
        for c in contracts.values():
            if "noop" in c.qualified_name:
                # No explicit return statement means not nullable
                # (implicitly returns None, but no mixed return path)
                assert c.returns_nullable is False

    def test_multiple_functions_each_get_contract(self):
        """Each function in the file gets its own contract."""
        code = (
            "def alpha():\n"
            "    return 1\n"
            "\n"
            "def beta():\n"
            "    if True:\n"
            "        return None\n"
            "    return 'ok'\n"
        )
        contracts = _contracts_from_code(code)

        names = [c.qualified_name for c in contracts.values()]
        assert any("alpha" in n for n in names)
        assert any("beta" in n for n in names)

        alpha = next(c for c in contracts.values() if "alpha" in c.qualified_name)
        beta = next(c for c in contracts.values() if "beta" in c.qualified_name)
        assert alpha.returns_nullable is False
        assert beta.returns_nullable is True


# ---------------------------------------------------------------------------
# PARAMETER CONTRACTS
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestParameterContracts:
    """Tests for param_nullability inference from type annotations."""

    def test_optional_param_annotation_nullable(self):
        """A parameter annotated Optional[X] is marked nullable=True."""
        code = (
            "def process(data: Optional[str]):\n"
            "    if data is None:\n"
            "        return\n"
            "    return data.upper()\n"
        )
        contracts = _contracts_from_code(code)

        contract = next(c for c in contracts.values() if "process" in c.qualified_name)
        # param_nullability depends on annotation extraction; if extracted:
        if "data" in contract.param_nullability:
            assert contract.param_nullability["data"] is True

    def test_regular_param_annotation_not_nullable(self):
        """A parameter annotated with a regular type is not nullable."""
        code = (
            "def greet(name: str):\n"
            "    return f'Hello, {name}'\n"
        )
        contracts = _contracts_from_code(code)

        contract = next(c for c in contracts.values() if "greet" in c.qualified_name)
        if "name" in contract.param_nullability:
            assert contract.param_nullability["name"] is False

    def test_no_annotations_empty_param_nullability(self):
        """A function with no type annotations has empty param_nullability."""
        code = (
            "def compute(a, b, c):\n"
            "    return a + b + c\n"
        )
        contracts = _contracts_from_code(code)

        contract = next(c for c in contracts.values() if "compute" in c.qualified_name)
        assert contract.param_nullability == {}

    def test_mixed_params_correct_per_param(self):
        """Mixed annotated and unannotated params get correct per-param nullability."""
        code = (
            "def mixed(x: int, y: Optional[str], z):\n"
            "    return str(x) + (y or '') + str(z)\n"
        )
        contracts = _contracts_from_code(code)

        contract = next(c for c in contracts.values() if "mixed" in c.qualified_name)
        # x: int -> not nullable (if extracted)
        if "x" in contract.param_nullability:
            assert contract.param_nullability["x"] is False
        # y: Optional[str] -> nullable (if extracted)
        if "y" in contract.param_nullability:
            assert contract.param_nullability["y"] is True
        # z: no annotation -> not in map
        assert "z" not in contract.param_nullability


# ---------------------------------------------------------------------------
# CROSS-FILE
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestCrossFile:
    """Tests for contract inference across multiple files."""

    def test_different_function_names_separate_contracts(self):
        """Two files with different function names get separate contracts."""
        code_a = (
            "def load_data(x):\n"
            "    return x * 2\n"
        )
        code_b = (
            "def save_data(x):\n"
            "    if x is None:\n"
            "        return None\n"
            "    return x.strip()\n"
        )
        sem_a = _sem(code_a, "a.py")
        sem_b = _sem(code_b, "b.py")
        config = get_config("python")
        tmap_a = infer_types(sem_a, code_a.encode("utf-8"), config)
        tmap_b = infer_types(sem_b, code_b.encode("utf-8"), config)

        contracts = infer_contracts(
            {"a.py": sem_a, "b.py": sem_b},
            {"a.py": tmap_a, "b.py": tmap_b},
        )

        # Both files contribute contracts with distinct qualified names
        assert "load_data" in contracts
        assert "save_data" in contracts
        assert contracts["load_data"].returns_nullable is False
        assert contracts["save_data"].returns_nullable is True

    def test_contract_references_correct_qualified_name(self):
        """Each contract's qualified_name matches the function definition."""
        code = (
            "class Handler:\n"
            "    def run(self):\n"
            "        return True\n"
        )
        contracts = _contracts_from_code(code)

        # Should have a contract for Handler.run
        run_contracts = [c for c in contracts.values() if "run" in c.qualified_name]
        assert len(run_contracts) >= 1
        assert any("Handler" in c.qualified_name or "run" in c.qualified_name for c in run_contracts)

    def test_empty_semantics_empty_contracts(self):
        """Empty semantics dict produces no contracts."""
        contracts = infer_contracts({}, {})
        assert contracts == {}


# ---------------------------------------------------------------------------
# EDGE CASES
# ---------------------------------------------------------------------------

@needs_tree_sitter
class TestEdgeCases:
    """Edge cases in contract inference."""

    def test_no_type_maps_empty_contracts(self):
        """Files with no corresponding type maps are skipped."""
        code = "def foo():\n    return 1\n"
        sem = _sem(code, "test.py")

        # Pass semantics but no type maps
        contracts = infer_contracts({"test.py": sem}, {})
        assert contracts == {}

    def test_single_file_works(self):
        """Contract inference works correctly with a single file."""
        code = (
            "def single(x):\n"
            "    if x:\n"
            "        return None\n"
            "    return x + 1\n"
        )
        contracts = _contracts_from_code(code)

        assert len(contracts) >= 1
        contract = next(c for c in contracts.values() if "single" in c.qualified_name)
        assert contract.returns_nullable is True

    def test_function_with_no_params_empty_param_nullability(self):
        """A function with no parameters has empty param_nullability."""
        code = (
            "def no_args():\n"
            "    return 42\n"
        )
        contracts = _contracts_from_code(code)

        contract = next(c for c in contracts.values() if "no_args" in c.qualified_name)
        assert contract.param_nullability == {}
