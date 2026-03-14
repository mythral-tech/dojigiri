"""Direct tests for dojigiri/semantic/lang_config.py.

Validates structure, regex validity, type correctness, and cross-module
consistency of every LanguageConfig in LANGUAGE_CONFIGS.
"""

import re

import pytest

from dojigiri.semantic.lang_config import LANGUAGE_CONFIGS, LanguageConfig, get_config
from dojigiri.semantic.types import InferredType

ALL_LANGUAGES = sorted(LANGUAGE_CONFIGS.keys())

# Expected self keywords per language
EXPECTED_SELF_KEYWORDS = {
    "python": "self",
    "javascript": "this",
    "typescript": "this",
    "java": "this",
    "csharp": "this",
    "rust": "self",
    "go": "",  # Go has no self keyword — methods use named receivers
}

# Languages that use block scoping (curly-brace languages)
BLOCK_SCOPED_LANGUAGES = {"javascript", "typescript", "go", "rust", "java", "csharp"}
NON_BLOCK_SCOPED_LANGUAGES = {"python"}


# ── Structural completeness ──────────────────────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_config_is_language_config_instance(lang: str) -> None:
    """Every entry must be a LanguageConfig dataclass."""
    assert isinstance(LANGUAGE_CONFIGS[lang], LanguageConfig)


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_required_keys_present(lang: str) -> None:
    """Every config must have the critical analysis fields populated."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert cfg.ts_language_name, f"{lang}: ts_language_name empty"
    assert cfg.function_node_types, f"{lang}: function_node_types empty"
    assert cfg.return_node_types, f"{lang}: return_node_types empty"
    assert cfg.comment_node_types, f"{lang}: comment_node_types empty"
    assert cfg.assignment_node_types, f"{lang}: assignment_node_types empty"
    assert cfg.call_node_types, f"{lang}: call_node_types empty"
    assert cfg.scope_boundary_types, f"{lang}: scope_boundary_types empty"
    assert cfg.attribute_access_types, f"{lang}: attribute_access_types empty"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_ts_language_name_matches_key(lang: str) -> None:
    """ts_language_name should match the dict key (or be the TS variant)."""
    cfg = LANGUAGE_CONFIGS[lang]
    # csharp uses "csharp" as both key and ts_language_name
    assert cfg.ts_language_name == lang


# ── Taint patterns: non-empty ────────────────────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_sources_not_empty(lang: str) -> None:
    """Every language should define at least one taint source."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert len(cfg.taint_source_patterns) > 0, f"{lang}: no taint sources defined"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_sinks_not_empty(lang: str) -> None:
    """Every language should define at least one taint sink."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert len(cfg.taint_sink_patterns) > 0, f"{lang}: no taint sinks defined"


# ── Taint source patterns are valid 2-tuples of strings ──────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_source_pattern_structure(lang: str) -> None:
    """Each taint source must be a (pattern, category) string tuple."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, entry in enumerate(cfg.taint_source_patterns):
        assert isinstance(entry, tuple), f"{lang} source[{i}]: not a tuple"
        assert len(entry) == 2, f"{lang} source[{i}]: expected 2 elements, got {len(entry)}"
        pattern, category = entry
        assert isinstance(pattern, str) and pattern, f"{lang} source[{i}]: pattern empty/non-string"
        assert isinstance(category, str) and category, f"{lang} source[{i}]: category empty/non-string"


# ── Taint sink patterns are valid 2-tuples of strings ────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_sink_pattern_structure(lang: str) -> None:
    """Each taint sink must be a (pattern, category) string tuple."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, entry in enumerate(cfg.taint_sink_patterns):
        assert isinstance(entry, tuple), f"{lang} sink[{i}]: not a tuple"
        assert len(entry) == 2, f"{lang} sink[{i}]: expected 2 elements, got {len(entry)}"
        pattern, category = entry
        assert isinstance(pattern, str) and pattern, f"{lang} sink[{i}]: pattern empty/non-string"
        assert isinstance(category, str) and category, f"{lang} sink[{i}]: category empty/non-string"


# ── Taint sanitizer patterns are plain strings ───────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_sanitizer_patterns_are_strings(lang: str) -> None:
    """Sanitizer patterns are plain strings, not tuples or regex."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, entry in enumerate(cfg.taint_sanitizer_patterns):
        assert isinstance(entry, str), f"{lang} sanitizer[{i}]: expected str, got {type(entry).__name__}"


# ── Taint source/sink patterns compile as regex ──────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_source_patterns_valid_regex(lang: str) -> None:
    """Source patterns must be valid when treated as regex (re.escape for literal use)."""
    cfg = LANGUAGE_CONFIGS[lang]
    for pattern, _category in cfg.taint_source_patterns:
        try:
            re.compile(re.escape(pattern))
        except re.error as e:
            pytest.fail(f"{lang} source pattern {pattern!r} fails regex compile: {e}")


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_taint_sink_patterns_valid_regex(lang: str) -> None:
    """Sink patterns must be valid when treated as regex (re.escape for literal use)."""
    cfg = LANGUAGE_CONFIGS[lang]
    for pattern, _category in cfg.taint_sink_patterns:
        try:
            re.compile(re.escape(pattern))
        except re.error as e:
            pytest.fail(f"{lang} sink pattern {pattern!r} fails regex compile: {e}")


# ── Cross-module: LANGUAGE_CONFIGS keys vs LANGUAGE_RULES ────────────


def test_lang_configs_subset_of_language_rules() -> None:
    """Every language in LANGUAGE_CONFIGS should exist in LANGUAGE_RULES."""
    from dojigiri.languages import LANGUAGE_RULES

    missing = set(LANGUAGE_CONFIGS.keys()) - set(LANGUAGE_RULES.keys())
    # Note: LANGUAGE_RULES has "php" which LANGUAGE_CONFIGS doesn't — that's fine.
    # But every config language should have rules.
    assert not missing, f"Languages in LANGUAGE_CONFIGS but not LANGUAGE_RULES: {missing}"


def test_language_rules_coverage() -> None:
    """Check which LANGUAGE_RULES languages lack a LANGUAGE_CONFIG."""
    from dojigiri.languages import LANGUAGE_RULES

    missing = set(LANGUAGE_RULES.keys()) - set(LANGUAGE_CONFIGS.keys())
    # This is informational — some languages may only have regex rules, no semantic config.
    # PHP is expected to be missing. Fail if any unexpected language is missing.
    expected_missing = {"php"}
    unexpected = missing - expected_missing
    assert not unexpected, f"Unexpected languages in LANGUAGE_RULES without config: {unexpected}"


# ── Resource patterns: open/close pairs ──────────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_resource_patterns_structure(lang: str) -> None:
    """Resource patterns must be (open, close, has_context_manager, kind) 4-tuples."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, entry in enumerate(cfg.resource_patterns):
        assert isinstance(entry, tuple), f"{lang} resource[{i}]: not a tuple"
        assert len(entry) == 4, f"{lang} resource[{i}]: expected 4 elements, got {len(entry)}"
        open_pat, close_pat, has_ctx, kind = entry
        assert isinstance(open_pat, str) and open_pat, f"{lang} resource[{i}]: open_pattern empty"
        assert isinstance(close_pat, str) and close_pat, f"{lang} resource[{i}]: close_pattern empty"
        assert isinstance(has_ctx, bool), f"{lang} resource[{i}]: has_context_manager not bool"
        assert isinstance(kind, str) and kind, f"{lang} resource[{i}]: kind empty"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_resource_open_close_not_identical(lang: str) -> None:
    """Open and close patterns should be different."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, (open_pat, close_pat, _, _) in enumerate(cfg.resource_patterns):
        assert open_pat != close_pat, f"{lang} resource[{i}]: open == close ({open_pat!r})"


# ── Type inference: literal_type_map values are valid InferredType ───


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_literal_type_map_values_are_valid(lang: str) -> None:
    """All literal_type_map values must map to valid InferredType enum names."""
    cfg = LANGUAGE_CONFIGS[lang]
    valid_names = {t.name for t in InferredType}
    for node_type, type_name in cfg.literal_type_map.items():
        assert type_name in valid_names, (
            f"{lang} literal_type_map[{node_type!r}] = {type_name!r} "
            f"is not a valid InferredType (valid: {valid_names})"
        )


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_literal_type_map_keys_are_nonempty_strings(lang: str) -> None:
    """literal_type_map keys (tree-sitter node types) must be non-empty strings."""
    cfg = LANGUAGE_CONFIGS[lang]
    for key in cfg.literal_type_map:
        assert isinstance(key, str) and key, f"{lang}: empty literal_type_map key"


# ── Control flow node types ──────────────────────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_cfg_if_node_types_nonempty(lang: str) -> None:
    """Every language should have at least one if node type."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert cfg.cfg_if_node_types, f"{lang}: cfg_if_node_types empty"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_cfg_node_types_are_nonempty_strings(lang: str) -> None:
    """All CFG node type entries must be non-empty strings."""
    cfg = LANGUAGE_CONFIGS[lang]
    all_cfg_lists = [
        ("cfg_if", cfg.cfg_if_node_types),
        ("cfg_else", cfg.cfg_else_node_types),
        ("cfg_for", cfg.cfg_for_node_types),
        ("cfg_while", cfg.cfg_while_node_types),
        ("cfg_try", cfg.cfg_try_node_types),
        ("cfg_switch", cfg.cfg_switch_node_types),
    ]
    for name, node_list in all_cfg_lists:
        for i, node_type in enumerate(node_list):
            assert isinstance(node_type, str) and node_type, (
                f"{lang} {name}[{i}]: empty or non-string"
            )


# ── Self keyword correctness ────────────────────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_self_keyword(lang: str) -> None:
    """self_keyword should be correct for each language."""
    cfg = LANGUAGE_CONFIGS[lang]
    if lang in EXPECTED_SELF_KEYWORDS:
        assert cfg.self_keyword == EXPECTED_SELF_KEYWORDS[lang], (
            f"{lang}: expected self_keyword={EXPECTED_SELF_KEYWORDS[lang]!r}, got {cfg.self_keyword!r}"
        )


# ── Block scoping flag ──────────────────────────────────────────────


@pytest.mark.parametrize("lang", sorted(BLOCK_SCOPED_LANGUAGES))
def test_block_scoped_true(lang: str) -> None:
    """Curly-brace languages should have block_scoped=True."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert cfg.block_scoped is True, f"{lang}: expected block_scoped=True"


@pytest.mark.parametrize("lang", sorted(NON_BLOCK_SCOPED_LANGUAGES))
def test_block_scoped_false(lang: str) -> None:
    """Python (indentation-based) should have block_scoped=False."""
    cfg = LANGUAGE_CONFIGS[lang]
    assert cfg.block_scoped is False, f"{lang}: expected block_scoped=False"


# ── get_config helper ────────────────────────────────────────────────


def test_get_config_returns_config_for_known_language() -> None:
    cfg = get_config("python")
    assert cfg is not None
    assert isinstance(cfg, LanguageConfig)
    assert cfg.ts_language_name == "python"


def test_get_config_returns_none_for_unknown_language() -> None:
    assert get_config("brainfuck") is None


# ── No duplicate patterns within a language ──────────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_no_duplicate_taint_sources(lang: str) -> None:
    """No duplicate source patterns within a single language."""
    cfg = LANGUAGE_CONFIGS[lang]
    patterns = [p for p, _c in cfg.taint_source_patterns]
    dupes = [p for p in patterns if patterns.count(p) > 1]
    assert not dupes, f"{lang}: duplicate taint sources: {set(dupes)}"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_no_duplicate_taint_sinks(lang: str) -> None:
    """No duplicate sink patterns within a single language."""
    cfg = LANGUAGE_CONFIGS[lang]
    patterns = [p for p, _c in cfg.taint_sink_patterns]
    dupes = [p for p in patterns if patterns.count(p) > 1]
    assert not dupes, f"{lang}: duplicate taint sinks: {set(dupes)}"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_no_duplicate_sanitizers(lang: str) -> None:
    """No duplicate sanitizer patterns within a single language."""
    cfg = LANGUAGE_CONFIGS[lang]
    dupes = [p for p in cfg.taint_sanitizer_patterns if cfg.taint_sanitizer_patterns.count(p) > 1]
    assert not dupes, f"{lang}: duplicate sanitizers: {set(dupes)}"


# ── Branch/block node types are non-empty strings ────────────────────


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_branch_node_types_valid(lang: str) -> None:
    """branch_node_types entries must be non-empty strings."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, nt in enumerate(cfg.branch_node_types):
        assert isinstance(nt, str) and nt, f"{lang} branch_node_types[{i}]: empty/non-string"


@pytest.mark.parametrize("lang", ALL_LANGUAGES)
def test_block_node_types_valid(lang: str) -> None:
    """block_node_types entries must be non-empty strings."""
    cfg = LANGUAGE_CONFIGS[lang]
    for i, nt in enumerate(cfg.block_node_types):
        assert isinstance(nt, str) and nt, f"{lang} block_node_types[{i}]: empty/non-string"
