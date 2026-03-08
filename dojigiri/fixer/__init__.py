"""Fixer subpackage -- auto-fix engine for Dojigiri findings.

Re-exports the full public API so that `from dojigiri.fixer import X` continues
to work for every name that was importable from the old single-file fixer.py.

Submodules:
  - deterministic.py: 19 rule-specific fix functions + DETERMINISTIC_FIXERS registry
  - engine.py: fix_file orchestrator, apply_fixes, verify_fixes, validation/rollback
  - cascade.py: derive_expected_cascades (predicts side-effect findings)
  - llm_fixes.py: generate_llm_fixes (LLM-assisted patch generation)
  - helpers.py: shared AST/string/semantic utilities used across modules

Called by: __main__.py, mcp_server.py, tests
Calls into: all submodules (re-export only)
Data in -> Data out: (re-export hub, no data transformation)
"""

# ─── Engine (orchestration, application, verification) ────────────────
# ─── Cascade derivation ──────────────────────────────────────────────
from .cascade import derive_expected_cascades  # doji:ignore(unused-import)

# ─── Deterministic fixers (the catalog) ───────────────────────────────
from .deterministic import (  # doji:ignore(unused-import)
    DETERMINISTIC_FIXERS,
    FixerFn,
    _fix_bare_except,
    _fix_console_log,
    _fix_eval_usage,
    _fix_exception_swallowed,
    _fix_fstring_no_expr,
    _fix_hardcoded_secret,
    _fix_insecure_http,
    _fix_loose_equality,
    _fix_mutable_default,
    _fix_none_comparison,
    _fix_open_without_with,
    _fix_os_system,
    _fix_resource_leak,
    _fix_sql_injection,
    _fix_type_comparison,
    _fix_unreachable_code,
    _fix_unused_import,
    _fix_unused_variable,
    _fix_weak_hash,
    _fix_yaml_unsafe,
)
from .engine import apply_fixes, fix_file, verify_fixes  # doji:ignore(unused-import)

# ─── Helpers (re-exported for tests that import them directly) ────────
from .helpers import (
    _in_multiline_string,
    _pattern_outside_strings,
)

# ─── LLM fixes ───────────────────────────────────────────────────────
from .llm_fixes import generate_llm_fixes  # doji:ignore(unused-import)

__all__ = [
    # Engine
    "apply_fixes",
    "fix_file",
    "verify_fixes",
    # Deterministic fixers (public registry + type)
    "DETERMINISTIC_FIXERS",
    "FixerFn",
    # Cascade
    "derive_expected_cascades",
    # LLM
    "generate_llm_fixes",
]
# Note: Individual fixer functions (_fix_*) and helpers (_in_multiline_string,
# _pattern_outside_strings) are still importable via explicit import but are NOT
# part of __all__. Import them from their specific modules:
#   from dojigiri.fixer.deterministic import _fix_eval_usage
#   from dojigiri.fixer.helpers import _in_multiline_string
