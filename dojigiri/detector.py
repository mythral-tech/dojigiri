"""Static analysis engine — regex matching + Python AST parsing.

Orchestrator module with intentionally high coupling — dispatches to all
analysis subsystems by design.

Runs language-specific regex rules and, for Python files, a full suite of
AST-based semantic checks (scope, taint, CFG, types, null-safety, resources).

Called by: analyzer.py.
Calls into: config.py, languages.py, ast_checks.py, semantic/checks.py,
    semantic/core.py, semantic/scope.py, semantic/taint.py, semantic/cfg.py,
    semantic/types.py, semantic/nullsafety.py, semantic/resource.py,
    semantic/smells.py.
Data in → Data out: (filepath, content, language) in → list[Finding] out.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from .ast_checks import run_python_ast_checks
from .languages import get_rules_for_language
from .types import Category, Finding, Severity, Source

if TYPE_CHECKING:
    from .semantic.core import FileSemantics
    from .semantic.lang_config import LanguageConfig
    from .semantic.types import FileTypeMap
    from .types import StaticAnalysisResult

# Security-related categories where string lines should still be scanned
_SECURITY_CATEGORIES = {Category.SECURITY}

# Rules that specifically target comments — never skip on comment lines
_COMMENT_RULES = {"todo-marker"}

# Rules to suppress in test/example files (high FP in non-production code)
_SKIP_IN_TEST_FILES = {
    "insecure-http",
    "console-log",
    "assert-statement",      # tests are *supposed* to use assert
    "unused-variable",       # test fixtures, setup vars, captures
    "variable-shadowing",    # parametrize/fixtures reuse names freely
    "long-method",           # test functions are naturally long
    "too-many-args",         # parametrized tests have many args
    "feature-envy",          # tests naturally reach into objects
    "ssrf-risk",             # tests use URLs/endpoints by design
    "requests-no-timeout",   # test HTTP calls don't need timeouts
    "hardcoded-ip",          # test fixtures use literal IPs
    "hardcoded-secret",      # test credentials are intentional
    "hardcoded-secret-dict", # test config dicts with fake keys
    "hardcoded-password",    # test passwords are intentional
    "hardcoded-api-key",     # test API keys are fake
    "db-connection-string",  # test connection strings are local/fake
    "flask-secret-hardcoded",  # test Flask configs use dummy secrets
    "subprocess-audit",      # test harness subprocess calls
    "resource-leak",         # test client responses, fixtures handle cleanup
    "null-dereference",      # TestClient.get() never returns None
    "pickle-unsafe",         # test roundtrip serialization is safe
    "dynamic-import",        # test fixtures use importlib with hardcoded values
    "weak-random",           # tests using random for sample data
    "toctou-file-check",     # test file operations aren't security-sensitive
    "sys-path-modify",       # test setup modifying paths
    "exception-swallowed",   # tests intentionally catch and ignore
    "exception-swallowed-continue",  # same pattern with continue
    "debug-enabled",         # tests intentionally enable debug mode
    "weak-hash",             # test cryptographic operations
}
_SKIP_IN_EXAMPLE_FILES = {
    "console-log",
    "assert-statement",      # tutorial code uses assert for illustration
    "hardcoded-secret",      # example credentials are intentional
    "hardcoded-secret-dict", # example config dicts with fake keys
    "hardcoded-password",    # example passwords are intentional
    "hardcoded-api-key",     # example API keys are fake
    "db-connection-string",  # example connection strings are illustrative
    "hardcoded-ip",          # example IPs are illustrative
    "subprocess-audit",      # example shell commands are instructional
    "unused-variable",       # snippets often declare without using
}

# Path segments identifying test and example files
_TEST_PATH_SEGMENTS = ("/test/", "/tests/", "test_", "_test.", ".test.", ".spec.", "/spec/", "/specs/", "/__tests__/", "/__mocks__/")
_TEST_FILENAMES = ("conftest.py",)  # exact filenames that are always test infra
_EXAMPLE_PATH_SEGMENTS = ("/examples/", "/example/", "/docs_src/", "/doc/", "/scripts/")

# Inline comment patterns per language family
_INLINE_COMMENT_RE = {
    "hash": re.compile(r"""(?<!['"\\])#(?![!])"""),  # Python/Ruby/Bash style
    "slash": re.compile(r"""(?<!['"\\:])//"""),  # C-family style
}

# Single source of truth: language -> comment style ("hash" or "slash")
_SLASH_LANGUAGES = frozenset(
    {
        "javascript",
        "typescript",
        "go",
        "rust",
        "java",
        "c",
        "cpp",
        "csharp",
        "swift",
        "kotlin",
        "pine",
    }
)
_HASH_LANGUAGES = frozenset({"python", "ruby", "bash"})


def _is_test_path(fp_lower: str) -> bool:
    """Return True if the normalized-lowercase path looks like a test file."""
    if any(seg in fp_lower for seg in _TEST_PATH_SEGMENTS):
        return True
    # Check exact filenames (e.g. conftest.py at any level)
    basename = fp_lower.rsplit("/", 1)[-1]
    return basename in _TEST_FILENAMES


def _get_comment_style(language: str) -> str | None:
    """Return 'hash' or 'slash' for the language, or None if unknown."""
    if language in _HASH_LANGUAGES:
        return "hash"
    if language in _SLASH_LANGUAGES:
        return "slash"
    return None


# Regex to detect lines that are predominantly string content
# Catches: var = 'javascript:eval(...)' and similar mid-line strings
_STRING_CONTENT_RE = re.compile(
    r"""['"][^'"]*(?:eval|exec)\s*\([^'"]*['"]"""  # eval/exec inside string literal
)

# Inline suppression: doji:ignore or doji:ignore(rule-a, rule-b, ...)
# \b prevents matching "undoji:ignore" etc. Empty parens doji:ignore()
# won't match the inner group ([a-z0-9...]+) so fall through to bare
# doji:ignore behavior (suppress all) — this is intentional.
_DOJI_IGNORE_RE = re.compile(r"\bdoji:ignore(?:\(([a-z0-9_,\s-]+)\))?")


def _parse_line_suppression(line: str, language: str) -> set[str] | bool | None:
    """Parse a doji:ignore directive from a line's trailing comment.

    Returns:
        True — suppress all rules (bare doji:ignore)
        set[str] — suppress only these rule names
        None — no suppression directive found
    """
    style = _get_comment_style(language)
    if style is None:
        return None

    pattern = _INLINE_COMMENT_RE[style]

    # Find the LAST comment marker — rightmost match is most likely the real
    # trailing comment, not one inside a string earlier on the line.
    last_match = None
    for m in pattern.finditer(line):
        last_match = m
    if last_match is None:
        return None

    comment_text = line[last_match.start() :]
    ignore_match = _DOJI_IGNORE_RE.search(comment_text)
    if not ignore_match:
        return None

    # No rule name in parens → suppress all
    rule_text = ignore_match.group(1)
    if rule_text is None:
        return True

    # Comma-separated rule names
    return {r.strip() for r in rule_text.split(",") if r.strip()}


def _is_line_suppressed(lines: list[str], line_no: int, rule: str, language: str) -> bool:
    """Check if a finding on the given line is suppressed by an inline doji:ignore comment.

    Only matches doji:ignore inside actual trailing comments (not string literals).
    line_no is 1-based.
    """
    if line_no < 1 or line_no > len(lines):
        return False

    result = _parse_line_suppression(lines[line_no - 1], language)
    if result is None:
        return False
    if result is True:
        return True
    return rule in result


def _strip_inline_comment(line: str, language: str) -> str:
    """Strip trailing inline comment from a line for non-security checks.

    Conservative: if in doubt, returns the full line (avoids hiding issues).
    Note: intentionally uses the FIRST comment marker match (via .search()),
    unlike _parse_line_suppression which uses the LAST. Stripping from the
    first '#' is the safe direction — it removes more, so more code is hidden
    from the pattern matcher, meaning fewer false positives (not more).
    """
    style = _get_comment_style(language)
    if style is None:
        return line

    m = _INLINE_COMMENT_RE[style].search(line)
    if m:
        return line[: m.start()]
    return line


def _get_block_comment_delimiters(language: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (block_open, block_close, alt_block_open, alt_block_close) for a language."""
    if language == "python":
        return '"""', '"""', "'''", "'''"
    elif language in ("html", "css"):
        return "<!--", "-->", "/*", "*/"
    elif language in _SLASH_LANGUAGES:
        return "/*", "*/", None, None
    return None, None, None, None


def _check_block_comment_open(stripped: str, opener: str, language: str) -> bool:
    """Check if a stripped line opens a block comment with the given delimiter."""
    if language == "python":
        if stripped.startswith(opener):
            after_open = stripped[len(opener):]
            if not after_open or after_open[0] not in ")],;":
                return True
        return False
    return opener in stripped


def _update_block_comment_state(
    stripped: str, language: str, in_block_comment: bool, block_comment_delimiter: str | None,
    block_open: str | None, block_close: str | None, alt_block_open: str | None, alt_block_close: str | None,
) -> tuple[bool, str | None, bool]:
    """Track block comment state for a single line.

    Returns (in_block_comment, block_comment_delimiter, should_skip_line).
    """
    if block_open and not in_block_comment:
        if _check_block_comment_open(stripped, block_open, language):
            idx = stripped.index(block_open)
            rest = stripped[idx + len(block_open):]
            if block_close not in rest:  # type: ignore[operator]  # block_close is non-None here
                return True, block_close, True
        elif alt_block_open:
            if _check_block_comment_open(stripped, alt_block_open, language):
                idx = stripped.index(alt_block_open)
                rest = stripped[idx + len(alt_block_open):]
                if alt_block_close not in rest:  # type: ignore[operator]  # alt_block_close is non-None here
                    return True, alt_block_close, True
    elif in_block_comment:
        if block_comment_delimiter and block_comment_delimiter in stripped:
            return False, None, True
        return True, block_comment_delimiter, True

    return in_block_comment, block_comment_delimiter, False


def _match_rule_with_context(
    rule_name: str, line_num: int, lines: list[str],
) -> bool:
    """Apply rule-specific context suppression. Returns True if the match should be kept."""
    if rule_name == "yaml-unsafe":
        context_start = max(0, line_num - 2)
        context_end = min(len(lines), line_num + 3)
        context = "\n".join(lines[context_start:context_end])
        if "SafeLoader" in context or "safe_load" in context:
            return False

    if rule_name == "java-async-file-operation":
        context_start = max(0, line_num - 30)
        context = "\n".join(lines[context_start:line_num - 1])
        if "@Async" not in context:
            return False

    return True


def _should_skip_rule_for_line(rule_name: str, category: Category, is_comment: bool, is_string_line: bool, skip_rules: set[str], stripped: str) -> bool:
    """Check if a rule should be skipped for this line based on context."""
    if is_comment and rule_name not in _COMMENT_RULES:
        return True
    if rule_name in skip_rules:
        return True
    if is_string_line and category not in _SECURITY_CATEGORIES:
        return True
    if rule_name in ("eval-usage", "exec-usage") and _STRING_CONTENT_RE.search(stripped):
        return True
    return False


def _get_check_line(line: str, language: str, category: Category, rule_name: str) -> str:
    """Return the line to match against, stripping inline comments for non-security rules."""
    if category not in _SECURITY_CATEGORIES and rule_name not in _COMMENT_RULES:
        return _strip_inline_comment(line, language)
    return line


def _check_builtin_rules(rules: list[tuple], line: str, stripped: str, line_num: int, lines: list[str], language: str,
                         is_comment: bool, is_string_line: bool, skip_rules: set[str], filepath: str,
                         is_suppressed: Callable[[str], bool], findings: list[Finding]) -> None:
    """Check built-in rules against a line and append findings."""
    for pattern, severity, category, rule_name, message, suggestion in rules:
        if _should_skip_rule_for_line(rule_name, category, is_comment, is_string_line, skip_rules, stripped):
            continue
        check_line = _get_check_line(line, language, category, rule_name)
        if pattern.search(check_line):
            if not _match_rule_with_context(rule_name, line_num, lines):
                continue
            if is_suppressed(rule_name):
                continue
            findings.append(_make_finding(
                filepath, line_num, severity, category, rule_name,
                message, suggestion, stripped[:120],
            ))


def _check_custom_rules(custom_rules: list[tuple], line: str, stripped: str, line_num: int, filepath: str, is_suppressed: Callable[[str], bool], findings: list[Finding]) -> None:
    """Check custom rules against a line and append findings."""
    for pattern, severity, category, rule_name, message, suggestion in custom_rules:
        if pattern.search(line):
            if is_suppressed(rule_name):
                continue
            findings.append(_make_finding(
                filepath, line_num, severity, category, rule_name,
                message, suggestion, stripped[:120],
            ))


def _is_string_literal_line(stripped: str) -> bool:
    """Check if a stripped line starts with a string literal (not a docstring)."""
    return (
        (stripped.startswith('"') or stripped.startswith("'"))
        and not stripped.startswith('"""')
        and not stripped.startswith("'''")
    )


def _make_finding(filepath: str, line_num: int, severity: Severity, category: Category, rule_name: str, message: str, suggestion: str, snippet: str) -> Finding:
    """Create a Finding from matched rule data."""
    return Finding(
        file=filepath,
        line=line_num,
        severity=severity,
        category=category,
        source=Source.STATIC,
        rule=rule_name,
        message=message,
        suggestion=suggestion,
        snippet=snippet,
    )


def run_regex_checks(content: str, filepath: str, language: str, custom_rules: list | None = None) -> list[Finding]:
    """Run regex-based pattern matching against file content.

    Args:
        custom_rules: Optional list of compiled custom rules from compile_custom_rules().
            Each tuple: (re.Pattern, Severity, Category, name, message, suggestion, languages).
            Rules with languages=None apply to all languages; otherwise only to listed ones.
    """
    findings = []
    rules = get_rules_for_language(language)

    # Detect test/example files for rule suppression
    fp_lower = filepath.lower().replace("\\", "/")
    is_test_file = _is_test_path(fp_lower)
    is_example_file = any(seg in fp_lower for seg in _EXAMPLE_PATH_SEGMENTS)

    # Rules to skip for this file based on path
    skip_rules: set[str] = set()
    if is_test_file:
        skip_rules |= _SKIP_IN_TEST_FILES
    if is_example_file:
        skip_rules |= _SKIP_IN_EXAMPLE_FILES

    # Collect applicable custom rules (processed separately — match full line)
    applicable_custom_rules = []
    if custom_rules:
        for pattern, severity, category, name, message, suggestion, languages in custom_rules:
            if languages is None or language in languages:
                applicable_custom_rules.append((pattern, severity, category, name, message, suggestion))

    # ── Full-content pass for DOTALL rules (multiline patterns) ──────
    dotall_rule_names: set[str] = set()
    for pattern, severity, category, rule_name, message, suggestion in rules:
        if pattern.flags & re.DOTALL:
            dotall_rule_names.add(rule_name)
            if rule_name in skip_rules:
                continue
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                matched_text = match.group()[:120].replace('\n', ' ')
                findings.append(_make_finding(
                    filepath, line_num, severity, category, rule_name,
                    message, suggestion, matched_text,
                ))
    # Add DOTALL rules to skip set so they don't run again line-by-line
    skip_rules = skip_rules | dotall_rule_names

    lines = content.splitlines()

    # Language-aware comment prefixes for full-line detection
    comment_prefixes = {"//"} if language in _SLASH_LANGUAGES else {"#"}

    # Block comment state tracking
    in_block_comment = False
    block_comment_delimiter = None
    block_open, block_close, alt_block_open, alt_block_close = _get_block_comment_delimiters(language)

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track block comments
        in_block_comment, block_comment_delimiter, should_skip = _update_block_comment_state(
            stripped, language, in_block_comment, block_comment_delimiter,
            block_open, block_close, alt_block_open, alt_block_close,
        )
        if should_skip:
            continue

        is_comment = any(stripped.startswith(p) for p in comment_prefixes)
        is_string_line = _is_string_literal_line(stripped)

        # Inline suppression: lazy — only computed on first rule match
        line_suppression = None
        line_suppression_parsed = False

        def _line_is_suppressed(rule: str) -> bool:
            nonlocal line_suppression, line_suppression_parsed  # doji:ignore(possibly-uninitialized)
            if not line_suppression_parsed:
                line_suppression = _parse_line_suppression(line, language)
                line_suppression_parsed = True
            if line_suppression is None:
                return False
            if line_suppression is True:
                return True
            return rule in line_suppression

        _check_builtin_rules(
            rules, line, stripped, line_num, lines, language,
            is_comment, is_string_line, skip_rules, filepath,
            _line_is_suppressed, findings,
        )

        # Custom rules: match against the full line (no comment stripping)
        _check_custom_rules(
            applicable_custom_rules, line, stripped, line_num,
            filepath, _line_is_suppressed, findings,
        )
    return findings


# ─── Internal helpers for analyze_file_static ─────────────────────────────


def _run_semantic_checks(
    findings: list[Finding], semantics: FileSemantics, content: str, filepath: str, language: str,
) -> FileTypeMap | None:
    """Run semantic analysis checks (scope, taint, CFG, types, null-safety, smells).

    Returns the type_map if computed, else None. Appends findings in place.
    """
    from .semantic.lang_config import get_config
    from .semantic.scope import (
        check_uninitialized_variables,
        check_unused_variables,
        check_variable_shadowing,
    )
    from .semantic.smells import check_feature_envy, check_god_class, check_long_method
    from .semantic.taint import analyze_taint

    findings.extend(check_unused_variables(semantics, filepath))
    findings.extend(check_variable_shadowing(semantics, filepath))
    findings.extend(check_uninitialized_variables(semantics, filepath))

    config = get_config(language)
    file_type_map = None

    if config:
        source_bytes = content.encode("utf-8")
        file_type_map = _run_cfg_and_type_checks(
            findings, semantics, source_bytes, config, filepath,
        )

    findings.extend(check_god_class(semantics, filepath))
    findings.extend(check_feature_envy(semantics, filepath))
    findings.extend(check_long_method(semantics, filepath))

    return file_type_map


def _run_cfg_and_type_checks(
    findings: list[Finding], semantics: FileSemantics, source_bytes: bytes, config: LanguageConfig, filepath: str,
) -> FileTypeMap | None:
    """Run CFG-based taint/resource checks and type inference + null safety.

    Returns the type_map if computed, else None. Appends findings in place.
    """
    from .semantic.cfg import build_cfg
    from .semantic.taint import analyze_taint

    cfgs = build_cfg(semantics, source_bytes, config)
    if cfgs:
        from .semantic.resource import check_resource_leaks
        from .semantic.taint import analyze_taint_pathsensitive

        findings.extend(analyze_taint_pathsensitive(semantics, source_bytes, config, filepath, cfgs))
        findings.extend(check_resource_leaks(semantics, source_bytes, config, filepath, cfgs))
    else:
        findings.extend(analyze_taint(semantics, source_bytes, config, filepath))

    # Type inference + null safety
    file_type_map = None
    try:
        from .semantic.nullsafety import check_null_safety
        from .semantic.types import infer_types

        file_type_map = infer_types(semantics, source_bytes, config, cfgs=cfgs if config else None)
        if file_type_map and file_type_map.types:
            findings.extend(
                check_null_safety(semantics, file_type_map, config, filepath, cfgs=cfgs if config else None, source_bytes=source_bytes)
            )
    except (ValueError, OSError, AttributeError) as e:
        logger.debug("Type inference/null safety skipped: %s", e)

    return file_type_map


def _run_ast_taint_checks(findings: list[Finding], filepath: str, content: str) -> None:
    """Run AST-based taint analysis for Python files, deduplicating against existing findings."""
    try:
        from .taint_cross import analyze_taint_ast

        ast_taint_findings = analyze_taint_ast(filepath, content)
        existing_taint_keys = {
            (f.file, f.line, f.rule) for f in findings if f.rule == "taint-flow"
        }
        for tf in ast_taint_findings:
            if (tf.file, tf.line, tf.rule) not in existing_taint_keys:
                findings.append(tf)
    except Exception as e:
        logger.debug("AST taint analysis skipped: %s", e)


def _run_all_checks(
    filepath: str, content: str, language: str, custom_rules: list | None = None,
    *, skip_benchmark_filters: bool = False,
) -> tuple[list[Finding], FileSemantics | None, FileTypeMap | None]:
    """Run regex + AST + semantic checks. Returns (findings, semantics, type_map).

    Note: imports inside this function are intentionally lazy, not due to circular
    dependencies. The semantic/* and java_sanitize modules pull in tree-sitter and
    other heavy dependencies that shouldn't be loaded at module import time.

    Args:
        skip_benchmark_filters: If True, only apply general-purpose Java FP
            filters (explicit sanitizer detection).
    """
    findings = run_regex_checks(content, filepath, language, custom_rules=custom_rules)

    if language == "java":
        from .java_sanitize import filter_java_fps
        findings = filter_java_fps(findings, content, skip_benchmark_filters=skip_benchmark_filters)

    from .semantic.checks import run_tree_sitter_checks
    ts_findings = run_tree_sitter_checks(content, filepath, language)
    if ts_findings:
        findings.extend(ts_findings)

    if language == "python":
        findings.extend(run_python_ast_checks(content, filepath))

    from .semantic.core import extract_semantics
    file_type_map = None
    semantics = extract_semantics(content, filepath, language)
    if semantics:
        file_type_map = _run_semantic_checks(findings, semantics, content, filepath, language)

    if language == "python":
        _run_ast_taint_checks(findings, filepath, content)

    return findings, semantics, file_type_map


def _apply_inline_suppression(
    findings: list[Finding], lines: list[str], language: str,
) -> list[Finding]:
    """Filter out AST/semantic findings suppressed by inline doji:ignore comments."""
    _suppression_cache: dict[int, set[str] | bool | None] = {}

    def _check_suppressed(line_no: int, rule: str) -> bool:
        if line_no not in _suppression_cache:
            if line_no < 1 or line_no > len(lines):
                _suppression_cache[line_no] = None
            else:
                _suppression_cache[line_no] = _parse_line_suppression(lines[line_no - 1], language)
        result = _suppression_cache[line_no]
        if result is None:
            return False
        if result is True:
            return True
        return rule in result

    return [f for f in findings if f.source == Source.STATIC or not _check_suppressed(f.line, f.rule)]


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same file + line + rule)."""
    seen: set[tuple[str, int, str]] = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# Maps each rule to its overlap group ID and priority (lower = preferred).
_OVERLAP_PRIORITY: dict[str, tuple[int, int]] = {
    # exception-swallowed (AST, has fixer) preferred over empty-exception-handler (tree-sitter)
    "exception-swallowed": (1, 0),
    "empty-exception-handler": (1, 1),
    "exception-swallowed-continue": (2, 0),
}


def _merge_overlap_findings(unique: list[Finding]) -> list[Finding]:
    """Merge overlapping rules at the same location, keeping the preferred variant."""
    overlap_best: dict[tuple[int, str, int], tuple[int, int]] = {}
    for idx, f in enumerate(unique):
        if f.rule not in _OVERLAP_PRIORITY:
            continue
        group_id, priority = _OVERLAP_PRIORITY[f.rule]
        key = (group_id, f.file, f.line)
        if key not in overlap_best or priority < overlap_best[key][0]:
            overlap_best[key] = (priority, idx)

    deduped = []
    for idx, f in enumerate(unique):
        if f.rule not in _OVERLAP_PRIORITY:
            deduped.append(f)
            continue
        group_id, _ = _OVERLAP_PRIORITY[f.rule]
        key = (group_id, f.file, f.line)
        if idx == overlap_best.get(key, (0, -1))[1]:
            deduped.append(f)
    return deduped


def _filter_test_example_rules(findings: list[Finding], filepath: str) -> list[Finding]:
    """Suppress rules not applicable in test/example files."""
    fp_lower = filepath.lower().replace("\\", "/")
    is_test = _is_test_path(fp_lower)
    is_example = any(seg in fp_lower for seg in _EXAMPLE_PATH_SEGMENTS)
    if not is_test and not is_example:
        return findings

    post_skip: set[str] = set()
    if is_test:
        post_skip |= _SKIP_IN_TEST_FILES
    if is_example:
        post_skip |= _SKIP_IN_EXAMPLE_FILES
    return [f for f in findings if f.rule not in post_skip]


def _postprocess_findings(
    findings: list[Finding], filepath: str, content: str, language: str
) -> list[Finding]:
    """Dedup, suppress test rules, apply inline suppression, merge overlaps."""
    lines = content.splitlines()
    findings = _apply_inline_suppression(findings, lines, language)
    unique = _dedup_findings(findings)
    unique = _merge_overlap_findings(unique)
    unique = _filter_test_example_rules(unique, filepath)

    from .types import SEVERITY_ORDER
    unique.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.line))
    return unique


def _record_metrics(findings: list[Finding], scan_ms: float) -> None:
    """Record scan metrics to the active session."""
    try:
        from .metrics import get_session

        session = get_session()
        if session:
            session.record_file(scan_ms)
            for f in findings:
                session.record_finding(f.rule, f.severity.value)
    except Exception as e:
        logger.debug("Failed to record metrics: %s", e)


def analyze_file_static(filepath: str, content: str, language: str, custom_rules: list | None = None) -> StaticAnalysisResult:
    """Run all static checks (regex + tree-sitter AST + Python AST fallback + semantic).

    Always returns a StaticAnalysisResult with findings, semantics, and type_map.
    Callers that only need findings can use result.findings.
    """
    import time as _time

    from .types import StaticAnalysisResult

    _scan_start = _time.perf_counter()

    findings, semantics, _file_type_map = _run_all_checks(filepath, content, language, custom_rules)
    unique = _postprocess_findings(findings, filepath, content, language)

    _scan_ms = (_time.perf_counter() - _scan_start) * 1000
    _record_metrics(unique, _scan_ms)

    return StaticAnalysisResult(findings=unique, semantics=semantics, type_map=_file_type_map)
