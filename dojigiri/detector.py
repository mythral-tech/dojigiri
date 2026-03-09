"""Static analysis engine — regex matching + Python AST parsing.

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

logger = logging.getLogger(__name__)

from .ast_checks import run_python_ast_checks
from .languages import get_rules_for_language
from .types import Category, Finding, Source

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
    "hardcoded-ip",          # example IPs are illustrative
    "subprocess-audit",      # example shell commands are instructional
    "unused-variable",       # snippets often declare without using
}

# Path segments identifying test and example files
_TEST_PATH_SEGMENTS = ("/test/", "/tests/", "test_", "_test.", "/spec/", "/specs/")
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


def run_regex_checks(content: str, filepath: str, language: str, custom_rules=None) -> list[Finding]:
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

    lines = content.splitlines()

    # Language-aware comment prefixes for full-line detection
    comment_prefixes = {"//"} if language in _SLASH_LANGUAGES else {"#"}

    # Block comment state tracking
    in_block_comment = False
    block_comment_delimiter = None  # tracks which delimiter opened the block
    # Block comment delimiters by language
    if language == "python":
        block_open, block_close = '"""', '"""'
        alt_block_open, alt_block_close = "'''", "'''"
    elif language in ("html", "css"):
        block_open, block_close = "<!--", "-->"
        alt_block_open, alt_block_close = "/*", "*/"
    elif language in _SLASH_LANGUAGES:
        block_open, block_close = "/*", "*/"
        alt_block_open, alt_block_close = None, None
    else:
        block_open, block_close = None, None
        alt_block_open, alt_block_close = None, None

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track block comments (/* */ style and """ """ style)
        if block_open and not in_block_comment:
            # For Python: only treat """ as block comment start if at line start
            # (docstring position, not mid-line string assignment)
            # For other languages: any /* is a comment
            block_start_match = False
            if language == "python":
                # Only treat leading triple-quote as docstring open if the
                # line is purely a docstring line.  A closing triple-quote
                # at line start (e.g. '""")  # comment') is NOT an opener —
                # it ends a multiline string from a previous line.
                if stripped.startswith(block_open):
                    after_open = stripped[len(block_open):]
                    # If the very next char is ) , ] or whitespace-then-), it's a close
                    if not after_open or after_open[0] not in ")],;":
                        block_start_match = True
            else:
                block_start_match = block_open in stripped

            if block_start_match:
                # Check if block opens and closes on same line
                idx = stripped.index(block_open)
                rest = stripped[idx + len(block_open) :]
                if block_close not in rest:  # type: ignore[operator]  # block_close is non-None here
                    in_block_comment = True
                    block_comment_delimiter = block_close
                    continue
            elif alt_block_open:
                # For Python ''' - same logic
                alt_start_match = False
                if language == "python":
                    if stripped.startswith(alt_block_open):
                        after_open = stripped[len(alt_block_open):]
                        if not after_open or after_open[0] not in ")],;":
                            alt_start_match = True
                else:
                    alt_start_match = alt_block_open in stripped

                if alt_start_match:
                    idx = stripped.index(alt_block_open)
                    rest = stripped[idx + len(alt_block_open) :]
                    if alt_block_close not in rest:  # type: ignore[operator]  # alt_block_close is non-None here
                        in_block_comment = True
                        block_comment_delimiter = alt_block_close
                        continue
        elif in_block_comment:
            # Only close on the delimiter that opened the block
            if block_comment_delimiter and block_comment_delimiter in stripped:
                in_block_comment = False
                block_comment_delimiter = None
            continue  # Skip lines inside block comments entirely

        is_comment = any(stripped.startswith(p) for p in comment_prefixes)
        # Skip lines that are purely string content (inside quotes)
        is_string_line = (
            (stripped.startswith('"') or stripped.startswith("'"))
            and not stripped.startswith('"""')
            and not stripped.startswith("'''")
        )

        # Inline suppression: parse once per line, reuse for all rule checks.
        # Lazy — only computed on first rule match (most lines have zero matches).
        line_suppression = None  # sentinel; computed on demand
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

        for pattern, severity, category, rule_name, message, suggestion in rules:
            # Comment lines: only run comment-targeting rules
            if is_comment and rule_name not in _COMMENT_RULES:
                continue

            # Skip rules suppressed for test/example files
            if rule_name in skip_rules:
                continue

            # String-only lines: skip non-security patterns (secrets DO live in strings)
            if is_string_line and category not in _SECURITY_CATEGORIES:
                continue

            # For eval-usage/exec-usage: also check if the match is inside a string
            # literal mid-line (e.g. var = 'javascript:eval(...)' )
            if rule_name in ("eval-usage", "exec-usage") and _STRING_CONTENT_RE.search(stripped):
                continue

            # For non-security rules, strip inline comments before matching
            if category not in _SECURITY_CATEGORIES and rule_name not in _COMMENT_RULES:
                check_line = _strip_inline_comment(line, language)
            else:
                check_line = line

            if pattern.search(check_line):
                # yaml-unsafe: suppress if SafeLoader appears within ±3 lines
                if rule_name == "yaml-unsafe":
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 3)
                    context = "\n".join(lines[context_start:context_end])
                    if "SafeLoader" in context or "safe_load" in context:
                        continue

                # Inline suppression: doji:ignore or doji:ignore(rule-name)
                if _line_is_suppressed(rule_name):
                    continue

                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        severity=severity,
                        category=category,
                        source=Source.STATIC,
                        rule=rule_name,
                        message=message,
                        suggestion=suggestion,
                        snippet=stripped[:120],
                    )
                )

        # Custom rules: match against the full line (no comment stripping)
        for pattern, severity, category, rule_name, message, suggestion in applicable_custom_rules:
            if pattern.search(line):
                if _line_is_suppressed(rule_name):
                    continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=line_num,
                        severity=severity,
                        category=category,
                        source=Source.STATIC,
                        rule=rule_name,
                        message=message,
                        suggestion=suggestion,
                        snippet=stripped[:120],
                    )
                )
    return findings


# ─── Internal helpers for analyze_file_static ─────────────────────────────


def _run_all_checks(
    filepath: str, content: str, language: str, custom_rules=None,
    *, skip_benchmark_filters: bool = False,
) -> tuple[list[Finding], object | None, object | None]:
    """Run regex + AST + semantic checks. Returns (findings, semantics, type_map).

    Note: imports inside this function are intentionally lazy, not due to circular
    dependencies. The semantic/* and java_sanitize modules pull in tree-sitter and
    other heavy dependencies that shouldn't be loaded at module import time (e.g.,
    when only regex checks are needed or when the module is imported for type access).

    Args:
        skip_benchmark_filters: If True, only apply general-purpose Java FP
            filters (explicit sanitizer detection).  Passed through to
            :func:`java_sanitize.filter_java_fps`.
    """
    findings = run_regex_checks(content, filepath, language, custom_rules=custom_rules)

    # Java: filter false positives from sanitized injection patterns
    if language == "java":
        from .java_sanitize import filter_java_fps

        findings = filter_java_fps(
            findings, content, skip_benchmark_filters=skip_benchmark_filters,
        )

    # AST checks: tree-sitter for all languages, Python ast as supplement/fallback
    from .semantic.checks import run_tree_sitter_checks

    ts_findings = run_tree_sitter_checks(content, filepath, language)
    if ts_findings:
        findings.extend(ts_findings)

    if language == "python":
        # Always run Python AST checks — they cover checks tree-sitter doesn't
        # (type-comparison, global-keyword, shadowed-builtin assignments, etc.)
        # Dedup below merges overlapping findings by (file, line, rule)
        findings.extend(run_python_ast_checks(content, filepath))

    # v0.8.0: Semantic analysis (scope, taint, smells)
    from .semantic.core import extract_semantics
    from .semantic.lang_config import get_config

    _file_type_map = None  # captured for return
    semantics = extract_semantics(content, filepath, language)
    if semantics:
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
        if config:
            source_bytes = content.encode("utf-8")

            # v0.9.0: Build CFG and use path-sensitive analysis when available
            from .semantic.cfg import build_cfg

            cfgs = build_cfg(semantics, source_bytes, config)
            if cfgs:
                from .semantic.resource import check_resource_leaks
                from .semantic.taint import analyze_taint_pathsensitive

                findings.extend(analyze_taint_pathsensitive(semantics, source_bytes, config, filepath, cfgs))
                findings.extend(check_resource_leaks(semantics, source_bytes, config, filepath, cfgs))
            else:
                # Fallback to flow-insensitive taint analysis
                findings.extend(analyze_taint(semantics, source_bytes, config, filepath))

        # v0.10.0: Type inference + null safety
        if config:
            try:
                from .semantic.nullsafety import check_null_safety
                from .semantic.types import infer_types

                _file_type_map = infer_types(semantics, source_bytes, config, cfgs=cfgs if config else None)
                type_map = _file_type_map
                if type_map and type_map.types:
                    findings.extend(
                        check_null_safety(semantics, type_map, config, filepath, cfgs=cfgs if config else None)
                    )
            except (ValueError, OSError, AttributeError) as e:
                logger.debug("Type inference/null safety skipped: %s", e)

        findings.extend(check_god_class(semantics, filepath))
        findings.extend(check_feature_envy(semantics, filepath))
        findings.extend(check_long_method(semantics, filepath))
        # Note: semantic clone detection is handled project-wide in analyzer.py
        # to avoid duplicate intra-file findings.

    # v0.11.0: AST-based taint analysis with variable indirection tracking
    # Catches patterns tree-sitter taint misses: f-string interpolation,
    # multi-hop variable chains, function parameter taint.
    # Only runs on Python files (uses built-in ast module).
    if language == "python":
        try:
            from .taint import analyze_taint_ast

            ast_taint_findings = analyze_taint_ast(filepath, content)
            # Deduplicate against existing taint-flow findings (same file + line + rule)
            existing_taint_keys = {
                (f.file, f.line, f.rule) for f in findings if f.rule == "taint-flow"
            }
            for tf in ast_taint_findings:
                if (tf.file, tf.line, tf.rule) not in existing_taint_keys:
                    findings.append(tf)
        except Exception as e:
            logger.debug("AST taint analysis skipped: %s", e)

    return findings, semantics, _file_type_map


def _postprocess_findings(
    findings: list[Finding], filepath: str, content: str, language: str
) -> list[Finding]:
    """Dedup, suppress test rules, apply inline suppression, merge overlaps."""
    # Inline suppression post-filter for AST/semantic findings.
    # Regex findings (Source.STATIC) are already filtered in run_regex_checks,
    # so only check AST/semantic findings here. Cache parse per-line.
    lines = content.splitlines()
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

    findings = [f for f in findings if f.source == Source.STATIC or not _check_suppressed(f.line, f.rule)]

    # Deduplicate: same file + line + rule
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.rule)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Merge overlapping rules at the same location — keep the preferred variant.
    # Maps each rule to its overlap group ID and priority (lower = preferred).
    _OVERLAP_PRIORITY: dict[str, tuple[int, int]] = {
        # exception-swallowed (AST, has fixer) preferred over empty-exception-handler (tree-sitter)
        "exception-swallowed": (1, 0),
        "empty-exception-handler": (1, 1),
        "exception-swallowed-continue": (2, 0),
    }
    # For each overlap group at each location, track the best finding
    _overlap_best: dict[tuple[int, str, int], tuple[int, int]] = {}  # (group, file, line) -> (priority, idx)
    for idx, f in enumerate(unique):
        if f.rule in _OVERLAP_PRIORITY:
            group_id, priority = _OVERLAP_PRIORITY[f.rule]
            key = (group_id, f.file, f.line)
            if key not in _overlap_best or priority < _overlap_best[key][0]:
                _overlap_best[key] = (priority, idx)
    # Build set of indices to keep
    keep_indices = set()
    for _, idx in _overlap_best.values():
        keep_indices.add(idx)
    # Filter: for overlap rules, only keep the preferred; non-overlap rules pass through
    deduped = []
    for idx, f in enumerate(unique):
        if f.rule in _OVERLAP_PRIORITY:
            group_id, _ = _OVERLAP_PRIORITY[f.rule]
            key = (group_id, f.file, f.line)
            if idx == _overlap_best.get(key, (0, -1))[1]:
                deduped.append(f)
        else:
            deduped.append(f)
    unique = deduped

    # Post-filter: suppress rules in test/example files (applies to ALL sources)
    fp_lower = filepath.lower().replace("\\", "/")
    is_test = _is_test_path(fp_lower)
    is_example = any(seg in fp_lower for seg in _EXAMPLE_PATH_SEGMENTS)
    if is_test or is_example:
        post_skip: set[str] = set()
        if is_test:
            post_skip |= _SKIP_IN_TEST_FILES
        if is_example:
            post_skip |= _SKIP_IN_EXAMPLE_FILES
        unique = [f for f in unique if f.rule not in post_skip]

    # Sort by severity (critical first), then line number
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


def analyze_file_static(filepath: str, content: str, language: str, custom_rules=None) -> StaticAnalysisResult:  # noqa: F821
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
