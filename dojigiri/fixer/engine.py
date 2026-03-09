"""Fix orchestration engine -- apply, verify, validate, and rollback fixes.

The main entry point is fix_file(), which coordinates deterministic fixers,
LLM fixes, conflict resolution, application, syntax validation, verification,
and auto-rollback. Also contains apply_fixes() and verify_fixes().

Called by: __main__.py, mcp_server.py (via fix_file)
Calls into: deterministic.py, llm_fixes.py, cascade.py, helpers.py, config.py, detector.py
Data in -> Data out: ScanReport + file content -> FixReport (diffs + status)
"""

from __future__ import annotations

import ast
import logging
import os
import re
import shutil
import sys
import tempfile

from ..types import (
    Finding,
    Fix,
    FixContext,
    FixReport,
    FixStatus,
)
from .cascade import derive_expected_cascades
from .deterministic import DETERMINISTIC_FIXERS
from .helpers import _record_fix_metric
from .llm_fixes import generate_llm_fixes

logger = logging.getLogger(__name__)


# ─── Fix application ─────────────────────────────────────────────────


def apply_fixes(
    filepath: str,
    fixes: list[Fix],
    dry_run: bool = True,
    create_backup: bool = True,
) -> list[Fix]:
    """Apply fixes to a file. Bottom-to-top to preserve line numbers.

    Returns the list of fixes with updated statuses.
    """
    if not fixes:
        return fixes

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        for fix in fixes:
            fix.status = FixStatus.FAILED
            fix.fail_reason = f"cannot read file: {e}"
        logger.warning("Cannot read %s: %s", filepath, e)
        return fixes

    lines = content.splitlines(keepends=True)

    # Sort by line descending so we apply from bottom up
    indexed_fixes = sorted(enumerate(fixes), key=lambda x: x[1].line, reverse=True)

    occupied_lines: set[int] = set()
    deleted_indices: set[int] = set()  # Track lines blanked by fixes (not original blank lines)

    for idx, fix in indexed_fixes:
        # Determine the full line range this fix covers
        start_line = fix.line
        end_line = fix.end_line if fix.end_line is not None else fix.line
        fix_range = set(range(start_line, end_line + 1))

        if fix_range & occupied_lines:
            fix.status = FixStatus.SKIPPED
            fix.fail_reason = "overlaps with another fix on the same line(s)"
            continue

        # Validate: check that original_code matches the actual file content
        line_idx = fix.line - 1  # 0-based
        if line_idx < 0 or line_idx >= len(lines):
            fix.status = FixStatus.FAILED
            fix.fail_reason = f"line {fix.line} out of range (file has {len(lines)} lines)"
            continue

        # For deletion fixes (empty fixed_code), remove the line(s)
        if fix.original_code and not fix.fixed_code:
            # Verify original matches
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() != actual.strip():
                fix.status = FixStatus.FAILED
                fix.fail_reason = "original code not found at this line (already fixed?)"
                continue
            if not dry_run:
                # Blank out all lines in the range
                for li in range(line_idx, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        elif fix.original_code and fix.fixed_code:
            # Replacement fix -- verify original is present
            actual = lines[line_idx]
            if fix.original_code.strip() and fix.original_code.strip() != actual.strip():
                fix.status = FixStatus.FAILED
                fix.fail_reason = "original code not found at this line (already fixed?)"
                continue
            if not dry_run:
                # Replace the first line with fixed_code
                new_code = fix.fixed_code
                if not new_code.endswith("\n") and actual.endswith("\n"):
                    new_code += "\n"
                lines[line_idx] = new_code
                # Blank out remaining lines in range (line+1..end_line)
                for li in range(line_idx + 1, min(line_idx + (end_line - start_line + 1), len(lines))):
                    lines[li] = ""
                    deleted_indices.add(li)
            fix.status = FixStatus.APPLIED
            occupied_lines.update(fix_range)

        else:
            fix.status = FixStatus.FAILED
            fix.fail_reason = "missing original or replacement code"

    if not dry_run:
        # Remove only lines that were blanked by fixes, not original blank lines
        new_content = "".join(line for i, line in enumerate(lines) if i not in deleted_indices)

        # Backup
        if create_backup:
            backup_path = filepath + ".doji.bak"
            # SECURITY: Refuse to write backup if the path is a symlink.
            # An attacker can plant a symlink (e.g. target.py.doji.bak -> /etc/passwd)
            # and shutil.copy2 would follow it, overwriting the symlink target
            # with the source file's content (arbitrary file overwrite).
            if os.path.islink(backup_path):
                logger.warning(
                    "Refusing to create backup — '%s' is a symlink (possible symlink attack)",
                    backup_path,
                )
            else:
                try:
                    shutil.copy2(filepath, backup_path)
                except OSError as e:
                    logger.warning("Could not create backup: %s", e)

        # Atomic write: write to temp file, then rename
        try:
            dir_name = os.path.dirname(filepath) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".doji.tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(new_content)
                # On Windows, we need to remove the target first
                if sys.platform == "win32" and os.path.exists(filepath):
                    os.replace(tmp_path, filepath)
                else:
                    os.rename(tmp_path, filepath)
            except (OSError, ValueError):  # cleanup-and-reraise for temp file
                try:
                    os.unlink(tmp_path)
                except OSError as e:
                    logger.debug("Failed to clean up temp file: %s", e)
                raise
        except OSError as e:
            logger.warning("Error writing %s: %s", filepath, e)
            for fix in fixes:
                if fix.status == FixStatus.APPLIED:
                    fix.status = FixStatus.FAILED
                    fix.fail_reason = f"cannot write file: {e}"

    return fixes


# ─── Fix verification ─────────────────────────────────────────────────


def verify_fixes(
    filepath: str,
    language: str,
    pre_findings: list[Finding],
    custom_rules=None,
    allowed_cascades: set[str] | None = None,
) -> dict:
    """Re-scan a file after fixes and compare before/after.

    Uses 5-line bucket matching to determine which issues were resolved
    and whether any new issues were introduced.

    Args:
        allowed_cascades: Set of rule names (e.g. {'unused-import'}) that are
            expected side-effects of fixes and should not trigger rollback.
            Computed by derive_expected_cascades() from AST analysis.

    Returns dict with:
      - resolved: int (issues that were fixed)
      - remaining: int (issues still present)
      - new_issues: int (issues introduced by fixes -- excludes expected cascades)
      - cascaded: int (new issues that are expected cascades, not counted)
      - new_findings: list of new Finding dicts
    """
    from ..detector import analyze_file_static

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            new_content = f.read()
    except OSError:
        return {
            "resolved": 0,
            "remaining": 0,
            "new_issues": 0,
            "cascaded": 0,
            "new_findings": [],
            "error": f"Could not re-read {filepath}",
        }

    post_findings = analyze_file_static(filepath, new_content, language, custom_rules=custom_rules).findings

    if not allowed_cascades:
        allowed_cascades = set()

    # Compare by rule counts: for each rule, how many before vs after.
    # Increase in count for a rule = new issues. Decrease = resolved.
    from collections import Counter

    pre_counts = Counter(f.rule for f in pre_findings)
    post_counts = Counter(f.rule for f in post_findings)
    # Rules that fixers intentionally introduce (e.g., TODO markers) should  # doji:ignore(todo-marker)
    # not trigger rollback. Track info-only new rules separately.
    info_only_rules = {f.rule for f in post_findings if getattr(f.severity, "value", f.severity) == "info"} - set(
        pre_counts
    )

    all_rules = set(pre_counts) | set(post_counts)
    resolved = 0
    remaining = 0
    new_issues = 0
    cascaded = 0
    for rule in all_rules:
        if rule in info_only_rules:
            continue  # skip info-only rules that fixers intentionally introduce
        before = pre_counts.get(rule, 0)
        after = post_counts.get(rule, 0)
        if after <= before:
            resolved += before - after
            remaining += after
        else:
            delta = after - before
            if rule in allowed_cascades:
                cascaded += delta
            else:
                remaining += before
                new_issues += delta

    new_findings = []
    # Only report findings with rules not present at all before
    pre_rules = set(pre_counts)
    for finding in post_findings:
        if finding.rule not in pre_rules:
            new_findings.append(finding.to_dict())

    return {
        "resolved": resolved,
        "remaining": remaining,
        "new_issues": new_issues,
        "cascaded": cascaded,
        "new_findings": new_findings,
    }


# ─── Post-fix validation & rollback ──────────────────────────────────


def _strip_template_literals(content: str) -> str:
    """Replace template literal content (including nested ${} expressions) with spaces.

    Uses a stack-based state machine to handle nested backticks inside ${} expressions.
    Preserves string length so positions remain valid for brace counting.
    """
    result = list(content)
    i = 0
    n = len(content)
    # Stack tracks nesting: 'T' = inside template literal, 'E' = inside ${} expression
    stack: list[str] = []
    max_depth = 100  # Safety cap against maliciously nested templates

    while i < n:
        if len(stack) > max_depth:
            break  # Bail out on maliciously nested templates
        ch = content[i]

        if not stack:
            # Outside any template literal
            if ch == "`":
                stack.append("T")
                result[i] = " "
            i += 1
            continue

        top = stack[-1]

        if top == "T":
            # Inside template literal body
            if ch == "\\" and i + 1 < n:
                result[i] = " "
                result[i + 1] = " "
                i += 2
                continue
            if ch == "$" and i + 1 < n and content[i + 1] == "{":
                # Enter ${} expression
                result[i] = " "
                result[i + 1] = " "
                stack.append("E")
                i += 2
                continue
            if ch == "`":
                # End of template literal
                result[i] = " "
                stack.pop()
                i += 1
                continue
            # Regular template content -- blank it
            result[i] = " "
            i += 1
            continue

        if top == "E":
            # Inside ${} expression -- blank everything (braces here are
            # template-internal and must not be counted by the validator)
            if ch == "}":
                result[i] = " "
                stack.pop()
                i += 1
                continue
            if ch == "`":
                # Nested template literal inside ${}
                result[i] = " "
                stack.append("T")
                i += 1
                continue
            if ch == "{":
                # Nested object literal / block inside expression
                result[i] = " "
                stack.append("E")
                i += 1
                continue
            # Blank all expression content (parens, brackets, code)
            result[i] = " "
            i += 1
            continue

        i += 1

    return "".join(result)


def _validate_syntax(filepath: str, content: str, language: str) -> str | None:
    """Validate syntax of fixed file. Returns error message or None if valid."""
    if language == "python":
        try:
            ast.parse(content, filename=filepath)
        except SyntaxError as e:
            return f"Python syntax error: {e.msg} (line {e.lineno})"
    elif language in ("javascript", "typescript"):
        # Lightweight check: balanced braces, parens, brackets
        # Strip string literals, template literals, and comments first
        # to avoid counting delimiters inside non-code regions.
        stripped = _strip_template_literals(content)  # template literals (nested-safe)
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', "", stripped)  # double-quoted strings
        stripped = re.sub(r"'(?:[^'\\]|\\.)*'", "", stripped)  # single-quoted strings
        stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.DOTALL)  # block comments
        stripped = re.sub(r"//[^\n]*", "", stripped)  # line comments
        # Regex literals: /pattern/flags after common preceding tokens
        stripped = re.sub(r"(?<=[=(:,;\[!&|?{}\n])\s*/(?:[^/\\\n]|\\.)+/[gimsuy]*", "", stripped)
        counts = {"(": 0, "[": 0, "{": 0}
        closers = {")": "(", "]": "[", "}": "{"}
        for ch in stripped:
            if ch in counts:
                counts[ch] += 1
            elif ch in closers:
                counts[closers[ch]] -= 1
        for opener, count in counts.items():
            if count != 0:
                closer = {"(": ")", "[": "]", "{": "}"}[opener]
                return f"Unbalanced '{opener}'/'{closer}' (off by {count})"

        # Tree-sitter structural validation (if available)
        try:
            from tree_sitter_language_pack import get_parser
            parser = get_parser("typescript" if language == "typescript" else "javascript")
            tree = parser.parse(content.encode("utf-8"))
            if tree.root_node.has_error:
                return "Syntax error detected by tree-sitter parser"
        except (ImportError, LookupError, ValueError, RuntimeError, MemoryError, RecursionError):
            pass
    return None


def _rollback_from_backup(filepath: str, fixes: list[Fix], reason: str = "") -> None:
    """Restore file from .doji.bak backup and mark all applied fixes as FAILED."""
    backup_path = filepath + ".doji.bak"
    if os.path.exists(backup_path):
        # SECURITY: Refuse to read from a symlinked backup. An attacker could
        # plant a symlink (e.g. target.py.doji.bak -> /path/to/malicious.py)
        # so that rollback injects attacker-controlled content into the target file.
        if os.path.islink(backup_path):
            logger.warning(
                "Refusing to rollback from '%s' — it is a symlink (possible symlink attack)",
                backup_path,
            )
        else:
            try:
                shutil.copy2(backup_path, filepath)
                logger.info("Rolled back %s from backup", filepath)
            except OSError as e:
                logger.warning("Rollback failed for %s: %s", filepath, e)
    for fix in fixes:
        if fix.status == FixStatus.APPLIED:
            fix.status = FixStatus.FAILED
            if reason:
                fix.fail_reason = reason


# ─── Main orchestrator ────────────────────────────────────────────────


def fix_file(
    filepath: str,
    content: str,
    language: str,
    findings: list[Finding],
    use_llm: bool = False,
    dry_run: bool = True,
    create_backup: bool = True,
    rules: list[str] | None = None,
    cost_tracker=None,
    verify: bool = True,
    custom_rules=None,
    semantics=None,
    type_map=None,
) -> FixReport:
    """Generate and optionally apply fixes for all findings in a file.

    Flow:
    1. Filter findings to rules if specified
    2. For each finding: check DETERMINISTIC_FIXERS first
    3. Remaining findings: batch to generate_llm_fixes() if use_llm=True
    4. Sort all fixes by line (descending)
    5. Call apply_fixes() with dry_run flag
    6. Return FixReport
    """
    # Filter by rules if specified
    if rules:
        rule_set = set(rules)
        findings = [f for f in findings if f.rule in rule_set]

    if not findings:
        return FixReport(
            root=filepath,
            files_fixed=0,
            total_fixes=0,
            applied=0,
            skipped=0,
            failed=0,  # doji:ignore(possibly-uninitialized)
        )

    lines = content.splitlines(keepends=True)
    all_fixes: list[Fix] = []
    remaining: list[Finding] = []

    # Part 1: Deterministic fixes -- all fixers receive FixContext
    import time as _time

    _fix_start = _time.perf_counter()

    for finding in findings:
        fixer = DETERMINISTIC_FIXERS.get(finding.rule)
        if not fixer:
            remaining.append(finding)
            continue

        line_idx = finding.line - 1
        if not (0 <= line_idx < len(lines)):
            remaining.append(finding)
            continue

        ctx = FixContext(
            content=content,
            finding=finding,
            semantics=semantics,
            type_map=type_map,
            language=language,
        )
        _t0 = _time.perf_counter()
        result = fixer(lines[line_idx], finding, content, ctx)
        _dur_ms = (_time.perf_counter() - _t0) * 1000

        if result:
            if isinstance(result, list):
                all_fixes.extend(result)
            else:
                all_fixes.append(result)
            _record_fix_metric(finding.rule, True, _dur_ms)
        else:
            _record_fix_metric(finding.rule, False, _dur_ms)
            remaining.append(finding)

    # Part 2: LLM fixes for remaining findings
    if use_llm and remaining:
        from ..llm import CostTracker

        if cost_tracker is None:
            cost_tracker = CostTracker()
        llm_fixes = generate_llm_fixes(
            filepath,
            content,
            language,
            remaining,
            cost_tracker,
        )
        all_fixes.extend(llm_fixes)

    if not all_fixes:
        return FixReport(
            root=filepath,
            files_fixed=0,
            total_fixes=0,
            applied=0,
            skipped=0,
            failed=0,
        )

    # Resolve conflicts between fixers that target the same lines.
    #
    # 1. If a variable is both hardcoded-secret AND unused-variable,
    #    unused-variable wins (delete dead code, don't bother securing it).
    # 2. Don't remove imports that surviving fixes still need.
    unused_var_lines = {fix.line for fix in all_fixes if fix.rule == "unused-variable"}
    all_fixes = [fix for fix in all_fixes if not (fix.rule == "hardcoded-secret" and fix.line in unused_var_lines)]

    # 3. If both open-without-with and resource-leak target the same variable in
    #    the same file, drop the resource-leak fix (the with block subsumes .close()).
    oww_vars: set[tuple[str, str]] = set()
    for fix in all_fixes:
        if fix.rule == "open-without-with" and fix.fixed_code:
            vm = re.search(r"as\s+(\w+)\s*:", fix.fixed_code)
            if vm:
                oww_vars.add((fix.file, vm.group(1)))
    if oww_vars:
        all_fixes = [
            fix
            for fix in all_fixes
            if not (
                fix.rule == "resource-leak"
                and fix.original_code
                and any((fix.file, var) in oww_vars for var in re.findall(r"(\w+)\.close\(\)", fix.fixed_code or ""))
            )
        ]

    # Check which modules surviving fixes still need
    modules_needed: set[str] = set()
    for fix in all_fixes:
        if fix.rule != "unused-import" and fix.fixed_code:
            if "os.environ" in fix.fixed_code:
                modules_needed.add("os")
            if "ast.literal_eval" in fix.fixed_code:
                modules_needed.add("ast")
            if "subprocess.run" in fix.fixed_code:
                modules_needed.add("subprocess")
            if "shlex.split" in fix.fixed_code:
                modules_needed.add("shlex")
    if modules_needed:
        all_fixes = [
            fix
            for fix in all_fixes
            if not (
                fix.rule == "unused-import"
                and fix.original_code
                and any(f"import {mod}" in fix.original_code for mod in modules_needed)
            )
        ]

    # Apply fixes
    all_fixes = apply_fixes(filepath, all_fixes, dry_run=dry_run, create_backup=create_backup)

    applied = sum(1 for f in all_fixes if f.status == FixStatus.APPLIED)
    skipped = sum(1 for f in all_fixes if f.status == FixStatus.SKIPPED)
    failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)

    # Post-fix syntax validation -- rollback if broken
    if not dry_run and applied > 0:
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                fixed_content = f.read()
            syntax_err = _validate_syntax(filepath, fixed_content, language)
            if syntax_err:
                logger.warning("Syntax validation failed after fix: %s -- rolling back", syntax_err)
                _rollback_from_backup(filepath, all_fixes, reason=f"rolled back -- {syntax_err}")
                applied = 0
                failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
        except OSError as e:
            logger.debug("Failed to validate/rollback fix: %s", e)

    llm_cost = 0.0
    if cost_tracker:
        llm_cost = cost_tracker.total_cost

    # Verify fixes if actually applied
    verification = None
    if verify and not dry_run and applied > 0:
        # Derive expected cascades from AST analysis of original content + applied fixes
        applied_fix_list = [f for f in all_fixes if f.status == FixStatus.APPLIED]
        allowed_cascades = derive_expected_cascades(content, language, applied_fix_list, semantics=semantics)
        verification = verify_fixes(
            filepath, language, findings, custom_rules=custom_rules, allowed_cascades=allowed_cascades
        )
        # Auto-rollback if fixes introduced new issues
        if verification and verification.get("new_issues", 0) > 0:
            logger.warning("Fixes introduced %d new issue(s) -- rolling back", verification["new_issues"])
            _rollback_from_backup(
                filepath, all_fixes, reason=f"rolled back -- fixes introduced {verification['new_issues']} new issue(s)"
            )
            applied = 0
            failed = sum(1 for f in all_fixes if f.status == FixStatus.FAILED)
            verification = {
                "rolled_back": True,
                "reason": f"{verification.get('new_issues', 0)} new issue(s) introduced",
            }

    # Record total fix duration in metrics
    _fix_total_ms = (_time.perf_counter() - _fix_start) * 1000
    try:
        from ..metrics import get_session

        session = get_session()
        if session:
            session.record_fix_duration(_fix_total_ms)
    except Exception as e:
        logger.debug("Failed to record fix duration metrics: %s", e)

    return FixReport(
        root=filepath,
        files_fixed=1 if applied > 0 else 0,
        total_fixes=len(all_fixes),
        applied=applied,
        skipped=skipped,
        failed=failed,
        fixes=all_fixes,
        llm_cost_usd=llm_cost,
        verification=verification,
    )
