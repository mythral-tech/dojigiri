"""Response parsing and recovery for LLM JSON output.

Handles malformed, truncated, and markdown-fenced JSON responses from
LLM calls. Converts raw responses into Finding objects or structured dicts.

Called by: llm.py
Calls into: types.py, llm_prompts.py (_sanitize_for_prompt)
Data in -> Data out: raw LLM text -> list[Finding] | dict | None
"""

from __future__ import annotations

import json
import logging
import re

from .llm_prompts import _sanitize_for_prompt
from .types import Category, Confidence, Finding, Severity, Source

logger = logging.getLogger(__name__)


# ─── Helpers ──────────────────────────────────────────────────────────


def _strip_markdown_fences(text: str) -> str:
    """Strip markdown code fences (```...```) from LLM response text."""
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    return text


def _recover_truncated_json(text: str) -> list | None:
    """Attempt to recover a truncated JSON array by finding the last complete object.

    Strategy: walk backwards through `}` positions, trying to close the array
    at each one. This finds the longest valid prefix of the array.
    """
    stripped = text.strip()
    if not stripped.startswith("["):
        return None

    # Find all } positions (potential object-end boundaries)
    brace_positions = [i for i, c in enumerate(stripped) if c == "}"]
    if not brace_positions:
        return None

    # Try from the last } backwards — first success is the longest valid prefix
    for pos in reversed(brace_positions):
        candidate = stripped[: pos + 1].rstrip().rstrip(",") + "]"
        try:
            result = json.loads(candidate)
            if isinstance(result, list):
                # Estimate how many objects we dropped
                remaining = stripped[pos + 1 :].strip().rstrip("]").strip()
                dropped_hint = remaining.count("{")
                msg = f"  [llm] Recovered {len(result)} findings from truncated JSON"
                if dropped_hint > 0:
                    msg += f" (~{dropped_hint} dropped)"
                logger.debug(msg)
                return result
        except json.JSONDecodeError:
            continue

    return None


# ─── Debug/optimize response parsing ─────────────────────────────────


def _parse_debug_response(text: str) -> dict | None:
    """Parse a JSON response from debug/optimize LLM call.

    Tries json.loads first, then strips markdown fences,
    then extracts outermost { } from surrounding text.
    Returns None on total failure.
    """
    if not text or not text.strip():
        return None

    stripped = text.strip()

    # Try direct parse
    try:
        result = json.loads(stripped)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError as e:
        logger.debug("Failed to parse JSON directly: %s", e)

    # Strip markdown fences
    stripped = _strip_markdown_fences(stripped)
    if stripped != text.strip():
        try:
            result = json.loads(stripped)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError as e:
            logger.debug("Failed to parse JSON after stripping fences: %s", e)

    # Extract outermost { } from surrounding text
    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = stripped[first_brace : last_brace + 1]
        try:
            result = json.loads(candidate)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError as e:
            logger.debug("Failed to parse JSON from brace extraction: %s", e)

    return None


# ─── Scan response parsing ────────────────────────────────────────────


def _parse_scan_response(text: str) -> list | None:
    """Parse a JSON array response from scan LLM calls with full resilience.

    Applies the same recovery strategies as _parse_debug_response but for
    JSON arrays: direct parse, markdown fence stripping, bracket extraction,
    and truncated array recovery. Returns None on total failure.
    """
    if not text or not text.strip():
        return None

    stripped = text.strip()

    # Try direct parse
    try:
        result = json.loads(stripped)
        if isinstance(result, list):
            return result
        # Model returned a dict wrapping the array (e.g. {"findings": [...]})
        if isinstance(result, dict):
            for key in ("findings", "results", "issues"):
                if isinstance(result.get(key), list):
                    logger.debug("Scan response wrapped in dict, extracting '%s' key", key)
                    return result[key]
    except json.JSONDecodeError:
        logger.debug("Scan response: direct parse failed, trying fence strip")

    # Strip markdown fences
    stripped = _strip_markdown_fences(stripped)
    try:
        result = json.loads(stripped)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        logger.debug("Scan response: fence-stripped parse failed, trying bracket extraction")

    # Extract outermost [ ] from surrounding text
    first_bracket = stripped.find("[")
    last_bracket = stripped.rfind("]")
    if first_bracket != -1 and last_bracket > first_bracket:
        candidate = stripped[first_bracket : last_bracket + 1]
        try:
            result = json.loads(candidate)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            logger.debug("Scan response: bracket extraction failed, trying truncated recovery")

    # Last resort: recover truncated JSON array
    recovered = _recover_truncated_json(stripped)
    if recovered is not None:
        return recovered

    logger.warning("Malformed scan response (all JSON recovery strategies failed)")
    return None


# ─── Finding construction ─────────────────────────────────────────────


def _raw_to_findings(
    response_text: str,
    filepath: str,
    chunk_index: int = 0,
    chunk_start_line: int = 1,
    tool_use_data: dict | list | None = None,
) -> list[Finding]:
    """Parse LLM response into Finding objects.

    Prefers structured tool_use_data when available (no JSON parsing needed).
    Falls back to text parsing with JSON recovery for non-tool_use responses.

    Args:
        response_text: Raw LLM response text (should be JSON array).
        filepath: Source file path for the findings.
        chunk_index: 0-based chunk index (0 = first/only chunk).
        chunk_start_line: Start line of this chunk in the file (for offset adjustment).
        tool_use_data: Structured data from tool_use response (dict with "findings" key or list).
    """
    # Prefer structured tool_use data — no JSON parsing needed
    if tool_use_data is not None:
        if isinstance(tool_use_data, dict) and "findings" in tool_use_data:
            raw_findings = tool_use_data["findings"]
        elif isinstance(tool_use_data, list):
            raw_findings = tool_use_data
        else:
            raw_findings = None
    else:
        raw_findings = _parse_scan_response(response_text)

    if raw_findings is None:
        return []

    findings = []
    for rf in raw_findings:
        try:
            if not isinstance(rf, dict):
                continue

            line = rf.get("line", 1)  # doji:ignore(null-dereference)
            if not isinstance(line, int) or line < 1:
                line = 1
            if chunk_index > 0:
                line = line + chunk_start_line - 1

            conf_str = rf.get("confidence", "medium")  # doji:ignore(null-dereference)
            try:
                confidence = Confidence(conf_str)
            except ValueError:
                confidence = Confidence.MEDIUM

            message = str(rf.get("message", "Issue found by Claude"))[:500]  # doji:ignore(null-dereference)
            suggestion = rf.get("suggestion")  # doji:ignore(null-dereference)
            if suggestion is not None:
                suggestion = str(suggestion)[:500]
            rule = str(rf.get("rule", "llm-finding"))[:100]  # doji:ignore(null-dereference)

            findings.append(
                Finding(
                    file=filepath,
                    line=line,
                    severity=Severity(rf.get("severity", "info")),  # doji:ignore(null-dereference)
                    category=Category(rf.get("category", "bug")),  # doji:ignore(null-dereference)
                    source=Source.LLM,
                    rule=rule,
                    message=message,
                    suggestion=suggestion,
                    confidence=confidence,
                )
            )
        except (ValueError, KeyError):
            continue

    return findings


# ─── Static findings formatter ────────────────────────────────────────


def _format_static_findings_for_llm(findings: list[Finding]) -> str:
    """Format existing Finding objects into context for the LLM.

    Tells the LLM what static analysis already found so it can
    confirm, refine, or dismiss those issues and focus on what
    static analysis cannot find.
    """
    from .types import should_redact_snippet

    if not findings:
        return ""

    parts = [
        "Static analysis already found these issues. Confirm, refine, or dismiss them. "
        "Focus on issues static analysis CANNOT find.\n"
    ]
    for f in findings:
        if should_redact_snippet(f.rule):
            parts.append(f"  [{f.severity.value.upper()}] [{f.source.value}] line {f.line}: [REDACTED] {f.rule} detected")
            continue
        severity = f.severity.value.upper()
        source = f.source.value
        msg = _sanitize_for_prompt(f.message, max_length=500)
        line = f"  [{severity}] [{source}] line {f.line}: {msg}"
        if f.suggestion:
            line += f" (suggestion: {_sanitize_for_prompt(f.suggestion, max_length=500)})"
        parts.append(line)

    return "\n".join(parts)


# ─── Traceback parsing ────────────────────────────────────────────────


def _parse_python_traceback(error_msg: str) -> dict | None:
    """Parse a Python traceback string into structured data.

    Returns dict with 'frames' (list of {file, line, function, code}),
    'exception_type', 'exception_message', and 'relevant_lines' set.
    Returns None for non-traceback strings.
    """
    if not error_msg or "Traceback (most recent call last)" not in error_msg:
        return None

    frames = []
    lines = error_msg.strip().splitlines()
    relevant_lines = set()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Match: File "path", line N, in func
        m = re.match(r'File "([^"]+)", line (\d+)(?:, in (.+))?', line)
        if m:
            frame = {
                "file": m.group(1),
                "line": int(m.group(2)),
                "function": m.group(3) or "<module>",
                "code": "",
            }
            relevant_lines.add(frame["line"])
            # Next line is usually the code
            if i + 1 < len(lines) and not lines[i + 1].strip().startswith("File "):
                frame["code"] = lines[i + 1].strip()
                i += 1
            frames.append(frame)
        i += 1

    if not frames:
        return None

    # Extract exception type and message from the last non-empty line
    exception_type = ""
    exception_message = ""
    for line in reversed(lines):
        line = line.strip()
        if line and not line.startswith("File ") and not line.startswith("Traceback"):
            # e.g. "ValueError: invalid literal"
            if ": " in line:
                exception_type, exception_message = line.split(": ", 1)
            else:
                exception_type = line
            break

    return {
        "frames": frames,
        "exception_type": exception_type,
        "exception_message": exception_message,
        "relevant_lines": relevant_lines,
    }
