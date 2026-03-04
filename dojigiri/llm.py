"""Anthropic SDK wrapper — prompts, API calls, cost tracking."""

import json
import logging
import sys
import time
import threading
from typing import Any, Optional

import re

logger = logging.getLogger(__name__)

from .config import (
    Finding, Severity, Category, Source, Confidence,
    LLM_MODEL, LLM_MAX_TOKENS, LLM_DEBUG_MAX_TOKENS, LLM_OPTIMIZE_MAX_TOKENS,
    LLM_ANALYZE_MAX_TOKENS, LLM_SYNTHESIS_MAX_TOKENS, LLM_FIX_MAX_TOKENS,
    LLM_TEMPERATURE, LLM_INPUT_COST_PER_M, LLM_OUTPUT_COST_PER_M,
    LANGUAGE_DEBUG_HINTS, LANGUAGE_OPTIMIZE_HINTS,
    CHUNK_SIZE, get_api_key,
)
from .chunker import Chunk, chunk_file


class LLMError(Exception):
    pass


def _strip_markdown_fences(text: str) -> str:
    """Strip markdown code fences (```...```) from LLM response text."""
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    return text


class CostTracker:
    """Track cumulative API costs for a session (thread-safe)."""

    def __init__(self) -> None:
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self._lock = threading.Lock()

    def add(self, input_tokens: int, output_tokens: int) -> None:
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens

    @property
    def total_cost(self) -> float:
        with self._lock:
            return (
                (self.total_input_tokens / 1_000_000) * LLM_INPUT_COST_PER_M
                + (self.total_output_tokens / 1_000_000) * LLM_OUTPUT_COST_PER_M
            )


def _get_client() -> Any:
    """Get Anthropic client, raising clear error if not available."""
    key = get_api_key()
    if not key:
        raise LLMError(
            "ANTHROPIC_API_KEY not set. "
            "Set it with: export ANTHROPIC_API_KEY=sk-..."
        )
    try:
        import anthropic
    except ImportError:
        raise LLMError(
            "anthropic package not installed. "
            "Install with: pip install anthropic"
        )
    return anthropic.Anthropic(api_key=key)


# ─── Prompts ──────────────────────────────────────────────────────────

SCAN_SYSTEM_PROMPT = """\
You are a senior code reviewer. Analyze the provided code and return findings as JSON.

Return ONLY a JSON array of finding objects. No markdown, no explanation outside JSON.

Each finding object:
{
  "line": <int, line number in the file>,
  "severity": "critical" | "warning" | "info",
  "category": "bug" | "security" | "performance" | "style" | "dead_code",
  "rule": "<short-kebab-case-rule-name>",
  "message": "<clear explanation of the issue>",
  "suggestion": "<specific fix recommendation>",
  "confidence": "high" | "medium" | "low"
}

Focus on:
1. Actual bugs that will cause runtime errors or incorrect behavior
2. Security vulnerabilities (injection, auth issues, data exposure, unsafe deserialization)
3. Performance problems (N+1 queries, unnecessary allocations, algorithmic issues)
4. Logic errors (off-by-one, race conditions, null derefs, exception handling gaps)
5. Dead code and unreachable paths
6. Resource leaks (unclosed files, connections, missing cleanup)

Only report issues you are confident about. Set "confidence" to reflect your certainty.

DO NOT report:
- Issues that are clearly intentional (test fixtures, examples, configuration)

If no issues found, return an empty array: []"""


DEBUG_SYSTEM_PROMPT = """\
You are a senior debugging expert. Analyze the provided code for bugs, logic errors, \
race conditions, resource leaks, and exception handling gaps.

{language_hints}

Return ONLY a JSON object (no markdown, no explanation outside JSON):
{{
  "summary": "<root cause analysis or overall assessment>",
  "findings": [
    {{
      "line": <int>,
      "end_line": <int or null>,
      "severity": "critical" | "warning" | "info",
      "category": "bug" | "security" | "performance" | "style" | "dead_code",
      "title": "<short title>",
      "description": "<detailed explanation>",
      "suggestion": "<how to fix>",
      "code_fix": "<corrected code snippet or null>",
      "confidence": "high" | "medium" | "low"
    }}
  ],
  "quick_wins": ["<easy fix 1>", "<easy fix 2>"]
}}

Focus on issues that static analysis CANNOT find: logic errors, semantic bugs, \
incorrect algorithms, missing edge cases, concurrency issues, subtle type misuse.

If no issues found, return: {{"summary": "No issues found", "findings": [], "quick_wins": []}}"""


OPTIMIZE_SYSTEM_PROMPT = """\
You are a senior performance engineer. Analyze the provided code for optimization \
opportunities in algorithmic complexity, memory usage, I/O patterns, caching, and concurrency.

{language_hints}

Return ONLY a JSON object (no markdown, no explanation outside JSON):
{{
  "summary": "<overall performance assessment>",
  "findings": [
    {{
      "line": <int>,
      "end_line": <int or null>,
      "severity": "critical" | "warning" | "info",
      "category": "performance",
      "title": "<short title>",
      "description": "<what's slow and why>",
      "suggestion": "<specific optimization>",
      "code_fix": "<optimized code snippet or null>",
      "confidence": "high" | "medium" | "low"
    }}
  ],
  "quick_wins": ["<easy improvement 1>", "<easy improvement 2>"]
}}

Focus on issues that static analysis CANNOT find: algorithmic complexity, unnecessary \
allocations in hot paths, missing caching opportunities, I/O bottlenecks, concurrency \
improvements.

If no issues found, return: {{"summary": "Code is well-optimized", "findings": [], "quick_wins": []}}"""


# ─── Helpers ─────────────────────────────────────────────────────────

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
        candidate = stripped[:pos + 1].rstrip().rstrip(",") + "]"
        try:
            result = json.loads(candidate)
            if isinstance(result, list):
                # Estimate how many objects we dropped
                remaining = stripped[pos + 1:].strip().rstrip("]").strip()
                dropped_hint = remaining.count("{")
                msg = f"  [llm] Recovered {len(result)} findings from truncated JSON"
                if dropped_hint > 0:
                    msg += f" (~{dropped_hint} dropped)"
                logger.debug(msg)
                return result
        except json.JSONDecodeError:
            continue

    return None


def _estimate_chunk_tokens(chunk: Chunk) -> int:
    """Rough token estimate for a chunk including system prompt overhead."""
    return len(chunk.content) // 4 + 500


def _parse_python_traceback(error_msg: str) -> Optional[dict]:
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


def _format_static_findings_for_llm(findings: list[Finding]) -> str:
    """Format existing Finding objects into context for the LLM.

    Tells the LLM what static analysis already found so it can
    confirm, refine, or dismiss those issues and focus on what
    static analysis cannot find.
    """
    if not findings:
        return ""

    parts = ["Static analysis already found these issues. Confirm, refine, or dismiss them. "
             "Focus on issues static analysis CANNOT find.\n"]
    for f in findings:
        severity = f.severity.value.upper()
        source = f.source.value
        line = f"  [{severity}] [{source}] line {f.line}: {f.message}"
        if f.suggestion:
            line += f" (suggestion: {f.suggestion})"
        parts.append(line)

    return "\n".join(parts)


def _parse_debug_response(text: str) -> Optional[dict]:
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
    except json.JSONDecodeError:
        pass

    # Strip markdown fences
    stripped = _strip_markdown_fences(stripped)
    if stripped != text.strip():
        try:
            result = json.loads(stripped)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    # Extract outermost { } from surrounding text
    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = stripped[first_brace:last_brace + 1]
        try:
            result = json.loads(candidate)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    return None


# ─── API calls ────────────────────────────────────────────────────────

MAX_CHUNK_TOKENS = 100_000  # warn threshold
_RETRY_DELAYS = [1, 2, 4]  # exponential backoff seconds
_RETRIABLE_STATUS_CODES = {429, 503, 529}


def _api_call_with_retry(client: Any, **kwargs: Any) -> Any:
    """Call client.messages.create with exponential backoff on transient errors."""
    last_err = None
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            return client.messages.create(**kwargs)
        except Exception as e:  # Anthropic SDK raises various types; inspect status to decide retry
            # Check if this is a retriable HTTP error
            status = getattr(e, "status_code", None)
            is_timeout = "timeout" in str(e).lower() or "timed out" in str(e).lower()
            is_retriable = status in _RETRIABLE_STATUS_CODES or is_timeout

            if is_retriable and attempt < len(_RETRY_DELAYS):
                delay = _RETRY_DELAYS[attempt]
                logger.debug("Retry %d/%d after %ds (status=%s)",
                             attempt + 1, len(_RETRY_DELAYS), delay, status)
                time.sleep(delay)
                last_err = e
            else:
                raise
    assert last_err is not None  # guaranteed by loop structure
    raise last_err


def analyze_chunk(chunk: Chunk, cost_tracker: CostTracker) -> list[Finding]:
    """Send a code chunk to Claude for analysis. Returns findings."""
    est_tokens = _estimate_chunk_tokens(chunk)
    if est_tokens > MAX_CHUNK_TOKENS:
        logger.debug("Chunk ~%s tokens (>%s) — %s lines %d-%d",
                     f"{est_tokens:,}", f"{MAX_CHUNK_TOKENS:,}",
                     chunk.filepath, chunk.start_line, chunk.end_line)

    client = _get_client()

    user_msg = f"{chunk.header}\n\n```{chunk.language}\n{chunk.content}\n```"

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=SCAN_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)

    # Parse JSON response
    text = _strip_markdown_fences(response.content[0].text.strip())

    try:
        raw_findings = json.loads(text)
    except json.JSONDecodeError:
        # Attempt to recover truncated JSON arrays
        raw_findings = _recover_truncated_json(text)
        if raw_findings is None:
            logger.warning("Malformed JSON response (not valid JSON array)")
            return []

    if not isinstance(raw_findings, list):
        logger.warning("Unexpected response type: %s", type(raw_findings).__name__)
        return []

    findings = []
    for rf in raw_findings:
        try:
            # Adjust line numbers for chunk offset
            line = rf.get("line", 1)
            if chunk.chunk_index > 0:
                line = line + chunk.start_line - 1

            # Parse confidence (default to medium if not provided)
            conf_str = rf.get("confidence", "medium")
            try:
                confidence = Confidence(conf_str)
            except ValueError:
                confidence = Confidence.MEDIUM

            findings.append(Finding(
                file=chunk.filepath,
                line=line,
                severity=Severity(rf.get("severity", "info")),
                category=Category(rf.get("category", "bug")),
                source=Source.LLM,
                rule=rf.get("rule", "llm-finding"),
                message=rf.get("message", "Issue found by Claude"),
                suggestion=rf.get("suggestion"),
                confidence=confidence,
            ))
        except (ValueError, KeyError):
            continue

    return findings


def _build_debug_system_prompt(language: str) -> str:
    """Build debug system prompt with language-specific hints."""
    hints = LANGUAGE_DEBUG_HINTS.get(language, "")
    if hints:
        hints = f"Language-specific pitfalls for {language}:\n{hints}\n"
    return DEBUG_SYSTEM_PROMPT.format(language_hints=hints)


def _build_optimize_system_prompt(language: str) -> str:
    """Build optimize system prompt with language-specific hints."""
    hints = LANGUAGE_OPTIMIZE_HINTS.get(language, "")
    if hints:
        hints = f"Language-specific optimization patterns for {language}:\n{hints}\n"
    return OPTIMIZE_SYSTEM_PROMPT.format(language_hints=hints)


def _debug_single_chunk(
    client, chunk_content: str, filepath: str, language: str,
    system_prompt: str, extra_context: str,
    cost_tracker: CostTracker,
    chunk_header: str = "",
) -> tuple[Optional[dict], str]:
    """Send a single chunk for debug/optimize analysis.

    Returns (parsed_dict_or_None, raw_text).
    """
    user_msg = f"File: {filepath} ({language})"
    if chunk_header:
        user_msg += f"\n{chunk_header}"
    user_msg += f"\n\n```{language}\n{chunk_content}\n```"
    if extra_context:
        user_msg += f"\n\n{extra_context}"

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_DEBUG_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=system_prompt,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)
    raw_text = response.content[0].text
    parsed = _parse_debug_response(raw_text)
    return parsed, raw_text


def _merge_chunked_results(results: list[dict]) -> dict:
    """Merge multiple chunked debug/optimize results into one.

    Deduplicates findings by (line, title) and merges quick_wins.
    """
    all_findings: list[dict] = []
    all_quick_wins: list[str] = []
    summaries: list[str] = []
    seen_findings: set[tuple] = set()

    for r in results:
        if r.get("summary"):
            summaries.append(r["summary"])
        for f in r.get("findings", []):
            key = (f.get("line"), f.get("title", ""))
            if key not in seen_findings:
                seen_findings.add(key)
                all_findings.append(f)
        for qw in r.get("quick_wins", []):
            if qw not in all_quick_wins:
                all_quick_wins.append(qw)

    return {
        "summary": " | ".join(summaries) if summaries else "No issues found",
        "findings": all_findings,
        "quick_wins": all_quick_wins,
    }


def _analyze_file_chunked(
    content: str, filepath: str, language: str,
    system_prompt: str, extra_context: str,
    cost_tracker: CostTracker,
) -> tuple[dict, CostTracker]:
    """Shared chunking logic for debug_file and optimize_file."""
    client = _get_client()

    if content.count("\n") > CHUNK_SIZE:
        chunks = chunk_file(content, filepath, language)
        results = []
        for chunk in chunks:
            parsed, raw = _debug_single_chunk(
                client, chunk.content, filepath, language,
                system_prompt, extra_context, cost_tracker,
                chunk_header=f"Lines {chunk.start_line}-{chunk.end_line} "
                             f"(chunk {chunk.chunk_index + 1}/{chunk.total_chunks})",
            )
            if parsed:
                results.append(parsed)
            elif not results:
                return {"raw_markdown": raw}, cost_tracker

        if results:
            return _merge_chunked_results(results), cost_tracker

    # Single-chunk path
    parsed, raw = _debug_single_chunk(
        client, content, filepath, language,
        system_prompt, extra_context, cost_tracker,
    )
    if parsed:
        return parsed, cost_tracker
    return {"raw_markdown": raw}, cost_tracker


def debug_file(
    content: str, filepath: str, language: str,
    error_msg: Optional[str] = None,
    static_findings: Optional[list[Finding]] = None,
    context_files: Optional[dict[str, str]] = None,
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[dict, CostTracker]:
    """Send file to Claude for debugging analysis.

    Returns (structured_dict, cost_tracker). The dict has keys:
    'summary', 'findings', 'quick_wins' on success,
    or 'raw_markdown' as fallback if JSON parsing fails.
    """
    if cost_tracker is None:
        cost_tracker = CostTracker()

    system_prompt = _build_debug_system_prompt(language)

    # Build extra context
    extra_parts = []

    # Stacktrace parsing
    if error_msg:
        tb = _parse_python_traceback(error_msg)
        if tb:
            extra_parts.append(f"Error: {tb['exception_type']}: {tb['exception_message']}")
            extra_parts.append(f"Pay special attention to lines: {sorted(tb['relevant_lines'])}")
            for frame in tb["frames"]:
                extra_parts.append(
                    f"  Frame: {frame['file']}:{frame['line']} in {frame['function']}"
                    + (f" → {frame['code']}" if frame['code'] else "")
                )
        else:
            extra_parts.append(f"Error message:\n```\n{error_msg}\n```")

    # Static findings context
    if static_findings:
        static_text = _format_static_findings_for_llm(static_findings)
        if static_text:
            extra_parts.append(static_text)

    # Context files
    if context_files:
        for ctx_path, ctx_content in context_files.items():
            extra_parts.append(f"Related file: {ctx_path}\n```\n{ctx_content}\n```")

    extra_context = "\n\n".join(extra_parts)
    return _analyze_file_chunked(content, filepath, language, system_prompt, extra_context, cost_tracker)


def optimize_file(
    content: str, filepath: str, language: str,
    static_findings: Optional[list[Finding]] = None,
    context_files: Optional[dict[str, str]] = None,
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[dict, CostTracker]:
    """Send file to Claude for optimization analysis.

    Returns (structured_dict, cost_tracker). The dict has keys:
    'summary', 'findings', 'quick_wins' on success,
    or 'raw_markdown' as fallback if JSON parsing fails.
    """
    if cost_tracker is None:
        cost_tracker = CostTracker()

    system_prompt = _build_optimize_system_prompt(language)

    # Filter static findings to perf-relevant ones
    extra_parts = []
    if static_findings:
        perf_relevant = [
            f for f in static_findings
            if f.category in (Category.PERFORMANCE, Category.STYLE)
            or f.rule in ("high-complexity", "too-many-args")
        ]
        static_text = _format_static_findings_for_llm(perf_relevant)
        if static_text:
            extra_parts.append(static_text)

    # Context files
    if context_files:
        for ctx_path, ctx_content in context_files.items():
            extra_parts.append(f"Related file: {ctx_path}\n```\n{ctx_content}\n```")

    extra_context = "\n\n".join(extra_parts)
    return _analyze_file_chunked(content, filepath, language, system_prompt, extra_context, cost_tracker)


def estimate_cost(total_chars: int) -> float:
    """Estimate cost for analyzing given amount of code."""
    input_tokens = total_chars // 4  # rough estimate
    # Add system prompt overhead (~500 tokens per call)
    input_tokens += 500
    # Assume output is ~25% of input
    output_tokens = input_tokens // 4

    return (
        (input_tokens / 1_000_000) * LLM_INPUT_COST_PER_M
        + (output_tokens / 1_000_000) * LLM_OUTPUT_COST_PER_M
    )


# ─── Cross-file analysis prompts ─────────────────────────────────────

ANALYZE_SYSTEM_PROMPT = """\
You are a senior architect performing cross-file analysis. You are given a PRIMARY file \
and CONTEXT files it depends on (or that depend on it), plus a dependency graph summary.

Your job: find issues that are ONLY visible when considering multiple files together.

Return ONLY a JSON object (no markdown, no explanation outside JSON):
{{
  "cross_file_findings": [
    {{
      "source_file": "<file where the issue manifests>",
      "target_file": "<related file involved in the issue>",
      "line": <int, line in source_file>,
      "target_line": <int or null, line in target_file>,
      "severity": "critical" | "warning" | "info",
      "category": "bug" | "security" | "performance" | "style" | "dead_code",
      "rule": "<short-kebab-case-rule-name>",
      "message": "<clear explanation of the cross-file issue>",
      "suggestion": "<specific fix recommendation>",
      "confidence": "high" | "medium" | "low"
    }}
  ],
  "local_findings": [
    {{
      "line": <int>,
      "severity": "critical" | "warning" | "info",
      "category": "bug" | "security" | "performance" | "style" | "dead_code",
      "rule": "<short-kebab-case-rule-name>",
      "message": "<explanation>",
      "suggestion": "<fix>",
      "confidence": "high" | "medium" | "low"
    }}
  ]
}}

Focus on cross-file issues:
1. Interface mismatches — function called with wrong args, missing params, type mismatches
2. Inconsistent patterns — error handling in one file but not another, mixed conventions
3. Data flow issues — value transformed incorrectly as it passes between modules
4. Dead exports — functions/classes exported but never imported anywhere
5. Contract violations — assumptions in one file broken by changes in another
6. Circular dependency implications — state ordering issues from import cycles

DO NOT report issues visible from a single file in isolation. \
Static analysis already found those. Focus on what requires cross-file context.

If no cross-file issues found, return: \
{{"cross_file_findings": [], "local_findings": []}}"""


SYNTHESIS_SYSTEM_PROMPT = """\
You are a senior architect synthesizing a project-level analysis. You are given:
1. A dependency graph summary (files, edges, cycles, hubs, dead modules)
2. Per-file analysis summaries
3. All cross-file findings from the analysis pass

Produce a project-level synthesis. Return ONLY a JSON object:
{{
  "architecture_summary": "<2-3 sentence overview of the project structure>",
  "health_score": <int 1-10, where 10 is excellent>,
  "architectural_issues": [
    {{
      "title": "<issue title>",
      "severity": "critical" | "warning" | "info",
      "description": "<detailed explanation>",
      "affected_files": ["<file1>", "<file2>"],
      "suggestion": "<how to fix>"
    }}
  ],
  "positive_patterns": ["<good pattern 1>", "<good pattern 2>"],
  "recommendations": [
    {{
      "priority": "high" | "medium" | "low",
      "title": "<recommendation title>",
      "description": "<what to do and why>"
    }}
  ]
}}

Be specific and actionable. Reference actual file names and line numbers from the data provided.
Only report architectural issues that span multiple files or affect the project structure."""


def analyze_file_with_context(
    content: str,
    filepath: str,
    language: str,
    context_files: dict[str, str],
    graph_summary: str,
    static_findings: Optional[list[Finding]] = None,
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[dict, CostTracker]:
    """Pass 1: Analyze one file with its dependency context.

    Returns (parsed_dict, cost_tracker). Dict has keys:
    'cross_file_findings' and 'local_findings'.
    """
    if cost_tracker is None:
        cost_tracker = CostTracker()

    client = _get_client()

    # Build user message
    parts = [f"Primary file: {filepath} ({language})\n\n```{language}\n{content}\n```"]

    if context_files:
        parts.append("\n--- Context files ---")
        for ctx_path, ctx_content in context_files.items():
            parts.append(f"\nFile: {ctx_path}\n```\n{ctx_content}\n```")

    if graph_summary:
        parts.append(f"\n--- Dependency graph ---\n{graph_summary}")

    if static_findings:
        static_text = _format_static_findings_for_llm(static_findings)
        if static_text:
            parts.append(f"\n--- Static analysis (already found) ---\n{static_text}")

    user_msg = "\n".join(parts)

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_ANALYZE_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=ANALYZE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)
    raw_text = response.content[0].text
    parsed = _parse_debug_response(raw_text)

    if parsed is None:
        parsed = {"cross_file_findings": [], "local_findings": []}

    return parsed, cost_tracker


def synthesize_project(
    graph_summary: str,
    per_file_summaries: list[dict],
    all_cross_file_findings: list[dict],
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[dict, CostTracker]:
    """Pass 2: Synthesize project-level insights from all per-file results.

    Returns (synthesis_dict, cost_tracker).
    """
    if cost_tracker is None:
        cost_tracker = CostTracker()

    client = _get_client()

    # Build user message
    parts = [f"--- Dependency Graph ---\n{graph_summary}"]

    if per_file_summaries:
        parts.append("\n--- Per-file Summaries ---")
        for summary in per_file_summaries:
            path = summary.get("path", "unknown")
            local = summary.get("local_findings", [])
            parts.append(f"\n{path}: {len(local)} local finding(s)")
            for f in local[:5]:  # cap at 5 per file to stay within budget
                parts.append(f"  - [{f.get('severity', 'info')}] line {f.get('line', '?')}: {f.get('message', '')}")

    if all_cross_file_findings:
        parts.append(f"\n--- Cross-file Findings ({len(all_cross_file_findings)} total) ---")
        for cf in all_cross_file_findings:
            parts.append(
                f"  [{cf.get('severity', 'warning')}] {cf.get('source_file', '?')}:{cf.get('line', '?')} "
                f"→ {cf.get('target_file', '?')}: {cf.get('message', '')}"
            )

    user_msg = "\n".join(parts)

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_SYNTHESIS_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=SYNTHESIS_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)
    raw_text = response.content[0].text
    parsed = _parse_debug_response(raw_text)

    if parsed is None:
        parsed = {
            "architecture_summary": "Analysis could not be completed.",
            "health_score": 0,
            "architectural_issues": [],
            "positive_patterns": [],
            "recommendations": [],
        }

    return parsed, cost_tracker


# ─── Fix generation prompts ──────────────────────────────────────────

FIX_SYSTEM_PROMPT = """\
You are a precise code fixer. You receive a file and a list of findings (bugs/issues detected \
by static analysis). For each finding, produce an exact fix.

Return ONLY a JSON array of fix objects. No markdown, no explanation outside JSON.

Each fix object:
{{
  "line": <int, line number of the finding>,
  "rule": "<rule name from the finding>",
  "original_code": "<exact line(s) from the file to replace — must match the file exactly>",
  "fixed_code": "<replacement code>",
  "explanation": "<brief explanation of what changed and why>"
}}

Rules:
1. original_code MUST be an exact substring of the file content (including indentation)
2. fixed_code should be minimal — only change what's needed to fix the reported issue
3. Preserve surrounding code, indentation, and style
4. Do NOT refactor or improve code beyond fixing the reported issue
5. If you cannot fix an issue safely, omit it from the array
6. For deletions (removing a line), set fixed_code to ""

If no fixes can be generated, return an empty array: []"""


def fix_file(
    content: str, filepath: str, language: str,
    findings: list[dict],
    cost_tracker=None,
) -> tuple[list[dict], "CostTracker"]:
    """Ask LLM to generate fixes for the given findings.

    Returns (list_of_fix_dicts, cost_tracker).
    """
    if cost_tracker is None:
        cost_tracker = CostTracker()

    if not findings:
        return [], cost_tracker

    client = _get_client()

    # Build user message
    findings_text = "\n".join(
        f"  Line {f['line']}: [{f['rule']}] {f['message']}"
        + (f" (suggestion: {f['suggestion']})" if f.get('suggestion') else "")
        for f in findings
    )

    user_msg = (
        f"File: {filepath} ({language})\n\n"
        f"```{language}\n{content}\n```\n\n"
        f"Findings to fix:\n{findings_text}"
    )

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_FIX_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=FIX_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)

    text = _strip_markdown_fences(response.content[0].text.strip())

    try:
        raw_fixes = json.loads(text)
    except json.JSONDecodeError:
        raw_fixes = _recover_truncated_json(text)
        if raw_fixes is None:
            logger.warning("Fix response: malformed JSON")
            return [], cost_tracker

    if not isinstance(raw_fixes, list):
        return [], cost_tracker

    return raw_fixes, cost_tracker
