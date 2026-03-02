"""Anthropic SDK wrapper — prompts, API calls, cost tracking."""

import json
import sys
import time
from typing import Optional

from .config import (
    Finding, Severity, Category, Source, Confidence,
    LLM_MODEL, LLM_MAX_TOKENS, LLM_TEMPERATURE,
    LLM_INPUT_COST_PER_M, LLM_OUTPUT_COST_PER_M,
    get_api_key,
)
from .chunker import Chunk


class LLMError(Exception):
    pass


class CostTracker:
    """Track cumulative API costs for a session."""

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def add(self, input_tokens: int, output_tokens: int):
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

    @property
    def total_cost(self) -> float:
        return (
            (self.total_input_tokens / 1_000_000) * LLM_INPUT_COST_PER_M
            + (self.total_output_tokens / 1_000_000) * LLM_OUTPUT_COST_PER_M
        )


def _get_client():
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
You are a senior debugging expert. Analyze the provided code and error context.

Structure your response as:

## Root Cause
<concise explanation of what's wrong>

## Analysis
<step-by-step reasoning>

## Fix
```
<specific code fix with line numbers>
```

## Prevention
<how to prevent this class of bug>

Be specific and actionable. Reference exact line numbers."""


OPTIMIZE_SYSTEM_PROMPT = """\
You are a senior performance engineer. Analyze the provided code for optimization opportunities.

Structure your response as:

## Performance Assessment
<overall assessment: good/needs work/critical>

## Findings
For each issue:
### <Issue Title>
- **Impact**: high/medium/low
- **Location**: line numbers
- **Problem**: what's slow and why
- **Solution**: specific code changes

## Quick Wins
<list of easy improvements with highest impact>

Focus on algorithmic complexity, memory usage, I/O patterns, and caching opportunities.
Be specific — show before/after code."""


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
                print(msg, file=sys.stderr)
                return result
        except json.JSONDecodeError:
            continue

    return None


def _estimate_chunk_tokens(chunk: Chunk) -> int:
    """Rough token estimate for a chunk including system prompt overhead."""
    return len(chunk.content) // 4 + 500


# ─── API calls ────────────────────────────────────────────────────────

MAX_CHUNK_TOKENS = 100_000  # warn threshold
_RETRY_DELAYS = [1, 2, 4]  # exponential backoff seconds
_RETRIABLE_STATUS_CODES = {429, 503, 529}


def _api_call_with_retry(client, **kwargs):
    """Call client.messages.create with exponential backoff on transient errors."""
    last_err = None
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            return client.messages.create(**kwargs)
        except Exception as e:
            # Check if this is a retriable HTTP error
            status = getattr(e, "status_code", None)
            is_timeout = "timeout" in str(e).lower() or "timed out" in str(e).lower()
            is_retriable = status in _RETRIABLE_STATUS_CODES or is_timeout

            if is_retriable and attempt < len(_RETRY_DELAYS):
                delay = _RETRY_DELAYS[attempt]
                print(f"  [llm] Retry {attempt + 1}/{len(_RETRY_DELAYS)} after {delay}s "
                      f"(status={status})", file=sys.stderr)
                time.sleep(delay)
                last_err = e
            else:
                raise
    raise last_err  # shouldn't reach here, but safety net


def analyze_chunk(chunk: Chunk, cost_tracker: CostTracker) -> list[Finding]:
    """Send a code chunk to Claude for analysis. Returns findings."""
    est_tokens = _estimate_chunk_tokens(chunk)
    if est_tokens > MAX_CHUNK_TOKENS:
        print(f"  [llm] Warning: chunk ~{est_tokens:,} tokens (>{MAX_CHUNK_TOKENS:,}) — "
              f"{chunk.filepath} lines {chunk.start_line}-{chunk.end_line}",
              file=sys.stderr)

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
    text = response.content[0].text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        raw_findings = json.loads(text)
    except json.JSONDecodeError:
        # Attempt to recover truncated JSON arrays
        raw_findings = _recover_truncated_json(text)
        if raw_findings is None:
            print("  [llm] Malformed JSON response (not valid JSON array)", file=sys.stderr)
            return []

    if not isinstance(raw_findings, list):
        print(f"  [llm] Unexpected response type: {type(raw_findings).__name__}", file=sys.stderr)
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


def debug_file(
    content: str, filepath: str, language: str,
    error_msg: Optional[str] = None,
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[str, CostTracker]:
    """Send file to Claude for debugging analysis. Returns markdown response."""
    if cost_tracker is None:
        cost_tracker = CostTracker()

    client = _get_client()

    user_msg = f"File: {filepath} ({language})\n\n```{language}\n{content}\n```"
    if error_msg:
        user_msg += f"\n\nError message:\n```\n{error_msg}\n```"

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=DEBUG_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)
    return response.content[0].text, cost_tracker


def optimize_file(
    content: str, filepath: str, language: str,
    cost_tracker: Optional[CostTracker] = None,
) -> tuple[str, CostTracker]:
    """Send file to Claude for optimization analysis. Returns markdown response."""
    if cost_tracker is None:
        cost_tracker = CostTracker()

    client = _get_client()

    user_msg = f"File: {filepath} ({language})\n\n```{language}\n{content}\n```"

    response = _api_call_with_retry(
        client,
        model=LLM_MODEL,
        max_tokens=LLM_MAX_TOKENS,
        temperature=LLM_TEMPERATURE,
        system=OPTIMIZE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )

    cost_tracker.add(response.usage.input_tokens, response.usage.output_tokens)
    return response.content[0].text, cost_tracker


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
