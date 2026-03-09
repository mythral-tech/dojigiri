"""Tool-use schemas for structured LLM output.

These replace free-form JSON text with API-enforced structured responses.
The Anthropic tool_use feature forces the model to return data matching
these schemas, eliminating the need for JSON text parsing.

Called by: llm.py
Calls into: llm_backend.py (AnthropicBackend check)
Data in -> Data out: backend -> bool (supports tools), schema dicts
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .llm_backend import LLMBackend

# ─── Scan schemas ─────────────────────────────────────────────────────

_SCAN_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "line": {"type": "integer", "description": "Line number in the file"},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "category": {"type": "string", "enum": ["bug", "security", "performance", "style", "dead_code"]},
        "rule": {"type": "string", "description": "Short kebab-case rule name"},
        "message": {"type": "string", "description": "Clear explanation of the issue"},
        "suggestion": {"type": "string", "description": "Specific fix recommendation"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["line", "severity", "category", "rule", "message", "confidence"],
}

SCAN_RESPONSE_TOOL = {
    "name": "report_scan_findings",
    "description": "Report code analysis findings as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": _SCAN_FINDING_SCHEMA,
                "description": "List of findings. Empty array if no issues found.",
            },
        },
        "required": ["findings"],
    },
}

# ─── Debug schemas ────────────────────────────────────────────────────

_DEBUG_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "line": {"type": "integer"},
        "end_line": {"type": ["integer", "null"]},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "category": {"type": "string", "enum": ["bug", "security", "performance", "style", "dead_code"]},
        "title": {"type": "string", "description": "Short title"},
        "description": {"type": "string", "description": "Detailed explanation"},
        "suggestion": {"type": "string", "description": "How to fix"},
        "code_fix": {"type": ["string", "null"], "description": "Corrected code snippet or null"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["line", "severity", "category", "title", "description", "confidence"],
}

DEBUG_RESPONSE_TOOL = {
    "name": "report_debug_findings",
    "description": "Report debugging analysis as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "Root cause analysis or overall assessment"},
            "findings": {
                "type": "array",
                "items": _DEBUG_FINDING_SCHEMA,
            },
            "quick_wins": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Easy fixes",
            },
        },
        "required": ["summary", "findings", "quick_wins"],
    },
}

OPTIMIZE_RESPONSE_TOOL = {
    "name": "report_optimization_findings",
    "description": "Report optimization analysis as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "Overall performance assessment"},
            "findings": {
                "type": "array",
                "items": _DEBUG_FINDING_SCHEMA,
            },
            "quick_wins": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Easy optimizations",
            },
        },
        "required": ["summary", "findings", "quick_wins"],
    },
}

# ─── Cross-file schemas ──────────────────────────────────────────────

_CROSS_FILE_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "source_file": {"type": "string"},
        "target_file": {"type": "string"},
        "line": {"type": "integer"},
        "target_line": {"type": ["integer", "null"]},
        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
        "category": {"type": "string", "enum": ["bug", "security", "performance", "style", "dead_code"]},
        "rule": {"type": "string"},
        "message": {"type": "string"},
        "suggestion": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["source_file", "target_file", "line", "severity", "category", "rule", "message", "confidence"],
}

CROSS_FILE_RESPONSE_TOOL = {
    "name": "report_cross_file_findings",
    "description": "Report cross-file analysis findings as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "cross_file_findings": {
                "type": "array",
                "items": _CROSS_FILE_FINDING_SCHEMA,
            },
            "local_findings": {
                "type": "array",
                "items": _SCAN_FINDING_SCHEMA,
            },
        },
        "required": ["cross_file_findings", "local_findings"],
    },
}

# ─── Synthesis schemas ────────────────────────────────────────────────

SYNTHESIS_RESPONSE_TOOL = {
    "name": "report_project_synthesis",
    "description": "Report project-level synthesis as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "architecture_summary": {"type": "string"},
            "health_score": {"type": "integer", "minimum": 1, "maximum": 10},
            "architectural_issues": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
                        "description": {"type": "string"},
                        "affected_files": {"type": "array", "items": {"type": "string"}},
                        "suggestion": {"type": "string"},
                    },
                    "required": ["title", "severity", "description"],
                },
            },
            "positive_patterns": {"type": "array", "items": {"type": "string"}},
            "recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["priority", "title", "description"],
                },
            },
        },
        "required": ["architecture_summary", "health_score", "architectural_issues", "positive_patterns", "recommendations"],
    },
}

# ─── Fix schemas ──────────────────────────────────────────────────────

FIX_RESPONSE_TOOL = {
    "name": "report_fixes",
    "description": "Report code fixes as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "fixes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "line": {"type": "integer"},
                        "rule": {"type": "string"},
                        "original_code": {"type": "string", "description": "Exact line(s) to replace, no line number prefixes"},
                        "fixed_code": {"type": "string", "description": "Replacement code, no line number prefixes"},
                        "explanation": {"type": "string"},
                    },
                    "required": ["line", "rule", "original_code", "fixed_code", "explanation"],
                },
            },
        },
        "required": ["fixes"],
    },
}

# ─── Explain schemas ──────────────────────────────────────────────────

EXPLAIN_RESPONSE_TOOL = {
    "name": "report_explanation",
    "description": "Report code explanation as structured data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "purpose": {"type": "string", "description": "1-2 sentence summary of what this file does"},
            "key_concepts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "concept": {"type": "string"},
                        "explanation": {"type": "string"},
                        "lines": {"type": "string"},
                    },
                    "required": ["concept", "explanation"],
                },
            },
            "data_flow": {"type": "string"},
            "gotchas": {"type": "array", "items": {"type": "string"}},
            "findings_explained": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rule": {"type": "string"},
                        "plain_english": {"type": "string"},
                    },
                    "required": ["rule", "plain_english"],
                },
            },
        },
        "required": ["purpose", "key_concepts", "data_flow", "gotchas", "findings_explained"],
    },
}


# ─── Backend capability check ────────────────────────────────────────


def _backend_supports_tools(backend: LLMBackend) -> bool:
    """Check if a backend supports tool_use (only AnthropicBackend does)."""
    from .llm_backend import AnthropicBackend

    return isinstance(backend, AnthropicBackend)
