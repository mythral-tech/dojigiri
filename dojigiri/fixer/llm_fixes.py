"""LLM-assisted fix generation -- sends findings to an LLM for patch proposals.

Falls back gracefully if the LLM is unavailable or returns errors.
Isolated from deterministic fixers so the LLM dependency is optional.

Called by: engine.py (fix_file calls generate_llm_fixes for remaining findings)
Calls into: llm.py (fix_file, CostTracker, LLMError), config.py (Finding, Fix, FixSource)
Data in -> Data out: filepath + content + findings -> list[Fix] with source=LLM
"""

import logging

from ..types import Finding, Fix, FixSource

logger = logging.getLogger(__name__)


def generate_llm_fixes(
    filepath: str,
    content: str,
    language: str,
    findings: list[Finding],
    cost_tracker=None,
) -> list[Fix]:
    """Send findings to LLM, get back structured fixes.

    Falls back gracefully if LLM is unavailable.
    """
    if not findings:
        return []

    try:
        from ..plugin import require_llm_plugin

        _llm = require_llm_plugin()
        CostTracker = _llm.CostTracker
        llm_fix_file = _llm.fix_file

        if cost_tracker is None:
            cost_tracker = CostTracker()

        findings_dicts = []
        for f in findings:
            findings_dicts.append(
                {
                    "line": f.line,
                    "rule": f.rule,
                    "message": f.message,
                    "suggestion": f.suggestion or "",
                }
            )

        raw_fixes, cost_tracker = llm_fix_file(
            content,
            filepath,
            language,
            findings_dicts,
            cost_tracker,
        )

        fixes = []
        for rf in raw_fixes:
            try:
                fixes.append(
                    Fix(
                        file=filepath,
                        line=rf.get("line", 0),
                        rule=rf.get("rule", "llm-fix"),
                        original_code=rf.get("original_code", ""),
                        fixed_code=rf.get("fixed_code", ""),
                        explanation=rf.get("explanation", "LLM-generated fix"),
                        source=FixSource.LLM,
                    )
                )
            except (KeyError, TypeError):
                continue

        return fixes

    except Exception as e:
        logger.warning("LLM fix generation failed: %s", e)
        return []
