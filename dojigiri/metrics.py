"""Session observability — structured metrics for scan and fix operations.

Collects timing, token counts, finding counts, and error rates during a scan
session. Persists metrics to disk as JSON for post-hoc analysis.

Called by: llm.py, detector.py, fixer.py
Calls into: nothing (standalone, only imports config.STORAGE_DIR)
Data in -> Data out: scan events (timing, counts) -> SessionMetrics dataclass
"""

import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import STORAGE_DIR

logger = logging.getLogger(__name__)

METRICS_DIR = STORAGE_DIR / "metrics"


@dataclass
class SessionMetrics:
    started_at: str = ""
    files_scanned: int = 0
    total_findings: int = 0
    findings_by_rule: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    fixes_attempted: int = 0
    fixes_succeeded: int = 0
    fixes_failed: int = 0
    fixes_by_rule: dict[str, dict] = field(default_factory=dict)
    scan_duration_ms: float = 0
    fix_duration_ms: float = 0
    llm_calls: int = 0
    llm_tokens_in: int = 0
    llm_tokens_out: int = 0

    def record_file(self, scan_duration_ms: float = 0) -> None:
        with _session_lock:
            self.files_scanned += 1
            self.scan_duration_ms += scan_duration_ms

    def record_finding(self, rule: str, severity: str) -> None:
        with _session_lock:
            self.total_findings += 1
            self.findings_by_rule[rule] = self.findings_by_rule.get(rule, 0) + 1
            self.findings_by_severity[severity] = self.findings_by_severity.get(severity, 0) + 1

    def record_fix(self, rule: str, succeeded: bool, duration_ms: float) -> None:
        with _session_lock:
            self.fixes_attempted += 1
            if succeeded:
                self.fixes_succeeded += 1
            else:
                self.fixes_failed += 1

            if rule not in self.fixes_by_rule:
                self.fixes_by_rule[rule] = {"attempted": 0, "succeeded": 0, "failed": 0, "total_duration_ms": 0}
            entry = self.fixes_by_rule[rule]
            entry["attempted"] += 1
            if succeeded:
                entry["succeeded"] += 1
            else:
                entry["failed"] += 1
            entry["total_duration_ms"] += duration_ms

    def record_fix_duration(self, duration_ms: float) -> None:
        with _session_lock:
            self.fix_duration_ms += duration_ms

    def record_llm_call(self, tokens_in: int, tokens_out: int) -> None:
        with _session_lock:
            self.llm_calls += 1
            self.llm_tokens_in += tokens_in
            self.llm_tokens_out += tokens_out


# Module-level lock for thread-safe access to _current_session and its fields
_session_lock = threading.Lock()

# Module-level current session — set by start_session(), used by instrument hooks
_current_session: Optional[SessionMetrics] = None


def start_session() -> SessionMetrics:
    """Start a new metrics session."""
    global _current_session  # doji:ignore(global-keyword)
    with _session_lock:
        _current_session = SessionMetrics(started_at=datetime.now().isoformat(timespec="seconds"))
        return _current_session


def get_session() -> Optional[SessionMetrics]:
    """Get the current session metrics, or None if no session is active."""
    with _session_lock:
        return _current_session


def end_session() -> Optional[SessionMetrics]:
    """End the current session and return its metrics."""
    global _current_session  # doji:ignore(global-keyword)
    with _session_lock:
        session = _current_session
        _current_session = None
        return session


def save_session(metrics: SessionMetrics) -> Path:
    """Save session metrics to .dojigiri/metrics/{timestamp}.json."""
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    ts = metrics.started_at.replace(":", "-") if metrics.started_at else "unknown"
    path = METRICS_DIR / f"{ts}.json"
    data = asdict(metrics)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def load_history(days: int = 30) -> list[dict]:
    """Load recent session metrics for trend analysis."""
    if not METRICS_DIR.exists():
        return []

    sessions = []
    for path in sorted(METRICS_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if days > 0 and data.get("started_at"):
                try:
                    session_dt = datetime.fromisoformat(data["started_at"])
                    age = (datetime.now() - session_dt).days
                    if age > days:
                        continue
                except ValueError as e:
                    logger.debug("Failed to parse session timestamp: %s", e)
            sessions.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return sessions


def format_summary(metrics: SessionMetrics) -> str:
    """Format a console summary of session metrics."""
    lines = []
    lines.append(f"Session: {metrics.started_at}")
    lines.append(f"  Files scanned: {metrics.files_scanned}")
    lines.append(f"  Total findings: {metrics.total_findings}")

    if metrics.findings_by_severity:
        sev_parts = [f"{k}: {v}" for k, v in sorted(metrics.findings_by_severity.items())]
        lines.append(f"  By severity: {', '.join(sev_parts)}")

    lines.append(f"  Scan duration: {metrics.scan_duration_ms:.0f}ms")

    if metrics.fixes_attempted:
        rate = metrics.fixes_succeeded / metrics.fixes_attempted * 100
        lines.append(f"  Fixes: {metrics.fixes_succeeded}/{metrics.fixes_attempted} succeeded ({rate:.0f}%)")
        lines.append(f"  Fix duration: {metrics.fix_duration_ms:.0f}ms")

        # Per-rule breakdown for rules with failures
        failing_rules = []
        for rule, data in sorted(metrics.fixes_by_rule.items()):
            attempted = data["attempted"]
            failed = data["failed"]
            if failed > 0:
                fail_rate = failed / attempted * 100
                failing_rules.append((rule, attempted, failed, fail_rate))

        if failing_rules:
            lines.append("  Failing rules:")
            for rule, attempted, failed, fail_rate in failing_rules:
                lines.append(f"    {rule}: {failed}/{attempted} failed ({fail_rate:.0f}%)")

    if metrics.llm_calls:
        lines.append(f"  LLM calls: {metrics.llm_calls} ({metrics.llm_tokens_in} in, {metrics.llm_tokens_out} out)")

    return "\n".join(lines)


def format_history_summary(sessions: list[dict], limit: int = 10) -> str:
    """Format a summary of recent sessions for the stats command."""
    if not sessions:
        return "No session history found."

    lines = []
    lines.append(f"Last {min(limit, len(sessions))} sessions:")
    lines.append("")

    # Aggregate stats
    total_scans = len(sessions)
    total_findings = sum(s.get("total_findings", 0) for s in sessions)
    total_fixes_attempted = sum(s.get("fixes_attempted", 0) for s in sessions)
    total_fixes_succeeded = sum(s.get("fixes_succeeded", 0) for s in sessions)

    lines.append(f"Aggregate ({total_scans} sessions):")
    lines.append(f"  Total findings: {total_findings}")
    if total_fixes_attempted:
        rate = total_fixes_succeeded / total_fixes_attempted * 100
        lines.append(f"  Fix success rate: {total_fixes_succeeded}/{total_fixes_attempted} ({rate:.0f}%)")
    lines.append("")

    # Per-rule failure rates across all sessions
    rule_stats: dict[str, dict] = {}
    for session in sessions:
        for rule, data in session.get("fixes_by_rule", {}).items():
            if rule not in rule_stats:
                rule_stats[rule] = {"attempted": 0, "succeeded": 0, "failed": 0}
            rule_stats[rule]["attempted"] += data.get("attempted", 0)
            rule_stats[rule]["succeeded"] += data.get("succeeded", 0)
            rule_stats[rule]["failed"] += data.get("failed", 0)

    # Flag rules with >20% failure rate
    problem_rules = []
    for rule, stats in sorted(rule_stats.items()):
        if stats["attempted"] > 0:
            fail_rate = stats["failed"] / stats["attempted"] * 100
            if fail_rate > 20:
                problem_rules.append((rule, stats["attempted"], stats["failed"], fail_rate))

    if problem_rules:
        lines.append("Rules with >20% failure rate:")
        for rule, attempted, failed, fail_rate in problem_rules:
            lines.append(f"  {rule}: {failed}/{attempted} failed ({fail_rate:.0f}%)")
        lines.append("")

    # Recent sessions table
    lines.append("Recent sessions:")
    for session in sessions[:limit]:
        ts = session.get("started_at", "?")
        findings = session.get("total_findings", 0)
        fixes_ok = session.get("fixes_succeeded", 0)
        fixes_total = session.get("fixes_attempted", 0)
        scan_ms = session.get("scan_duration_ms", 0)
        fix_part = f", fixes {fixes_ok}/{fixes_total}" if fixes_total else ""
        lines.append(f"  {ts} — {findings} findings, {scan_ms:.0f}ms{fix_part}")

    return "\n".join(lines)
