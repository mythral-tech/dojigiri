"""SCA scanner — orchestrates lockfile discovery, parsing, and OSV queries.

Flow: discover lockfiles → parse dependencies → batch query OSV → emit Findings.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..types import Category, FileAnalysis, Finding, Severity, Source
from .osv import Vulnerability, query_osv
from .parsers import Dependency, discover_lockfiles, parse_lockfile

logger = logging.getLogger(__name__)

# Map OSV severity strings to Dojigiri Severity enum
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.CRITICAL,
    "MEDIUM": Severity.WARNING,
    "MODERATE": Severity.WARNING,
    "LOW": Severity.INFO,
    "UNKNOWN": Severity.WARNING,
}


def scan_sca(root: Path, *, offline: bool = False, timeout: int = 30) -> list[FileAnalysis]:
    """Scan a project for vulnerable dependencies.

    Args:
        root: Project root directory.
        offline: If True, skip OSV query (useful for testing parsers).
        timeout: HTTP timeout for OSV API.

    Returns:
        List of FileAnalysis objects, one per lockfile with findings.
    """
    lockfiles = discover_lockfiles(root)
    if not lockfiles:
        logger.info("No lockfiles found in %s", root)
        return []

    logger.info("Found %d lockfile(s)", len(lockfiles))

    # Collect all dependencies with their source lockfile
    all_deps: list[tuple[Path, Dependency]] = []
    for lf in lockfiles:
        deps = parse_lockfile(lf)
        logger.info("  %s: %d dependencies", lf.name, len(deps))
        for dep in deps:
            all_deps.append((lf, dep))

    if not all_deps:
        return []

    # Query OSV for all unique packages
    unique_deps = list({dep for _, dep in all_deps})
    logger.info("Querying OSV for %d unique packages...", len(unique_deps))

    if offline:
        vulns: list[Vulnerability] = []
    else:
        vulns = query_osv(unique_deps, timeout=timeout)

    if not vulns:
        logger.info("No vulnerabilities found")
        return []

    logger.info("Found %d vulnerabilities", len(vulns))

    # Build a lookup: (package, version) -> [Vulnerability]
    vuln_map: dict[tuple[str, str], list[Vulnerability]] = {}
    for v in vulns:
        key = (v.package.lower(), v.installed_version)
        vuln_map.setdefault(key, []).append(v)

    # Build FileAnalysis objects per lockfile
    analyses: list[FileAnalysis] = []
    for lf in lockfiles:
        deps = parse_lockfile(lf)
        findings: list[Finding] = []

        for pkg_name, pkg_version, _ecosystem in deps:
            key = (pkg_name.lower(), pkg_version)
            pkg_vulns = vuln_map.get(key, [])
            for v in pkg_vulns:
                findings.append(_vuln_to_finding(v, str(lf)))

        if findings:
            # Sort: critical first
            findings.sort(key=lambda f: (0 if f.severity == Severity.CRITICAL else 1 if f.severity == Severity.WARNING else 2))
            analyses.append(
                FileAnalysis(
                    path=str(lf),
                    language="lockfile",
                    lines=0,
                    findings=findings,
                )
            )

    return analyses


def _vuln_to_finding(vuln: Vulnerability, lockfile_path: str) -> Finding:
    """Convert an OSV Vulnerability to a Dojigiri Finding."""
    severity = _SEVERITY_MAP.get(vuln.severity, Severity.WARNING)

    # Build message
    ids = [vuln.vuln_id] + [a for a in vuln.aliases if a != vuln.vuln_id]
    id_str = ", ".join(ids[:3])  # Show up to 3 IDs
    msg = f"{vuln.package} {vuln.installed_version} — {id_str}"
    if vuln.summary:
        msg += f": {vuln.summary}"

    suggestion = None
    if vuln.fix_version:
        suggestion = f"Upgrade {vuln.package} to {vuln.fix_version}"

    return Finding(
        file=lockfile_path,
        line=1,
        severity=severity,
        category=Category.SECURITY,
        source=Source.SCA,
        rule="vulnerable-dependency",
        message=msg,
        suggestion=suggestion,
        snippet=f"{vuln.package}=={vuln.installed_version}",
    )
