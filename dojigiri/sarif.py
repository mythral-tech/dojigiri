"""SARIF 2.1.0 output converter for Dojigiri scan reports.

Converts a ScanReport into SARIF (Static Analysis Results Interchange Format),
the industry standard consumed by GitHub Code Scanning, GitLab SAST, Azure
DevOps, and other CI/CD result management systems.

Called by: report.py (print_sarif), __main__.py
Calls into: compliance.py (CWE lookups), types.py
Data in -> Data out: ScanReport -> SARIF dict
"""

from __future__ import annotations  # noqa

import hashlib
from datetime import datetime, timezone

from . import __version__
from .compliance import get_cwe, get_nist
from .types import CrossFileFinding, ScanReport, Severity

# SARIF severity mapping
_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

DOJIGIRI_URI = "https://github.com/mythral-tech/dojigiri"

CWE_TAXONOMY_URI = "https://cwe.mitre.org/data/published/cwe_latest.pdf"


def _to_uri(path: str) -> str:
    """Normalize a file path to a forward-slash URI-safe string."""
    return path.replace("\\", "/")


def _fingerprint(file: str, rule: str, snippet: str | None) -> str:
    """Content-based fingerprint that survives line shifts.

    Uses file + rule + snippet hash so that moving code doesn't generate
    a new alert as long as the code itself hasn't changed.  Falls back to
    file + rule when no snippet is available.
    """
    key = f"{file}:{rule}"
    if snippet and snippet != "[REDACTED]":
        key += f":{snippet}"
    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:16]


def _build_rule(finding_or_cf: object, rules_map: dict[str, dict]) -> int:
    """Register a rule in rules_map if new; return the rule index."""
    rule = finding_or_cf.rule  # type: ignore[union-attr]
    if rule in rules_map:
        return list(rules_map.keys()).index(rule)

    rule_entry: dict = {
        "id": rule,
        "shortDescription": {"text": finding_or_cf.message},  # type: ignore[union-attr]
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL[finding_or_cf.severity],  # type: ignore[union-attr]
        },
        "properties": {
            "tags": [],
            "category": finding_or_cf.category.value,  # type: ignore[union-attr]
        },
    }
    # Source is only on Finding, not CrossFileFinding
    if hasattr(finding_or_cf, "source"):
        rule_entry["properties"]["source"] = finding_or_cf.source.value

    cwe = get_cwe(rule)
    if cwe:
        cwe_num = cwe.replace("CWE-", "")
        rule_entry["properties"]["tags"].append(f"external/cwe/cwe-{cwe_num}")
    nist = get_nist(rule)
    if nist:
        rule_entry["properties"]["nist"] = nist

    rules_map[rule] = rule_entry
    return len(rules_map) - 1


def _add_cwe_taxa(rule: str, result: dict, cwe_taxa: dict[str, dict]) -> None:
    """Add CWE taxa reference to a SARIF result if applicable."""
    cwe = get_cwe(rule)
    if cwe:
        cwe_num = cwe.replace("CWE-", "")
        result["taxa"] = [{"id": cwe_num, "toolComponent": {"name": "cwe"}}]
        if cwe_num not in cwe_taxa:
            cwe_taxa[cwe_num] = {"id": cwe_num, "guid": cwe}


def _build_per_file_results(
    report: ScanReport, rules_map: dict[str, dict],
    artifacts_map: dict[str, int], cwe_taxa: dict[str, dict],
) -> list[dict]:
    """Build SARIF results from per-file findings."""
    results = []
    for fa in report.file_analyses:
        uri = _to_uri(fa.path)
        if uri not in artifacts_map:
            artifacts_map[uri] = len(artifacts_map)
        artifact_idx = artifacts_map[uri]

        for f in fa.findings:
            rule_idx = _build_rule(f, rules_map)
            message_text = f"{f.message} — {f.suggestion}" if f.suggestion else f.message
            snippet = f.to_dict()["snippet"]

            region: dict = {"startLine": f.line, "startColumn": 1}
            if snippet:
                region["snippet"] = {"text": snippet}

            result: dict = {
                "ruleId": f.rule,
                "ruleIndex": rule_idx,
                "level": _SEVERITY_TO_LEVEL[f.severity],
                "message": {"text": message_text},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%", "index": artifact_idx},
                        "region": region,
                    }
                }],
                "partialFingerprints": {"primaryLocationLineHash": _fingerprint(uri, f.rule, snippet)},
            }
            if f.suggestion:
                result["fixes"] = [{"description": {"text": f.suggestion}}]
            _add_cwe_taxa(f.rule, result, cwe_taxa)
            if f.confidence:
                result.setdefault("properties", {})["confidence"] = f.confidence.value
            results.append(result)
    return results


def _build_cross_file_results(
    report: ScanReport, rules_map: dict[str, dict],
    artifacts_map: dict[str, int], cwe_taxa: dict[str, dict],
) -> list[dict]:
    """Build SARIF results from cross-file findings."""
    results = []
    for cf in report.cross_file_findings:
        rule_idx = _build_rule(cf, rules_map)
        source_uri = _to_uri(cf.source_file)
        target_uri = _to_uri(cf.target_file)
        if source_uri not in artifacts_map:
            artifacts_map[source_uri] = len(artifacts_map)
        source_artifact = artifacts_map[source_uri]
        if target_uri not in artifacts_map:
            artifacts_map[target_uri] = len(artifacts_map)

        result: dict = {
            "ruleId": cf.rule,
            "ruleIndex": rule_idx,
            "level": _SEVERITY_TO_LEVEL[cf.severity],
            "message": {"text": cf.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": source_uri, "uriBaseId": "%SRCROOT%", "index": source_artifact},
                    "region": {"startLine": cf.line, "startColumn": 1},
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": _fingerprint(source_uri, cf.rule, None)},
        }

        related: dict = {
            "id": 0,
            "message": {"text": f"Related location in {cf.target_file}"},
            "physicalLocation": {"artifactLocation": {"uri": target_uri, "uriBaseId": "%SRCROOT%"}},
        }
        if cf.target_line is not None:
            related["physicalLocation"]["region"] = {"startLine": cf.target_line, "startColumn": 1}
        result["relatedLocations"] = [related]

        if cf.suggestion:
            result["fixes"] = [{"description": {"text": cf.suggestion}}]
        _add_cwe_taxa(cf.rule, result, cwe_taxa)
        if cf.confidence:
            result.setdefault("properties", {})["confidence"] = cf.confidence.value
        results.append(result)
    return results


def to_sarif(report: ScanReport) -> dict:
    """Convert a ScanReport to a SARIF 2.1.0 document (as a dict).

    The returned dict is JSON-serializable and conforms to the SARIF 2.1.0
    schema including tool metadata, rules with CWE tags, results with
    locations, taxa references, artifacts, invocations, CWE taxonomy
    declarations, cross-file findings, and content-based fingerprints.
    """
    rules_map: dict[str, dict] = {}
    artifacts_map: dict[str, int] = {}
    cwe_taxa: dict[str, dict] = {}

    results = _build_per_file_results(report, rules_map, artifacts_map, cwe_taxa)
    results.extend(_build_cross_file_results(report, rules_map, artifacts_map, cwe_taxa))

    artifacts = [{"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}} for uri in artifacts_map]

    extensions = []
    if cwe_taxa:
        extensions.append({
            "name": "cwe", "version": "4.15", "informationUri": CWE_TAXONOMY_URI,
            "organization": "MITRE", "shortDescription": {"text": "Common Weakness Enumeration"},
            "taxa": list(cwe_taxa.values()),
        })

    now = report.timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
    invocation: dict = {"executionSuccessful": True, "endTimeUtc": now, "properties": {"mode": report.mode}}

    driver: dict = {
        "name": "dojigiri", "semanticVersion": __version__,
        "informationUri": DOJIGIRI_URI, "rules": list(rules_map.values()),
    }
    run: dict = {
        "tool": {"driver": driver}, "invocations": [invocation],
        "artifacts": artifacts, "results": results,
        "properties": {"mode": report.mode, "filesScanned": report.files_scanned, "filesSkipped": report.files_skipped},
    }
    if extensions:
        run["tool"]["extensions"] = extensions
        run["taxonomies"] = extensions

    return {"version": "2.1.0", "$schema": SARIF_SCHEMA, "runs": [run]}
