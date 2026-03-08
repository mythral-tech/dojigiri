"""SARIF 2.1.0 output converter for Dojigiri scan reports.

Converts a ScanReport into SARIF (Static Analysis Results Interchange Format),
the industry standard consumed by GitHub Code Scanning, GitLab SAST, Azure
DevOps, and other CI/CD result management systems.

Called by: report.py (print_sarif), __main__.py
Calls into: compliance.py (CWE lookups), types.py
Data in -> Data out: ScanReport -> SARIF dict
"""

from __future__ import annotations

from . import __version__
from .compliance import get_cwe, get_nist
from .types import Severity, ScanReport

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


def to_sarif(report: ScanReport) -> dict:
    """Convert a ScanReport to a SARIF 2.1.0 document (as a dict).

    The returned dict is JSON-serializable and conforms to the SARIF 2.1.0
    schema including tool metadata, rules with CWE tags, results with
    locations, taxa references, and partial fingerprints.
    """
    rules_map: dict[str, dict] = {}
    results: list[dict] = []

    for fa in report.file_analyses:
        for f in fa.findings:
            # Build rule entry (deduplicated by rule name)
            if f.rule not in rules_map:
                rule_entry: dict = {
                    "id": f.rule,
                    "shortDescription": {"text": f.message},
                    "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[f.severity]},
                    "properties": {
                        "tags": [],
                        "category": f.category.value,
                        "source": f.source.value,
                    },
                }
                cwe = get_cwe(f.rule)
                if cwe:
                    cwe_num = cwe.replace("CWE-", "")
                    rule_entry["properties"]["tags"].append(f"external/cwe/cwe-{cwe_num}")
                nist = get_nist(f.rule)
                if nist:
                    rule_entry["properties"]["nist"] = nist
                rules_map[f.rule] = rule_entry

            # Build result entry
            message_text = f.message
            if f.suggestion:
                message_text = f"{f.message} — {f.suggestion}"

            result: dict = {
                "ruleId": f.rule,
                "level": _SEVERITY_TO_LEVEL[f.severity],
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": f.line, "startColumn": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": f"{f.file}:{f.rule}:{f.line}",
                },
            }

            # Snippet (secrets redacted via to_dict)
            snippet = f.to_dict()["snippet"]
            if snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": snippet
                }

            # Suggestion as SARIF fix
            if f.suggestion:
                result["fixes"] = [{"description": {"text": f.suggestion}}]

            # CWE taxa reference on the result
            cwe = get_cwe(f.rule)
            if cwe:
                cwe_num = cwe.replace("CWE-", "")
                result["taxa"] = [
                    {
                        "id": cwe_num,
                        "toolComponent": {"name": "cwe"},
                    }
                ]

            # Confidence (LLM findings only)
            if f.confidence:
                result.setdefault("properties", {})["confidence"] = f.confidence.value

            results.append(result)

    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dojigiri",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Inklling/dojigiri",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
                "properties": {
                    "mode": report.mode,
                    "filesScanned": report.files_scanned,
                    "filesSkipped": report.files_skipped,
                },
            }
        ],
    }
