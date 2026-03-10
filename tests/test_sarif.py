"""Comprehensive SARIF output tests — complementary to test_report.py.

Focuses on structural validation, CWE taxonomy, edge cases, and schema compliance
that test_report.py doesn't cover.
"""

import json
import pytest

from dojigiri.sarif import to_sarif, SARIF_SCHEMA, _to_uri, _fingerprint
from dojigiri.compliance import CWE_MAP
from dojigiri.types import (
    CrossFileFinding,
    Finding, FileAnalysis, ScanReport,
    Severity, Category, Source, Confidence,
)
from dojigiri import __version__


def _finding(rule="test-rule", line=10, severity=Severity.WARNING,
             category=Category.BUG, source=Source.STATIC,
             message="Test", suggestion=None, snippet=None,
             confidence=None, file="app.py"):
    return Finding(
        file=file, line=line, severity=severity,
        category=category, source=source, rule=rule,
        message=message, suggestion=suggestion,
        snippet=snippet, confidence=confidence,
    )


def _report(findings, path="app.py", mode="quick", cross_file_findings=None):
    fa = FileAnalysis(path=path, language="python", lines=50, findings=findings)
    return ScanReport(
        root="/project", mode=mode,
        files_scanned=1, files_skipped=0,
        file_analyses=[fa],
        cross_file_findings=cross_file_findings or [],
    )


# ─── Schema structure ────────────────────────────────────────────────


class TestSarifSchema:
    def test_top_level_keys(self):
        """SARIF document has version, $schema, and runs."""
        sarif = to_sarif(_report([_finding()]))
        assert set(sarif.keys()) == {"version", "$schema", "runs"}
        assert sarif["version"] == "2.1.0"

    def test_schema_url(self):
        """$schema points to the OASIS SARIF 2.1.0 schema."""
        sarif = to_sarif(_report([_finding()]))
        assert sarif["$schema"] == SARIF_SCHEMA
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_single_run(self):
        """Output always has exactly one run."""
        sarif = to_sarif(_report([_finding()]))
        assert len(sarif["runs"]) == 1

    def test_tool_driver_metadata(self):
        """Tool driver has name, version, and informationUri."""
        sarif = to_sarif(_report([_finding()]))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "dojigiri"
        assert driver["semanticVersion"] == __version__
        assert "informationUri" in driver

    def test_full_json_roundtrip(self):
        """SARIF document survives JSON serialization roundtrip."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", severity=Severity.CRITICAL,
                     category=Category.SECURITY, suggestion="Use ast.literal_eval"),
            _finding(rule="bare-except", line=20),
        ]))
        text = json.dumps(sarif)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 2


# ─── CWE taxonomy ────────────────────────────────────────────────────


class TestCWETaxonomy:
    def test_known_rule_has_cwe_tag(self):
        """Rules with CWE mappings get external/cwe tags on the rule entry."""
        sarif = to_sarif(_report([_finding(rule="eval-usage", severity=Severity.CRITICAL,
                                           category=Category.SECURITY)]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        tags = rules[0]["properties"]["tags"]
        assert any("cwe-95" in t for t in tags)

    def test_known_rule_has_taxa_on_result(self):
        """Results for CWE-mapped rules have taxa references."""
        sarif = to_sarif(_report([_finding(rule="sql-injection-execute",
                                           severity=Severity.CRITICAL,
                                           category=Category.SECURITY)]))
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert result["taxa"][0]["toolComponent"]["name"] == "cwe"
        assert result["taxa"][0]["id"] == "89"

    def test_unknown_rule_no_taxa(self):
        """Rules without CWE mappings do not have taxa references."""
        sarif = to_sarif(_report([_finding(rule="custom-rule-xyz")]))
        result = sarif["runs"][0]["results"][0]
        assert "taxa" not in result

    def test_unknown_rule_empty_tags(self):
        """Rules without CWE mappings have empty tags list."""
        sarif = to_sarif(_report([_finding(rule="custom-rule-xyz")]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["properties"]["tags"] == []

    def test_multiple_cwe_rules_dedup(self):
        """Multiple findings with the same rule produce one rule entry."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", line=1, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
            _finding(rule="eval-usage", line=20, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
        ]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_cwe_taxonomy_extension_declared(self):
        """When CWE-mapped rules exist, taxonomies and extensions are declared."""
        sarif = to_sarif(_report([_finding(rule="eval-usage", severity=Severity.CRITICAL,
                                           category=Category.SECURITY)]))
        run = sarif["runs"][0]
        assert "taxonomies" in run
        assert run["taxonomies"][0]["name"] == "cwe"
        assert run["taxonomies"][0]["organization"] == "MITRE"
        assert len(run["taxonomies"][0]["taxa"]) >= 1
        assert "extensions" in run["tool"]
        assert run["tool"]["extensions"][0]["name"] == "cwe"

    def test_no_cwe_no_taxonomy(self):
        """When no CWE-mapped rules exist, no taxonomy section is added."""
        sarif = to_sarif(_report([_finding(rule="custom-rule-xyz")]))
        run = sarif["runs"][0]
        assert "taxonomies" not in run
        assert "extensions" not in run["tool"]


# ─── Empty / edge cases ──────────────────────────────────────────────


class TestSarifEdgeCases:
    def test_empty_report_valid_structure(self):
        """Empty report produces valid SARIF with no results or rules."""
        report = ScanReport(root="/project", mode="quick",
                            files_scanned=0, files_skipped=0)
        sarif = to_sarif(report)
        run = sarif["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        assert run["artifacts"] == []
        # Still valid JSON
        json.dumps(sarif)

    def test_finding_without_snippet(self):
        """Finding with no snippet still produces valid location."""
        sarif = to_sarif(_report([_finding(snippet=None)]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        region = loc["region"]
        assert region["startLine"] == 10
        assert "snippet" not in region

    def test_finding_without_suggestion_no_fixes(self):
        """Finding with no suggestion has no fixes key."""
        sarif = to_sarif(_report([_finding(suggestion=None)]))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" not in result

    def test_finding_with_suggestion_has_fixes(self):
        """Finding with suggestion produces fixes entry."""
        sarif = to_sarif(_report([_finding(suggestion="Use X instead")]))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Use X instead"

    def test_run_properties_reflect_report(self):
        """Run properties contain mode and file counts from the report."""
        report = ScanReport(root="/p", mode="deep",
                            files_scanned=42, files_skipped=7)
        sarif = to_sarif(report)
        props = sarif["runs"][0]["properties"]
        assert props["mode"] == "deep"
        assert props["filesScanned"] == 42
        assert props["filesSkipped"] == 7

    def test_artifact_location_uses_srcroot_base(self):
        """Artifact location uses %SRCROOT% as uriBaseId."""
        sarif = to_sarif(_report([_finding()]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_llm_confidence_in_properties(self):
        """LLM findings have confidence in result properties."""
        sarif = to_sarif(_report([
            _finding(source=Source.LLM, confidence=Confidence.HIGH),
        ]))
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["confidence"] == "high"

    def test_severity_mapping_complete(self):
        """All three severity levels map correctly."""
        sarif = to_sarif(_report([
            _finding(rule="r1", severity=Severity.CRITICAL, line=1),
            _finding(rule="r2", severity=Severity.WARNING, line=2),
            _finding(rule="r3", severity=Severity.INFO, line=3),
        ]))
        levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
        assert levels == {"r1": "error", "r2": "warning", "r3": "note"}


# ─── Rule index ──────────────────────────────────────────────────────


class TestRuleIndex:
    def test_results_have_rule_index(self):
        """Every result has a ruleIndex pointing to the correct rule."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", line=1, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
            _finding(rule="bare-except", line=20),
        ]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        for r in results:
            assert "ruleIndex" in r
            assert rules[r["ruleIndex"]]["id"] == r["ruleId"]

    def test_duplicate_rule_same_index(self):
        """Multiple findings with the same rule share the same ruleIndex."""
        sarif = to_sarif(_report([
            _finding(rule="eval-usage", line=1, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
            _finding(rule="eval-usage", line=20, severity=Severity.CRITICAL,
                     category=Category.SECURITY),
        ]))
        results = sarif["runs"][0]["results"]
        assert results[0]["ruleIndex"] == results[1]["ruleIndex"]


# ─── Artifacts ───────────────────────────────────────────────────────


class TestArtifacts:
    def test_artifacts_listed(self):
        """Scanned files appear in the artifacts array."""
        sarif = to_sarif(_report([_finding()]))
        artifacts = sarif["runs"][0]["artifacts"]
        assert len(artifacts) == 1
        assert artifacts[0]["location"]["uri"] == "app.py"

    def test_artifact_index_on_location(self):
        """Result locations reference artifact by index."""
        sarif = to_sarif(_report([_finding()]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["index"] == 0

    def test_multiple_files_deduplicated(self):
        """Multiple findings in the same file produce one artifact."""
        sarif = to_sarif(_report([
            _finding(line=1), _finding(line=20),
        ]))
        artifacts = sarif["runs"][0]["artifacts"]
        assert len(artifacts) == 1


# ─── Invocations ─────────────────────────────────────────────────────


class TestInvocations:
    def test_invocation_present(self):
        """Run has an invocations array with one entry."""
        sarif = to_sarif(_report([_finding()]))
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_invocation_has_end_time(self):
        """Invocation includes endTimeUtc."""
        sarif = to_sarif(_report([_finding()]))
        inv = sarif["runs"][0]["invocations"][0]
        assert "endTimeUtc" in inv

    def test_invocation_uses_report_timestamp(self):
        """When report has a timestamp, invocation uses it."""
        report = _report([_finding()])
        report.timestamp = "2026-03-10T12:00:00+00:00"
        sarif = to_sarif(report)
        inv = sarif["runs"][0]["invocations"][0]
        assert inv["endTimeUtc"] == "2026-03-10T12:00:00+00:00"

    def test_invocation_has_mode(self):
        """Invocation properties include scan mode."""
        sarif = to_sarif(_report([_finding()], mode="deep"))
        inv = sarif["runs"][0]["invocations"][0]
        assert inv["properties"]["mode"] == "deep"


# ─── Cross-file findings ────────────────────────────────────────────


class TestCrossFileFindings:
    def _cf(self, **kwargs):
        defaults = dict(
            source_file="src/auth.py",
            target_file="src/utils.py",
            line=42,
            target_line=10,
            severity=Severity.WARNING,
            category=Category.BUG,
            rule="semantic-clone",
            message="Duplicate logic detected",
        )
        defaults.update(kwargs)
        return CrossFileFinding(**defaults)

    def test_cross_file_findings_in_results(self):
        """Cross-file findings appear in the results array."""
        sarif = to_sarif(_report([], cross_file_findings=[self._cf()]))
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "semantic-clone"

    def test_cross_file_has_related_locations(self):
        """Cross-file results have relatedLocations for the target file."""
        sarif = to_sarif(_report([], cross_file_findings=[self._cf()]))
        result = sarif["runs"][0]["results"][0]
        assert "relatedLocations" in result
        related = result["relatedLocations"][0]
        assert related["physicalLocation"]["artifactLocation"]["uri"] == "src/utils.py"
        assert related["physicalLocation"]["region"]["startLine"] == 10

    def test_cross_file_no_target_line(self):
        """Cross-file finding without target_line omits region on related location."""
        cf = self._cf(target_line=None)
        sarif = to_sarif(_report([], cross_file_findings=[cf]))
        related = sarif["runs"][0]["results"][0]["relatedLocations"][0]
        assert "region" not in related["physicalLocation"]

    def test_cross_file_both_files_in_artifacts(self):
        """Both source and target files appear in artifacts."""
        sarif = to_sarif(_report([], cross_file_findings=[self._cf()]))
        uris = {a["location"]["uri"] for a in sarif["runs"][0]["artifacts"]}
        assert "src/auth.py" in uris
        assert "src/utils.py" in uris

    def test_cross_file_with_suggestion(self):
        """Cross-file finding with suggestion includes fixes."""
        cf = self._cf(suggestion="Extract shared logic")
        sarif = to_sarif(_report([], cross_file_findings=[cf]))
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Extract shared logic"

    def test_cross_file_rule_index(self):
        """Cross-file findings have valid ruleIndex."""
        sarif = to_sarif(_report([], cross_file_findings=[self._cf()]))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        result = sarif["runs"][0]["results"][0]
        assert rules[result["ruleIndex"]]["id"] == "semantic-clone"

    def test_mixed_findings_and_cross_file(self):
        """Per-file and cross-file findings coexist correctly."""
        sarif = to_sarif(_report(
            [_finding(rule="eval-usage", severity=Severity.CRITICAL,
                      category=Category.SECURITY)],
            cross_file_findings=[self._cf()],
        ))
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2


# ─── URI normalization ───────────────────────────────────────────────


class TestURINormalization:
    def test_backslashes_converted(self):
        """Windows backslashes in paths are converted to forward slashes."""
        sarif = to_sarif(_report([_finding(file="src\\auth\\login.py")],
                                 path="src\\auth\\login.py"))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "\\" not in loc["artifactLocation"]["uri"]
        assert loc["artifactLocation"]["uri"] == "src/auth/login.py"

    def test_to_uri_helper(self):
        """_to_uri normalizes paths correctly."""
        assert _to_uri("src\\foo\\bar.py") == "src/foo/bar.py"
        assert _to_uri("src/foo/bar.py") == "src/foo/bar.py"


# ─── Fingerprints ────────────────────────────────────────────────────


class TestFingerprints:
    def test_fingerprint_is_hex(self):
        """Fingerprints are hex strings."""
        sarif = to_sarif(_report([_finding()]))
        fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_length(self):
        """Fingerprints are 16 hex chars (64 bits)."""
        fp = _fingerprint("app.py", "eval-usage", "eval(x)")
        assert len(fp) == 16

    def test_fingerprint_content_based(self):
        """Same file+rule+snippet produces the same fingerprint regardless of line."""
        fp1 = _fingerprint("app.py", "eval-usage", "eval(x)")
        fp2 = _fingerprint("app.py", "eval-usage", "eval(x)")
        assert fp1 == fp2

    def test_fingerprint_different_snippet(self):
        """Different snippets produce different fingerprints."""
        fp1 = _fingerprint("app.py", "eval-usage", "eval(x)")
        fp2 = _fingerprint("app.py", "eval-usage", "eval(y)")
        assert fp1 != fp2

    def test_fingerprint_no_snippet_fallback(self):
        """Without a snippet, fingerprint still works (file+rule only)."""
        fp = _fingerprint("app.py", "eval-usage", None)
        assert len(fp) == 16

    def test_fingerprint_redacted_ignored(self):
        """[REDACTED] snippets are treated as no-snippet."""
        fp_redacted = _fingerprint("app.py", "secret-rule", "[REDACTED]")
        fp_none = _fingerprint("app.py", "secret-rule", None)
        assert fp_redacted == fp_none
