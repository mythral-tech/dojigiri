"""OSV (Open Source Vulnerability) API client.

Uses Google's OSV API (https://api.osv.dev) for vulnerability lookups.
No API key required. Zero external dependencies — stdlib urllib only.

The batch endpoint (/v1/querybatch) returns only vuln IDs, so we fetch
full details via /v1/vulns/{id} for severity, summary, and fix info.
Concurrent fetching keeps latency reasonable.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
OSV_BATCH_LIMIT = 1000


@dataclass
class Vulnerability:
    """A single vulnerability affecting a package."""

    vuln_id: str
    package: str
    installed_version: str
    ecosystem: str
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    summary: str = ""
    fix_version: str | None = None


def query_osv(packages: list[tuple[str, str, str]], timeout: int = 30) -> list[Vulnerability]:
    """Query OSV for vulnerabilities affecting the given packages."""
    if not packages:
        return []

    all_vulns: list[Vulnerability] = []
    for i in range(0, len(packages), OSV_BATCH_LIMIT):
        batch = packages[i : i + OSV_BATCH_LIMIT]
        vulns = _query_batch(batch, timeout)
        all_vulns.extend(vulns)
    return all_vulns


def _query_batch(packages: list[tuple[str, str, str]], timeout: int) -> list[Vulnerability]:
    """Batch query OSV, then fetch full details for each vuln."""
    queries = [
        {"package": {"name": name, "ecosystem": eco}, "version": ver}
        for name, ver, eco in packages
    ]
    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        logger.error("OSV batch query failed: %s", e)
        return []

    # Collect (vuln_id, package_info) pairs from batch response
    vuln_pkg_map: dict[str, tuple[str, str, str]] = {}
    results = data.get("results", [])
    for idx, result in enumerate(results):
        if idx >= len(packages):
            break
        for vuln_stub in result.get("vulns", []):
            vid = vuln_stub.get("id", "")
            if vid and vid not in vuln_pkg_map:
                vuln_pkg_map[vid] = packages[idx]

    if not vuln_pkg_map:
        return []

    logger.info("Fetching details for %d vulnerabilities...", len(vuln_pkg_map))

    # Fetch full vuln details concurrently
    vuln_details: dict[str, dict] = {}
    max_workers = min(20, len(vuln_pkg_map))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_fetch_vuln, vid, timeout): vid
            for vid in vuln_pkg_map
        }
        for future in as_completed(futures):
            vid = futures[future]
            try:
                detail = future.result()
                if detail:
                    vuln_details[vid] = detail
            except Exception:
                pass

    # Build Vulnerability objects
    vulns: list[Vulnerability] = []
    for vid, pkg_info in vuln_pkg_map.items():
        detail = vuln_details.get(vid)
        if not detail:
            # Fallback: minimal vuln with just the ID
            vulns.append(Vulnerability(
                vuln_id=vid,
                package=pkg_info[0],
                installed_version=pkg_info[1],
                ecosystem=pkg_info[2],
            ))
            continue
        vuln = _parse_vuln(detail, pkg_info[0], pkg_info[1], pkg_info[2])
        if vuln:
            vulns.append(vuln)

    return vulns


def _fetch_vuln(vuln_id: str, timeout: int) -> dict | None:
    """Fetch full vulnerability details from OSV."""
    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        logger.debug("Failed to fetch %s: %s", vuln_id, e)
        return None


def _parse_vuln(
    data: dict, package: str, version: str, ecosystem: str
) -> Vulnerability | None:
    """Parse a full OSV vulnerability response."""
    vuln_id = data.get("id", "")
    if not vuln_id:
        return None

    aliases = data.get("aliases", [])
    summary = data.get("summary", "") or (data.get("details", "") or "")[:200]

    severity = "UNKNOWN"
    cvss_score = None

    # 1. Try database_specific.severity (GHSA provides this)
    db_specific = data.get("database_specific", {})
    if "severity" in db_specific:
        severity = db_specific["severity"].upper()

    # 2. Try CVSS vector from severity array
    if severity == "UNKNOWN":
        for sev in data.get("severity", []):
            score_str = sev.get("score", "")
            if score_str.startswith("CVSS:"):
                cvss_score = _parse_cvss_score(score_str)
                if cvss_score is not None:
                    severity = _cvss_to_severity(cvss_score)
                    break

    # 3. Try affected[].database_specific or ecosystem_specific
    if severity == "UNKNOWN":
        for affected in data.get("affected", []):
            for key in ("database_specific", "ecosystem_specific"):
                sev = affected.get(key, {}).get("severity", "")
                if sev:
                    severity = sev.upper()
                    break
            if severity != "UNKNOWN":
                break

    fix_version = _find_fix_version(data, package, ecosystem)

    return Vulnerability(
        vuln_id=vuln_id,
        package=package,
        installed_version=version,
        ecosystem=ecosystem,
        aliases=aliases,
        severity=severity,
        cvss_score=cvss_score,
        summary=summary,
        fix_version=fix_version,
    )


def _find_fix_version(data: dict, package: str, ecosystem: str) -> str | None:
    """Extract the fix version from affected ranges."""
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _parse_cvss_score(vector: str) -> float | None:
    """Estimate CVSS base score from a CVSS v3.x or v4.0 vector string.

    This is a rough approximation — enough to classify severity tiers.
    Full CVSS calculation requires a library we don't want to depend on.
    """
    # Common CVSS v3.x metrics and rough weights
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val

    # If it's CVSS v3.x, estimate from key metrics
    av = metrics.get("AV", "N")  # Attack Vector
    ac = metrics.get("AC", "L")  # Attack Complexity
    pr = metrics.get("PR", "N")  # Privileges Required
    ui = metrics.get("UI", "N")  # User Interaction
    ci = metrics.get("C", metrics.get("VC", "N"))  # Confidentiality Impact
    ii = metrics.get("I", metrics.get("VI", "N"))  # Integrity Impact
    ai = metrics.get("A", metrics.get("VA", "N"))  # Availability Impact

    # Rough scoring: high impact + easy access = critical
    impact_scores = {"H": 3, "L": 1, "N": 0}
    access_scores = {"N": 3, "A": 2, "L": 1, "P": 0}  # Network > Adjacent > Local > Physical
    complexity_scores = {"L": 2, "H": 0}
    priv_scores = {"N": 2, "L": 1, "H": 0}
    ui_scores = {"N": 1, "R": 0}

    impact = sum(impact_scores.get(x, 0) for x in [ci, ii, ai])  # 0-9
    access = access_scores.get(av, 1)
    complexity = complexity_scores.get(ac, 1)
    priv = priv_scores.get(pr, 1)
    ui_val = ui_scores.get(ui, 0)

    # Normalize to 0-10 range
    raw = (impact / 9) * 6 + (access / 3) * 1.5 + (complexity / 2) * 1 + (priv / 2) * 1 + ui_val * 0.5
    return min(10.0, round(raw, 1))


def _cvss_to_severity(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"
