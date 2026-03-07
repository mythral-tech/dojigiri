"""HTML report generator for Dojigiri scan results.

Renders a ScanReport into a self-contained HTML page with severity badges,
CWE/NIST compliance tags, and collapsible file sections.

Called by: __main__.py
Calls into: config.py, compliance.py
Data in -> Data out: ScanReport -> HTML string
"""

import html
from datetime import datetime
from typing import Optional

from .types import ScanReport
from .compliance import get_cwe, get_nist


_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "warning": "#d97706",
    "info": "#2563eb",
}

_SEVERITY_BG = {
    "critical": "#fef2f2",
    "warning": "#fffbeb",
    "info": "#eff6ff",
}


def render_html(
    report: ScanReport,
    classification: Optional[str] = None,
    project_name: Optional[str] = None,
) -> str:
    """Render a self-contained HTML report with inline CSS.

    Returns the full HTML document as a string.
    """
    title = project_name or report.root
    timestamp = report.timestamp or datetime.now().isoformat(timespec="seconds")
    cls_banner = ""
    cls_footer = ""
    if classification:
        cls_banner = f"""<div class="classification-banner">{html.escape(classification)}</div>"""
        cls_footer = f"""<div class="classification-banner">{html.escape(classification)}</div>"""

    # Build findings table rows
    findings_rows = []
    for fa in report.file_analyses:
        for f in fa.findings:
            sev = f.severity.value
            color = _SEVERITY_COLOR.get(sev, "#666")
            bg = _SEVERITY_BG.get(sev, "#f9f9f9")
            cwe = get_cwe(f.rule) or ""
            nist_list = get_nist(f.rule)
            nist = ", ".join(nist_list) if nist_list else ""
            snippet = html.escape(f.snippet or "")
            suggestion = html.escape(f.suggestion or "")

            source_label = html.escape(f.source.value if hasattr(f, 'source') else "static")
            conf_badge = ""
            if source_label == "llm" and f.confidence:
                conf_badge = f' <span class="confidence-badge">{html.escape(f.confidence.value)}</span>'

            findings_rows.append(f"""<tr style="background:{bg}">
  <td style="color:{color};font-weight:bold">{html.escape(sev.upper())}</td>
  <td><code>{source_label}</code>{conf_badge}</td>
  <td>{html.escape(f.file)}:{f.line}</td>
  <td><code>{html.escape(f.rule)}</code></td>
  <td>{html.escape(cwe)}</td>
  <td>{html.escape(f.message)}</td>
  <td class="mono">{snippet}</td>
  <td>{suggestion}</td>
  <td>{html.escape(nist)}</td>
</tr>""")

    findings_html = "\n".join(findings_rows) if findings_rows else "<tr><td colspan='9'>No findings</td></tr>"

    # Per-file breakdown
    file_sections = []
    for fa in report.file_analyses:
        if not fa.findings:
            continue
        file_findings = []
        for f in fa.findings:
            sev = f.severity.value
            color = _SEVERITY_COLOR.get(sev, "#666")
            cwe = get_cwe(f.rule) or ""
            cwe_tag = f' <span class="cwe-tag">{html.escape(cwe)}</span>' if cwe else ""
            file_findings.append(
                f'<div class="finding" style="border-left:3px solid {color};padding-left:8px;margin:6px 0">'
                f'<strong style="color:{color}">{html.escape(sev.upper())}</strong> '
                f'line {f.line} &mdash; <code>{html.escape(f.rule)}</code>{cwe_tag}<br>'
                f'{html.escape(f.message)}'
                f'{"<br><em>" + html.escape(f.suggestion) + "</em>" if f.suggestion else ""}'
                '</div>'
            )
        file_sections.append(
            '<div class="file-section">'
            f'<h3>{html.escape(fa.path)} <span class="dim">({fa.language}, {fa.lines} lines)</span></h3>'
            f'{"".join(file_findings)}'
            '</div>'
        )

    files_html = "\n".join(file_sections) if file_sections else "<p>No files with findings.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Dojigiri Report — {html.escape(title)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         color: #1a1a1a; line-height: 1.5; padding: 20px; max-width: 1200px; margin: 0 auto; }}
  .classification-banner {{
    background: #dc2626; color: white; text-align: center;
    font-weight: bold; font-size: 14px; padding: 6px 0;
    letter-spacing: 2px; margin-bottom: 20px;
  }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; margin: 24px 0 12px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
  h3 {{ font-size: 14px; margin: 16px 0 8px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 20px; }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin: 16px 0;
  }}
  .summary-card {{
    background: #f8f8f8; border-radius: 8px; padding: 12px; text-align: center;
  }}
  .summary-card .number {{ font-size: 28px; font-weight: bold; }}
  .summary-card .label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
  .crit .number {{ color: #dc2626; }}
  .warn .number {{ color: #d97706; }}
  .info-card .number {{ color: #2563eb; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin: 12px 0; }}
  th {{ background: #1a1a1a; color: white; padding: 8px 10px; text-align: left; font-size: 12px; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 12px; }}
  .mono {{ font-family: 'Consolas', 'Monaco', monospace; font-size: 11px; }}
  .dim {{ color: #888; font-weight: normal; }}
  .cwe-tag {{ background: #e0e7ff; color: #3730a3; padding: 1px 5px; border-radius: 3px; font-size: 11px; }}
  .confidence-badge {{ background: #fef3c7; color: #92400e; padding: 1px 5px; border-radius: 3px; font-size: 10px; margin-left: 4px; }}
  .file-section {{ margin: 12px 0; padding: 12px; background: #fafafa; border-radius: 6px; }}
  @media print {{
    .classification-banner {{ break-inside: avoid; }}
    body {{ font-size: 11px; padding: 10px; }}
    .summary-grid {{ grid-template-columns: repeat(4, 1fr); }}
    table {{ font-size: 11px; }}
  }}
</style>
</head>
<body>
{cls_banner}
<h1>Dojigiri Scan Report</h1>
<div class="meta">
  Project: {html.escape(title)} &middot;
  Mode: {html.escape(report.mode)} &middot;
  {html.escape(timestamp)}
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card"><div class="number">{report.files_scanned}</div><div class="label">Files Scanned</div></div>
  <div class="summary-card crit"><div class="number">{report.critical}</div><div class="label">Critical</div></div>
  <div class="summary-card warn"><div class="number">{report.warnings}</div><div class="label">Warnings</div></div>
  <div class="summary-card info-card"><div class="number">{report.info}</div><div class="label">Info</div></div>
  <div class="summary-card"><div class="number">{report.total_findings}</div><div class="label">Total</div></div>
</div>

<h2>All Findings</h2>
<table>
<thead>
<tr><th>Severity</th><th>Source</th><th>Location</th><th>Rule</th><th>CWE</th><th>Message</th><th>Snippet</th><th>Suggestion</th><th>NIST</th></tr>
</thead>
<tbody>
{findings_html}
</tbody>
</table>

<h2>Per-File Breakdown</h2>
{files_html}

{f'<p class="meta">LLM cost: ${report.llm_cost_usd:.4f}</p>' if report.llm_cost_usd > 0 else ""}
{cls_footer}
<div class="disclaimer" style="margin-top:24px;padding:12px;background:#f8f8f8;border-radius:6px;font-size:12px;color:#666">
  <strong>Disclaimer:</strong> This report is generated by automated analysis.
  Findings marked <code>llm</code> are AI-generated and may contain false positives or miss real issues.
  This tool does not guarantee the absence of bugs or vulnerabilities.
  Critical systems should undergo independent security review.
  See <a href="https://github.com/Inklling/dojigiri/blob/main/PRIVACY.md">PRIVACY.md</a> for data handling details.
</div>
<p class="meta" style="margin-top:12px">Generated by Dojigiri v1.1.0</p>
</body>
</html>"""


def render_pdf(
    report: ScanReport,
    output_path: str,
    classification: Optional[str] = None,
    project_name: Optional[str] = None,
) -> None:
    """Render report as PDF via weasyprint (optional dependency).

    Raises ImportError if weasyprint is not installed.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "PDF output requires weasyprint. Install with: pip install dojigiri[pdf]"
        )

    html_content = render_html(report, classification=classification, project_name=project_name)
    HTML(string=html_content).write_pdf(output_path)
