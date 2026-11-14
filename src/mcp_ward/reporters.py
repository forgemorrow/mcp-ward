"""Output formatters for mcp-ward scan reports (Terminal, SARIF 2.1.0, HTML)."""

from __future__ import annotations

import html
from typing import Any

from . import __version__
from .models import ScanReport, Severity

_SARIF_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_terminal(report: ScanReport) -> str:
    """Render a clean plain-text terminal report."""
    lines = [
        f"mcp-ward v{__version__} Security Audit Report",
        "=" * 56,
        f"Target          : {report.target}",
        f"Files Scanned   : {report.files_scanned}",
        f"Tools Discovered: {len(report.tools_discovered)}",
        f"Findings        : {len(report.findings)}",
        f"Toxic Flows     : {len(report.toxic_flows)}",
        f"Risk Score      : {report.risk_score}/100 (Grade: {report.security_grade})",
    ]

    if report.findings:
        lines.extend(["", "Findings:", "-" * 56])
        for idx, finding in enumerate(report.findings, start=1):
            lines.append(
                f"{idx:>2}. [{finding.severity.value:<8}] {finding.rule_id} "
                f"{finding.file_path}:{finding.line} - {finding.title}"
            )
            if finding.snippet:
                lines.append(f"    Evidence: {finding.snippet}")
            if finding.recommendation:
                lines.append(f"    Fix     : {finding.recommendation}")
    else:
        lines.extend(["", "No security issues detected."])

    if report.toxic_flows:
        lines.extend(["", "Toxic Capability Chains:", "-" * 56])
        for flow in report.toxic_flows:
            hop = (
                f"{flow.source_tool} -> {flow.bridge_tool} -> {flow.sink_tool}"
                if flow.bridge_tool
                else f"{flow.source_tool} -> {flow.sink_tool}"
            )
            lines.append(f"- [{flow.severity.value}] {flow.chain_id}: {hop}")
            lines.append(f"  {flow.attack_narrative}")

    return "\n".join(lines)


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """Convert ScanReport to a valid SARIF 2.1.0 dictionary."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation or finding.title},
                "properties": {"category": finding.category},
            }

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVELS[finding.severity],
                "message": {"text": f"{finding.title}: {finding.snippet}".strip(": ")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": max(1, finding.line)},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "category": finding.category,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-ward",
                        "version": __version__,
                        "informationUri": "https://github.com/forgemorrow/mcp-ward",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def to_html(report: ScanReport) -> str:
    """Render a self-contained single-file dark-mode HTML audit report."""
    badge_colors = {
        "A": "#16a34a",
        "B": "#22c55e",
        "C": "#eab308",
        "D": "#f97316",
        "F": "#ef4444",
    }
    grade_color = badge_colors.get(report.security_grade, "#64748b")

    rows: list[str] = []
    for f in report.findings:
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{html.escape(f.severity.value.lower())}'>"
            f"{html.escape(f.severity.value)}</span></td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td><code>{html.escape(f.file_path)}:{f.line}</code></td>"
            f"<td><strong>{html.escape(f.title)}</strong>"
            f"<div class='snippet'>{html.escape(f.snippet)}</div></td>"
            f"<td>{html.escape(f.recommendation)}</td>"
            "</tr>"
        )
    findings_body = (
        "\n".join(rows)
        if rows
        else "<tr><td colspan='5'>No security issues detected.</td></tr>"
    )

    flow_items = []
    for flow in report.toxic_flows:
        chain = (
            f"{flow.source_tool} &rarr; {flow.bridge_tool} &rarr; {flow.sink_tool}"
            if flow.bridge_tool
            else f"{flow.source_tool} &rarr; {flow.sink_tool}"
        )
        flow_items.append(
            f"<li><strong>[{html.escape(flow.severity.value)}] {html.escape(flow.chain_id)}</strong>: "
            f"<code>{chain}</code> — {html.escape(flow.attack_narrative)}</li>"
        )
    flows_html = (
        f"<ul>{''.join(flow_items)}</ul>"
        if flow_items
        else "<p>No cross-tool toxic flows detected.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>mcp-ward Audit Report - {html.escape(report.target)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; background: #0b1120; color: #e2e8f0; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }}
    .grade {{ font-size: 2rem; font-weight: 700; padding: 0.4rem 1rem; border-radius: 0.5rem; background: {grade_color}; color: #fff; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 0.5rem; padding: 1rem; }}
    .card span {{ display: block; font-size: 0.85rem; color: #94a3b8; }}
    .card strong {{ font-size: 1.4rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: #111827; }}
    th, td {{ border: 1px solid #1f2937; padding: 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #1e293b; }}
    .snippet {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; word-break: break-word; }}
    .sev {{ padding: 0.15rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 700; }}
    .sev-critical {{ background: #991b1b; color: #fecaca; }}
    .sev-high {{ background: #9a3412; color: #fed7aa; }}
    .sev-medium {{ background: #854d0e; color: #fef08a; }}
    .sev-low, .sev-info {{ background: #1e3a8a; color: #bfdbfe; }}
    code {{ color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>mcp-ward Security Report</h1>
      <p>Target: <code>{html.escape(report.target)}</code></p>
    </div>
    <div class="grade">Grade {html.escape(report.security_grade)} ({report.risk_score}/100)</div>
  </div>
  <div class="cards">
    <div class="card"><span>Files Scanned</span><strong>{report.files_scanned}</strong></div>
    <div class="card"><span>Tools Discovered</span><strong>{len(report.tools_discovered)}</strong></div>
    <div class="card"><span>Findings</span><strong>{len(report.findings)}</strong></div>
    <div class="card"><span>Toxic Flows</span><strong>{len(report.toxic_flows)}</strong></div>
  </div>
  <h2>Toxic Capability Flows</h2>
  {flows_html}
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Issue</th><th>Recommendation</th></tr></thead>
    <tbody>{findings_body}</tbody>
  </table>
</body>
</html>
"""
