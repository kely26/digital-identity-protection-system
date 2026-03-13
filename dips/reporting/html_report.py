"""HTML report writer."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from dips.core.models import ScanReport
from dips.reporting.json_report import render_json_payload
from dips.utils.secure_io import atomic_write_text


def _severity_class(value: str) -> str:
    return f"sev-{escape(value)}"


def _render_plugin_report(report_extension: object) -> str:
    if not isinstance(report_extension, dict):
        return f"<p>{escape(json.dumps(report_extension, sort_keys=True))}</p>"
    rows: list[str] = []
    for key, value in report_extension.items():
        label = escape(key.replace("_", " ").title())
        if isinstance(value, list):
            rendered = ", ".join(escape(str(item)) for item in value)
        elif isinstance(value, dict):
            rendered = escape(json.dumps(value, sort_keys=True))
        else:
            rendered = escape(str(value))
        rows.append(f"<p><strong>{label}:</strong> {rendered}</p>")
    return "".join(rows)


def render_html_payload(payload: dict[str, Any]) -> str:
    ai_module = next(
        (module for module in payload["modules"] if module.get("module") == "ai_security_analysis"),
        None,
    )
    findings_rows: list[str] = []
    for module in payload["modules"]:
        for finding in module["findings"]:
            tags = ", ".join(finding.get("tags", []))
            findings_rows.append(
                "<tr>"
                f"<td>{escape(module['module'])}</td>"
                f"<td><span class='pill {_severity_class(finding['severity'])}'>{escape(finding['severity'])}</span></td>"
                f"<td>{escape(finding['title'])}</td>"
                f"<td>{escape(finding['location'])}</td>"
                f"<td>{escape(finding['summary'])}</td>"
                f"<td>{escape(json.dumps(finding.get('evidence', {}), sort_keys=True))}</td>"
                f"<td>{escape(tags)}</td>"
                "</tr>"
            )

    module_cards = "".join(
        "<div class='card'>"
        f"<h3>{escape(module['module'])}</h3>"
        f"<p>Status: {escape(module['status'])}</p>"
        f"<p>Findings: {len(module['findings'])}</p>"
        f"<p>Warnings: {len(module['warnings'])}</p>"
        f"<p>Risk Score: {int(payload['summary'].get('module_scores', {}).get(module['module'], 0))}</p>"
        "</div>"
        for module in payload["modules"]
    )

    recommendation_items = "".join(
        f"<li>{escape(item)}</li>" for item in payload["summary"]["top_recommendations"]
    ) or "<li>No urgent remediation items.</li>"
    contributing_items = "".join(
        f"<li>{escape(item)}</li>" for item in payload["summary"].get("contributing_findings", [])
    ) or "<li>No primary contributors were captured.</li>"
    ai_summary_block = ""
    if ai_module:
        metadata = ai_module.get("metadata", {})
        ai_actions = "".join(
            f"<li>{escape(str(item))}</li>"
            for item in metadata.get("recommended_actions", [])
            if str(item).strip()
        ) or "<li>No AI-specific actions were generated.</li>"
        ai_patterns = "".join(
            "<li>"
            f"<strong>{escape(str(item.get('title', '')))}</strong>: "
            f"{escape(str(item.get('summary', '')))}"
            "</li>"
            for item in metadata.get("suspicious_patterns", [])
            if isinstance(item, dict)
        ) or "<li>No cross-module suspicious patterns were detected.</li>"
        ai_summary_block = (
            "<h2>AI Security Analysis</h2>"
            "<div class='grid'>"
            "<div class='card'>"
            "<h3>Security Summary</h3>"
            f"<p>{escape(str(metadata.get('summary', 'No AI summary generated.')))}</p>"
            "</div>"
            "<div class='card'>"
            "<h3>Risk Explanation</h3>"
            f"<p>{escape(str(metadata.get('risk_explanation', 'No AI explanation generated.')))}</p>"
            "</div>"
            "<div class='card'>"
            "<h3>Recommended Actions</h3>"
            f"<ul>{ai_actions}</ul>"
            "</div>"
            "<div class='card'>"
            "<h3>Suspicious Patterns</h3>"
            f"<ul>{ai_patterns}</ul>"
            "</div>"
            "</div>"
        )
    timeline_rows = "".join(
        "<tr>"
        f"<td>{escape(str(event.get('timestamp', ''))[11:16] or '--:--')}</td>"
        f"<td><span class='pill {_severity_class(str(event.get('severity', 'info')))}'>{escape(str(event.get('severity', 'info')))}</span></td>"
        f"<td>{escape(str(event.get('title', '')))}</td>"
        f"<td>{escape(str(event.get('module', '')))}</td>"
        "</tr>"
        for event in payload.get("timeline", {}).get("events", [])[-20:]
    ) or "<tr><td colspan='4'>No security events were captured.</td></tr>"
    pattern_items = "".join(
        f"<li><strong>{escape(pattern.get('name', ''))}</strong>: {escape(pattern.get('summary', ''))}</li>"
        for pattern in payload.get("timeline", {}).get("patterns", [])
    ) or "<li>No correlated event patterns were detected.</li>"
    category_rows = "".join(
        "<tr>"
        f"<td>{escape(category.replace('_', ' ').title())}</td>"
        f"<td>{int(score)}</td>"
        "</tr>"
        for category, score in sorted(
            payload["summary"].get("category_scores", {}).items(),
            key=lambda item: (-int(item[1]), item[0]),
        )
    ) or "<tr><td colspan='2'>No category scores were produced.</td></tr>"
    plugin_extensions = payload.get("extensions", {}).get("plugins", {})
    plugin_extension_cards = "".join(
        "<div class='card'>"
        f"<h3>{escape(name)}</h3>"
        f"<p>{escape(str(details.get('description', '')))}</p>"
        f"<p><strong>Version:</strong> {escape(str(details.get('version', '')))}</p>"
        f"<p><strong>Modules:</strong> {escape(', '.join(details.get('modules', [])))}</p>"
        f"{_render_plugin_report(details.get('report', {})) if details.get('report') else ''}"
        "</div>"
        for name, details in sorted(plugin_extensions.items())
        if isinstance(details, dict)
    )

    finding_table = "".join(findings_rows) or (
        "<tr><td colspan='7'>No findings were generated for this scan.</td></tr>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DIPS Report {escape(payload['scan_id'])}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0b1020; color: #e5e7eb; margin: 0; padding: 24px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 16px 0 24px; }}
    .card {{ background: #131a2d; border: 1px solid #22304e; border-radius: 12px; padding: 16px; }}
    .pill {{ border-radius: 999px; padding: 4px 10px; font-size: 12px; font-weight: bold; }}
    .sev-info {{ background: #1f3b64; }}
    .sev-low {{ background: #14532d; }}
    .sev-medium {{ background: #854d0e; }}
    .sev-high {{ background: #9a3412; }}
    .sev-critical {{ background: #991b1b; }}
    table {{ width: 100%; border-collapse: collapse; background: #131a2d; border-radius: 12px; overflow: hidden; }}
    th, td {{ border-bottom: 1px solid #22304e; text-align: left; padding: 12px; vertical-align: top; }}
    th {{ background: #172036; }}
    ul {{ padding-left: 20px; }}
    .score {{ font-size: 42px; font-weight: 700; }}
    .muted {{ color: #9ca3af; }}
  </style>
</head>
<body>
  <h1>Digital Identity Protection System</h1>
  <p class="muted">Scan ID {escape(payload['scan_id'])} · Platform {escape(payload['platform_name'])} · User {escape(payload['username'])}</p>
  <div class="grid">
    <div class="card"><h3>Overall Score</h3><div class="score">{payload['summary']['overall_score']}</div><p>{escape(payload['summary']['overall_label'])}</p></div>
    <div class="card"><h3>Risk Model</h3><p>{escape(payload['summary'].get('risk_model', 'digital_identity_weighted_sum'))}</p><h3>Duration</h3><p>{int(payload['duration_ms'])} ms</p></div>
    <div class="card"><h3>Started</h3><p>{escape(payload['started_at'])}</p><h3>Finished</h3><p>{escape(payload['finished_at'])}</p></div>
    <div class="card"><h3>Target Paths</h3><ul>{''.join(f'<li>{escape(path)}</li>' for path in payload['target_paths'])}</ul></div>
  </div>
  <h2>Module Breakdown</h2>
  <div class="grid">{module_cards}</div>
  <h2>Risk Categories</h2>
  <table>
    <thead>
      <tr><th>Category</th><th>Score</th></tr>
    </thead>
    <tbody>{category_rows}</tbody>
  </table>
  <h2>Top Recommendations</h2>
  <div class="card"><ul>{recommendation_items}</ul></div>
  <h2>Top Risk Drivers</h2>
  <div class="card"><ul>{contributing_items}</ul></div>
  {ai_summary_block}
  {"<h2>Plugin Extensions</h2><div class='grid'>" + plugin_extension_cards + "</div>" if plugin_extension_cards else ""}
  <h2>Security Timeline</h2>
  <table>
    <thead>
      <tr><th>Time</th><th>Severity</th><th>Event</th><th>Module</th></tr>
    </thead>
    <tbody>{timeline_rows}</tbody>
  </table>
  <h2>Correlated Patterns</h2>
  <div class="card"><ul>{pattern_items}</ul></div>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Module</th><th>Severity</th><th>Title</th><th>Location</th><th>Summary</th><th>Evidence</th><th>Tags</th></tr>
    </thead>
    <tbody>{finding_table}</tbody>
  </table>
</body>
</html>"""


def render_html_report(report: ScanReport, *, redact: bool = True, payload: dict[str, Any] | None = None) -> str:
    report_payload = payload if payload is not None else render_json_payload(report, redact=redact)
    return render_html_payload(report_payload)


def write_html_report(
    report: ScanReport,
    output_path: Path,
    *,
    redact: bool = True,
    payload: dict[str, Any] | None = None,
) -> Path:
    atomic_write_text(output_path, render_html_report(report, redact=redact, payload=payload), private=True)
    return output_path
