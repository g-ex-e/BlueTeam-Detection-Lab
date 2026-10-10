from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .models import Finding


SEVERITY_COLORS = {
    "critical": "#991b1b",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#475569",
}


def write_json(findings: list[Finding], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2), encoding="utf-8")


def write_html(findings: list[Finding], event_count: int, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter(finding.severity for finding in findings)
    technique_counts = Counter(finding.technique for finding in findings if finding.technique)

    rows = []
    for finding in findings:
        evidence = html.escape(json.dumps(finding.evidence, ensure_ascii=False))
        badge = SEVERITY_COLORS.get(finding.severity, "#475569")
        rows.append(
            f"<tr><td>{html.escape(finding.timestamp.isoformat())}</td>"
            f"<td><span class='badge' style='background:{badge}'>{html.escape(finding.severity.upper())}</span></td>"
            f"<td><strong>{html.escape(finding.title)}</strong><br><small>{html.escape(finding.rule_id)}</small></td>"
            f"<td>{html.escape(finding.host)}</td><td>{html.escape(finding.user)}</td>"
            f"<td>{html.escape(finding.src_ip)}</td><td>{html.escape(finding.technique)}</td>"
            f"<td><code>{evidence}</code></td></tr>"
        )

    techniques = "".join(
        f"<li><strong>{html.escape(technique)}</strong><span>{count}</span></li>"
        for technique, count in technique_counts.most_common()
    ) or "<li><span>No ATT&CK technique detected</span></li>"

    cards = "".join(
        f"<div class='metric'><span>{severity.title()}</span><strong>{counts.get(severity, 0)}</strong></div>"
        for severity in ["critical", "high", "medium", "low"]
    )

    document = f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>BlueHunt Security Report</title>
<style>
:root{{--bg:#08111f;--panel:#101b2e;--muted:#8fa2bf;--text:#e8eef8;--line:#24324a;--cyan:#22d3ee}}
*{{box-sizing:border-box}}body{{margin:0;font:14px Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}}
main{{max-width:1400px;margin:auto;padding:32px}}h1{{margin:0;font-size:32px}}p{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}}.metric,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px}}
.metric{{padding:18px}}.metric span{{display:block;color:var(--muted)}}.metric strong{{display:block;font-size:30px;margin-top:8px}}
.layout{{display:grid;grid-template-columns:1fr 320px;gap:18px}}.panel{{padding:20px;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:1000px}}th,td{{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--muted);font-size:12px;text-transform:uppercase}}
.badge{{display:inline-block;color:white;font-weight:700;padding:4px 8px;border-radius:999px;font-size:11px}}code{{color:#bae6fd;white-space:normal}}ul{{list-style:none;padding:0}}li{{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--line)}}
.kicker{{color:var(--cyan);text-transform:uppercase;letter-spacing:.12em;font-weight:700;font-size:12px}}@media(max-width:900px){{.grid{{grid-template-columns:repeat(2,1fr)}}.layout{{grid-template-columns:1fr}}}}
</style>
</head>
<body><main>
<div class='kicker'>BlueTeam Detection Lab</div><h1>Security Detection Report</h1>
<p>{event_count} events analyzed · {len(findings)} findings generated</p>
<div class='grid'>{cards}</div>
<div class='layout'><section class='panel'><h2>Detection timeline</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Host</th><th>User</th><th>Source IP</th><th>MITRE</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<aside class='panel'><h2>MITRE ATT&CK</h2><ul>{techniques}</ul></aside></div>
</main></body></html>"""
    destination.write_text(document, encoding="utf-8")
