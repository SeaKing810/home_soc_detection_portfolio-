from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List

from .utils import Alert, ensure_dir


def render_markdown(alerts: List[Alert], input_name: str) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = []
    lines.append("# SOC Detection Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Input: {input_name}")
    lines.append("")

    if not alerts:
        lines.append("No alerts were generated.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Executive summary")
    lines.append("")
    lines.append(
        f"Detections generated {len(alerts)} alert entries. Review each alert and validate context before escalating."
    )
    lines.append("")

    # Group by host
    by_host = {}
    for a in alerts:
        by_host.setdefault(a.host, []).append(a)

    lines.append("## Alerts by host")
    lines.append("")
    for host, host_alerts in by_host.items():
        lines.append(f"### Host: {host}")
        lines.append("")
        for a in host_alerts:
            ts = a.timestamp.isoformat()
            mitre = ", ".join(a.mitre_techniques) if a.mitre_techniques else "none listed"
            user = a.user or "unknown"
            lines.append(f"#### {a.title}")
            lines.append("")
            lines.append(f"Time: {ts}")
            lines.append(f"Severity: {a.severity}")
            lines.append(f"User: {user}")
            lines.append(f"MITRE: {mitre}")
            lines.append("")
            lines.append(a.summary)
            lines.append("")
            lines.append("Evidence")
            lines.append("")
            for k, v in a.evidence.items():
                lines.append(f"- {k}: {v}")
            lines.append("")
        lines.append("")

    lines.append("## Analyst notes")
    lines.append("")
    lines.append(
        "These detections are intentionally conservative and meant to be tuned. For each alert, consider environment baselines, admin activity, and expected automation."
    )
    lines.append("")
    lines.append("## Recommended next steps")
    lines.append("")
    lines.append("1. Validate source and destination context for network alerts")
    lines.append("2. Check parent process lineage for suspicious PowerShell alerts")
    lines.append("3. If brute force is suspected, confirm account lockouts and review authentication logs")
    lines.append("4. Add allowlists for known administrative tools and scripts")
    lines.append("")

    return "\n".join(lines)


def write_report(alerts: List[Alert], out_dir: str | Path, input_name: str) -> Path:
    out_path = ensure_dir(out_dir)
    filename = f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    full = out_path / filename
    full.write_text(render_markdown(alerts, input_name), encoding="utf-8")
    return full
