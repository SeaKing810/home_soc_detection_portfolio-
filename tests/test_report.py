from src.report import render_markdown
from src.utils import Alert
from datetime import datetime, timezone


def test_report_renders_no_alerts():
    md = render_markdown([], "input.jsonl")
    assert "No alerts were generated" in md


def test_report_renders_alerts():
    a = Alert(
        rule_id="SOC001",
        title="Example alert",
        severity="high",
        mitre_techniques=("T1059.001",),
        timestamp=datetime(2026, 2, 26, 18, 10, tzinfo=timezone.utc),
        host="WIN10-LAB",
        user="WIN10-LAB\\sean",
        summary="Example summary",
        evidence={"k": "v"},
    )
    md = render_markdown([a], "input.jsonl")
    assert "Example alert" in md
    assert "WIN10-LAB" in md
    assert "T1059.001" in md
