from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from .detections import load_rules, run_detections
from .normalizer import normalize_sysmon_like
from .report import write_report
from .utils import read_jsonl


def cmd_run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    raw_events = list(read_jsonl(input_path))
    normalized = [normalize_sysmon_like(e) for e in raw_events]

    rules = load_rules(args.rules)
    alerts = run_detections(normalized, rules)

    report_path = write_report(alerts, args.out, input_name=str(input_path))
    print(f"Report written to: {report_path}")

    # Print a short console summary
    print(f"Events read: {len(raw_events)}")
    print(f"Alerts generated: {len(alerts)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="home_soc_detection_portfolio",
        description="Normalize Sysmon style events, run detections, and generate a SOC style report.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run pipeline and generate report.")
    run_p.add_argument("--input", required=True, help="Path to JSONL events file.")
    run_p.add_argument("--out", required=True, help="Output directory for reports.")
    run_p.add_argument("--rules", default="detections/rules.yaml", help="Path to detection rules YAML.")
    run_p.set_defaults(func=cmd_run)

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
