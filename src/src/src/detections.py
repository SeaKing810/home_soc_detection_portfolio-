from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Deque, Dict, Iterable, List, Tuple

import yaml

from .normalizer import NormalizedEvent
from .utils import Alert


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    mitre_techniques: tuple[str, ...]
    kind: str
    params: Dict[str, Any]


def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)

    rules: List[Rule] = []
    for r in doc.get("rules", []):
        rules.append(
            Rule(
                rule_id=str(r["rule_id"]),
                title=str(r["title"]),
                severity=str(r.get("severity", "medium")),
                mitre_techniques=tuple(r.get("mitre_techniques", [])),
                kind=str(r["kind"]),
                params=dict(r.get("params", {})),
            )
        )
    return rules


def run_detections(events: Iterable[NormalizedEvent], rules: List[Rule]) -> List[Alert]:
    alerts: List[Alert] = []
    events_list = list(events)

    # Index for simple pattern rules
    for rule in rules:
        if rule.kind == "powershell_suspicious":
            alerts.extend(_detect_suspicious_powershell(events_list, rule))
        elif rule.kind == "failed_logon_burst":
            alerts.extend(_detect_failed_logon_burst(events_list, rule))
        elif rule.kind == "unexpected_admin_share_access_hint":
            alerts.extend(_detect_admin_share_hint(events_list, rule))

    # Sort alerts by time
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def _detect_suspicious_powershell(events: List[NormalizedEvent], rule: Rule) -> List[Alert]:
    needles = [s.lower() for s in rule.params.get("command_substrings", [])]
    out: List[Alert] = []

    for e in events:
        if e.event_type != "process_create":
            continue
        if not e.process_name:
            continue

        proc = e.process_name.lower()
        if "powershell" not in proc and "pwsh" not in proc:
            continue

        cmd = (e.process_command_line or "").lower()
        if not cmd:
            continue

        if any(n in cmd for n in needles):
            out.append(
                Alert(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    mitre_techniques=rule.mitre_techniques,
                    timestamp=e.timestamp,
                    host=e.host,
                    user=e.user,
                    summary="PowerShell process creation matched suspicious command line substrings.",
                    evidence={
                        "process_name": e.process_name,
                        "command_line": e.process_command_line,
                        "parent_process": e.parent_process_name,
                    },
                )
            )
    return out


def _detect_failed_logon_burst(events: List[NormalizedEvent], rule: Rule) -> List[Alert]:
    """
    Detect N failed logons from the same source IP within a sliding time window.
    """
    threshold = int(rule.params.get("threshold", 8))
    window_seconds = int(rule.params.get("window_seconds", 120))

    out: List[Alert] = []
    window = timedelta(seconds=window_seconds)

    # per host and src_ip queue of timestamps
    buckets: Dict[Tuple[str, str], Deque] = defaultdict(deque)

    for e in sorted(events, key=lambda x: x.timestamp):
        if e.event_type != "failed_logon":
            continue
        if not e.src_ip:
            continue

        key = (e.host, e.src_ip)
        q = buckets[key]
        q.append(e.timestamp)

        # slide window
        while q and (e.timestamp - q[0]) > window:
            q.popleft()

        if len(q) == threshold:
            out.append(
                Alert(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    mitre_techniques=rule.mitre_techniques,
                    timestamp=e.timestamp,
                    host=e.host,
                    user=e.user,
                    summary="Multiple failed logons detected from one source IP in a short time window.",
                    evidence={
                        "src_ip": e.src_ip,
                        "failed_count_in_window": len(q),
                        "window_seconds": window_seconds,
                    },
                )
            )

    return out


def _detect_admin_share_hint(events: List[NormalizedEvent], rule: Rule) -> List[Alert]:
    """
    Very light heuristic: if a process connects to port 445 and the process name is suspicious in context.
    This is not a definitive alert, but it shows detection reasoning and tuning.
    """
    suspicious_parents = [s.lower() for s in rule.params.get("parent_process_substrings", [])]
    out: List[Alert] = []

    for e in events:
        if e.event_type != "network_connect":
            continue
        if e.dst_port != 445:
            continue

        parent = (e.raw or {}).get("ParentImage", "") or (e.parent_process_name or "")
        parent_l = str(parent).lower()

        if suspicious_parents and not any(s in parent_l for s in suspicious_parents):
            continue

        out.append(
            Alert(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                mitre_techniques=rule.mitre_techniques,
                timestamp=e.timestamp,
                host=e.host,
                user=e.user,
                summary="SMB connection detected that may indicate lateral movement activity depending on context.",
                evidence={
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "dst_port": e.dst_port,
                    "process_name": e.process_name,
                    "command_line": e.process_command_line,
                    "parent_process": parent,
                },
            )
        )

    return out
