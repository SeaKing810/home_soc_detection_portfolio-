from src.detections import load_rules, run_detections
from src.normalizer import normalize_sysmon_like


def test_rules_load():
    rules = load_rules("detections/rules.yaml")
    assert len(rules) >= 3


def test_suspicious_powershell_detection():
    rules = load_rules("detections/rules.yaml")
    e = {
        "EventID": 1,
        "UtcTime": "2026-02-26T18:10:00Z",
        "Computer": "WIN10-LAB",
        "User": "WIN10-LAB\\sean",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoP -W Hidden -Enc AAA=",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    }
    alerts = run_detections([normalize_sysmon_like(e)], rules)
    assert any(a.rule_id == "SOC001" for a in alerts)


def test_failed_logon_burst_detection():
    rules = load_rules("detections/rules.yaml")
    base = "2026-02-26T18:11:"
    events = []
    for sec in ["10Z", "20Z", "30Z", "40Z", "50Z", "55Z"]:
        events.append(
            normalize_sysmon_like(
                {
                    "EventID": 4625,
                    "UtcTime": base + sec,
                    "Computer": "DC01",
                    "TargetUserName": "administrator",
                    "IpAddress": "203.0.113.50",
                    "DestinationPort": 3389,
                }
            )
        )

    alerts = run_detections(events, rules)
    assert any(a.rule_id == "SOC002" for a in alerts)
