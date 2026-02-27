from src.normalizer import normalize_sysmon_like


def test_normalize_process_create():
    e = {
        "EventID": 1,
        "UtcTime": "2026-02-26T18:10:00Z",
        "Computer": "WIN10-LAB",
        "User": "WIN10-LAB\\sean",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoP -Enc AAA=",
        "ParentImage": "C:\\Windows\\explorer.exe",
    }
    n = normalize_sysmon_like(e)
    assert n.event_type == "process_create"
    assert n.host == "WIN10-LAB"
    assert "powershell" in (n.process_name or "").lower()
    assert "-enc" in (n.process_command_line or "").lower()


def test_normalize_failed_logon():
    e = {
        "EventID": 4625,
        "UtcTime": "2026-02-26T18:11:10Z",
        "Computer": "DC01",
        "TargetUserName": "administrator",
        "IpAddress": "203.0.113.50",
        "DestinationPort": 3389,
    }
    n = normalize_sysmon_like(e)
    assert n.event_type == "failed_logon"
    assert n.host == "DC01"
    assert n.user == "administrator"
    assert n.src_ip == "203.0.113.50"
    assert n.dst_port == 3389
