"""Every rule gets positive and negative cases, written as real auth.log lines.

Each case runs through the parser and the full rule set, so it also catches
rules that fire when they shouldn't.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.enrichment import Enricher, ThreatIntel
from app.parsers.auth_log import parse_line

RULES = load_rules(DEFAULT_RULES_DIR)
KNOWN_BAD_IP = "198.51.100.66"
ENRICHER = Enricher(intel=ThreatIntel({"test-feed": [KNOWN_BAD_IP]}))
BASE = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)
REF = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def line(seconds: float, process: str, message: str, host: str = "web01") -> str:
    return f"{BASE + timedelta(seconds=seconds):%b %d %H:%M:%S} {host} {process}: {message}"


def ssh_fail(seconds: float, user: str = "root", ip: str = "203.0.113.9") -> str:
    return line(seconds, "sshd[100]", f"Failed password for {user} from {ip} port 4242 ssh2")


def ssh_ok(seconds: float, user: str = "deploy", ip: str = "203.0.113.9") -> str:
    return line(seconds, "sshd[100]", f"Accepted password for {user} from {ip} port 4242 ssh2")


def sudo(seconds: float, command: str, user: str = "bob") -> str:
    return line(seconds, "sudo", f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")


def sudo_fail(seconds: float, command: str, user: str = "bob") -> str:
    return line(
        seconds,
        "sudo",
        f"  {user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
    )


def useradd(seconds: float, user: str) -> str:
    return line(seconds, "useradd[200]", f"new user: name={user}, UID=1500, GID=1500, home=/home/{user}, shell=/bin/bash")


def usermod(seconds: float, user: str, group: str) -> str:
    return line(seconds, "usermod[201]", f"add '{user}' to group '{group}'")


def fired(lines: list[str]) -> list[str]:
    engine = DetectionEngine(RULES)
    alerts = []
    for raw in lines:
        event = parse_line(raw, REF)
        assert event is not None, f"test line didn't parse: {raw}"
        alerts.extend(engine.process(ENRICHER.enrich(event)))
    return sorted(a.rule_id for a in alerts)


CASES = {
    # ssh-brute-force
    "5 failures in a minute": ([ssh_fail(i * 5) for i in range(5)], ["ssh-brute-force"]),
    "4 failures is below threshold": ([ssh_fail(i * 5) for i in range(4)], []),
    "5 failures spread over 2 minutes": ([ssh_fail(i * 30) for i in range(5)], []),
    "5 failures from 5 different IPs": ([ssh_fail(i, ip=f"198.51.100.{i}") for i in range(5)], []),
    "10 fast failures fire twice": ([ssh_fail(i) for i in range(10)], ["ssh-brute-force"] * 2),
    # ssh-password-spraying
    "5 users from one IP over 3 minutes": (
        [ssh_fail(i * 40, user=u) for i, u in enumerate(["root", "admin", "oracle", "pi", "ubuntu"])],
        ["ssh-password-spraying"],
    ),
    "same user 5 times slowly": ([ssh_fail(i * 40) for i in range(5)], []),
    # ssh-brute-force-success
    "failures then success": (
        [*[ssh_fail(i * 5) for i in range(5)], ssh_ok(30)],
        ["ssh-brute-force", "ssh-brute-force-success"],
    ),
    "success from a different IP": (
        [*[ssh_fail(i * 5) for i in range(5)], ssh_ok(30, ip="198.51.100.1")],
        ["ssh-brute-force"],
    ),
    "4 failures then success": ([*[ssh_fail(i * 5) for i in range(4)], ssh_ok(30)], []),
    "success after the window": (
        [*[ssh_fail(i * 5) for i in range(5)], ssh_ok(11 * 60)],
        ["ssh-brute-force"],
    ),
    # ssh-scanner
    "3 banner-less connections": (
        [line(i * 10, "sshd[1]", "Did not receive identification string from 192.0.2.5 port 1111") for i in range(3)],
        ["ssh-scanner"],
    ),
    "3 banner-less connections (OpenSSH 9 wording)": (
        [line(i * 10, "sshd[1]", "Connection closed by 192.0.2.5 port 1111") for i in range(3)],
        ["ssh-scanner"],
    ),
    "2 banner-less connections": (
        [line(i * 10, "sshd[1]", "Did not receive identification string from 192.0.2.5 port 1111") for i in range(2)],
        [],
    ),
    # ssh-root-login
    "root logs in over ssh": ([ssh_ok(0, user="root")], ["ssh-root-login"]),
    "normal user logs in": ([ssh_ok(0, user="alice")], []),
    # ssh-login-threat-intel
    "login from a listed IP": ([ssh_ok(0, ip=KNOWN_BAD_IP)], ["ssh-login-threat-intel"]),
    "failed login from a listed IP": ([ssh_fail(0, ip=KNOWN_BAD_IP)], []),
    # sudo-auth-failure
    "wrong sudo password": ([sudo_fail(0, "/usr/bin/apt update")], ["sudo-auth-failure"]),
    # sudo-credential-file-access
    "sudo cat /etc/shadow": ([sudo(0, "/bin/cat /etc/shadow")], ["sudo-credential-file-access"]),
    "failed sudo on /etc/sudoers": (
        [sudo_fail(0, "/usr/bin/vim /etc/sudoers")],
        ["sudo-auth-failure", "sudo-credential-file-access"],
    ),
    "harmless sudo command": ([sudo(0, "/usr/bin/apt update")], []),
    # sudo-root-shell
    "sudo bash": ([sudo(0, "/bin/bash")], ["sudo-root-shell"]),
    "sudo su -": ([sudo(0, "/usr/bin/su -")], ["sudo-root-shell"]),
    "sudo bash -c is not interactive": ([sudo(0, "/bin/bash -c 'systemctl restart nginx'")], []),
    # local-account-created / privileged-group-change / backdoor-account
    "account created": ([useradd(0, "svc")], ["local-account-created"]),
    "added to sudo group": ([usermod(0, "alice", "sudo")], ["privileged-group-change"]),
    "added to harmless group": ([usermod(0, "alice", "audio")], []),
    "new account made admin": (
        [useradd(0, "backup2"), usermod(60, "backup2", "sudo")],
        ["backdoor-account", "local-account-created", "privileged-group-change"],
    ),
    "different account made admin": (
        [useradd(0, "backup2"), usermod(60, "alice", "sudo")],
        ["local-account-created", "privileged-group-change"],
    ),
    "made admin long after creation": (
        [useradd(0, "backup2"), usermod(11 * 60, "backup2", "wheel")],
        ["local-account-created", "privileged-group-change"],
    ),
    "same username on another host": (
        [useradd(0, "backup2"), line(60, "usermod[1]", "add 'backup2' to group 'sudo'", host="db01")],
        ["local-account-created", "privileged-group-change"],
    ),
}


@pytest.mark.parametrize("lines,expected", CASES.values(), ids=CASES.keys())
def test_rule_case(lines, expected):
    assert fired(lines) == sorted(expected)


def test_every_rule_has_a_positive_case():
    covered = {rule_id for _, expected in CASES.values() for rule_id in expected}
    assert covered == {rule.id for rule in RULES}


def test_sample_attack_scenario():
    assert fired(SAMPLE.read_text().splitlines()[:-1]) == sorted(
        [
            "ssh-brute-force",
            "ssh-brute-force-success",
            "sudo-auth-failure",
            "sudo-credential-file-access",
            "local-account-created",
            "privileged-group-change",
            "backdoor-account",
        ]
    )
