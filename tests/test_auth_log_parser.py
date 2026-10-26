from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.parsers.auth_log import parse_line
from app.schema import Outcome

REF = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


def parse(line: str):
    event = parse_line(line, REF)
    assert event is not None, f"failed to parse: {line}"
    return event


def test_failed_password_invalid_user():
    e = parse(
        "Oct 26 10:15:34 web01 sshd[2140]: Failed password for invalid user admin "
        "from 203.0.113.45 port 51110 ssh2"
    )
    assert e.event.action == "ssh_login"
    assert e.event.outcome == Outcome.FAILURE
    assert e.user.name == "admin"
    assert e.source.ip == "203.0.113.45"
    assert e.source.port == 51110
    assert e.labels == {"auth_method": "password", "invalid_user": "true"}
    assert e.host.name == "web01"
    assert e.process.name == "sshd" and e.process.pid == 2140
    assert e.timestamp == datetime(2026, 10, 26, 10, 15, 34, tzinfo=timezone.utc)


def test_failed_password_valid_user():
    e = parse("Oct 26 10:15:37 web01 sshd[2143]: Failed password for root from 203.0.113.45 port 51124 ssh2")
    assert e.user.name == "root"
    assert e.labels["invalid_user"] == "false"


def test_accepted_publickey_iso_timestamp():
    e = parse(
        "2026-10-26T10:20:00.512345+00:00 web01 sshd[2201]: Accepted publickey for alice "
        "from 198.51.100.7 port 60222 ssh2: ED25519 SHA256:abc123"
    )
    assert e.event.outcome == Outcome.SUCCESS
    assert e.user.name == "alice"
    assert e.labels["auth_method"] == "publickey"
    assert e.timestamp == datetime(2026, 10, 26, 10, 20, 0, 512345, tzinfo=timezone.utc)


def test_ipv6_source():
    e = parse("Oct 26 10:15:37 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2")
    assert e.source.ip == "2001:db8::1"


def test_invalid_user():
    e = parse("Oct 26 10:15:32 web01 sshd[2140]: Invalid user admin from 203.0.113.45 port 51110")
    assert e.event.action == "ssh_invalid_user"
    assert e.user.name == "admin"


def test_preauth_disconnect():
    e = parse(
        "Oct 26 10:15:35 web01 sshd[2140]: Connection closed by invalid user admin "
        "203.0.113.45 port 51110 [preauth]"
    )
    assert e.event.action == "ssh_disconnect"
    assert e.user.name == "admin"
    assert e.labels["preauth"] == "true"


def test_no_identification_string():
    e = parse("Oct 26 10:15:01 web01 sshd[2101]: Did not receive identification string from 203.0.113.45 port 51022")
    assert e.event.action == "ssh_no_identification"
    assert e.source.ip == "203.0.113.45"


def test_sudo_command():
    e = parse(
        "Oct 26 10:16:05 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
        "USER=root ; COMMAND=/usr/sbin/useradd -m backup2"
    )
    assert e.event.action == "sudo_command"
    assert e.event.outcome == Outcome.SUCCESS
    assert e.user.name == "deploy" and e.user.target == "root"
    assert e.labels["command"] == "/usr/sbin/useradd -m backup2"
    assert e.process.pid is None


def test_sudo_incorrect_password():
    e = parse(
        "Oct 26 10:17:30 web01 sudo:   intern : 3 incorrect password attempts ; TTY=pts/1 ; "
        "PWD=/home/intern ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    assert e.event.outcome == Outcome.FAILURE
    assert e.labels["failed_attempts"] == "3"
    assert e.labels["command"] == "/bin/cat /etc/shadow"


def test_session_opened():
    e = parse(
        "Oct 26 10:16:05 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) "
        "by deploy(uid=1001)"
    )
    assert e.event.action == "session_opened"
    assert e.user.name == "root"
    assert e.labels == {"service": "sudo", "opened_by": "deploy"}


def test_user_created_and_added_to_group():
    created = parse(
        "Oct 26 10:16:05 web01 useradd[2160]: new user: name=backup2, UID=1002, GID=1002, "
        "home=/home/backup2, shell=/bin/bash, from=/dev/pts/0"
    )
    assert created.event.action == "user_created"
    assert created.user.target == "backup2"

    grouped = parse("Oct 26 10:16:12 web01 usermod[2165]: add 'backup2' to group 'sudo'")
    assert grouped.event.action == "user_added_to_group"
    assert grouped.labels["group"] == "sudo"


def test_year_rollover():
    # A "Dec 31" line read on Jan 1 belongs to the previous year.
    e = parse_line(
        "Dec 31 23:59:59 web01 sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
        datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc),
    )
    assert e is not None and e.timestamp.year == 2026


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a syslog line",
        "Oct 26 10:21:00 web01 systemd[1]: Started Session 12 of user alice.",
        "Oct 26 10:21:00 web01 sshd[1]: Server listening on 0.0.0.0 port 22.",
    ],
)
def test_unrecognized_lines_return_none(line):
    assert parse_line(line, REF) is None


def test_sample_file():
    lines = SAMPLE.read_text().splitlines()
    events = [e for line in lines if (e := parse_line(line, REF))]
    assert len(lines) == 17
    assert len(events) == 16  # only the systemd line is skipped
