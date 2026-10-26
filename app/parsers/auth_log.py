"""Parser for Linux /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL).

Supports both syslog header styles:
  BSD (RFC 3164):  "Oct 26 10:15:32 web01 sshd[1234]: <message>"
  ISO (rsyslog):   "2026-10-26T10:15:32.123456+00:00 web01 sshd[1234]: <message>"

BSD timestamps carry no year or timezone, so the caller supplies a reference
time (defaults to now, UTC). A date that lands more than a day in the future
is assumed to be from last year, which handles logs read just after New Year.
"""

import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from app.schema import (
    EventInfo,
    HostInfo,
    NormalizedEvent,
    Outcome,
    ProcessInfo,
    SourceInfo,
    UserInfo,
)

LOG_SOURCE = "auth.log"

_BSD_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
_ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) "
    r"(?P<host>\S+) (?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

# A message rule builds the event-specific fields from a regex match.
Builder = Callable[[re.Match[str]], dict]
_RULES: dict[str, list[tuple[re.Pattern[str], Builder]]] = {}


def _rule(process: str, pattern: str) -> Callable[[Builder], Builder]:
    def register(builder: Builder) -> Builder:
        _RULES.setdefault(process, []).append((re.compile(pattern), builder))
        return builder

    return register


def _port(value: str | None) -> int | None:
    return int(value) if value else None


# --- sshd -------------------------------------------------------------------


@_rule(
    "sshd",
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)",
)
def _ssh_failed(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="authentication", action="ssh_login", outcome=Outcome.FAILURE),
        "user": UserInfo(name=m["user"] or None),
        "source": SourceInfo(ip=m["ip"], port=_port(m["port"])),
        "labels": {"auth_method": m["method"], "invalid_user": str(bool(m["invalid"])).lower()},
    }


@_rule(
    "sshd",
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
)
def _ssh_accepted(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="authentication", action="ssh_login", outcome=Outcome.SUCCESS),
        "user": UserInfo(name=m["user"]),
        "source": SourceInfo(ip=m["ip"], port=_port(m["port"])),
        "labels": {"auth_method": m["method"]},
    }


@_rule("sshd", r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
def _ssh_invalid_user(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(
            category="authentication", action="ssh_invalid_user", outcome=Outcome.FAILURE
        ),
        "user": UserInfo(name=m["user"] or None),
        "source": SourceInfo(ip=m["ip"], port=_port(m["port"])),
    }


@_rule(
    "sshd",
    r"^(?:Connection closed|Disconnected from) (?:by )?"
    r"(?:(?:authenticating|invalid) user (?P<user>\S+) )?(?:user (?P<user2>\S+) )?"
    r"(?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)",
)
def _ssh_disconnect(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="network", action="ssh_disconnect"),
        "user": UserInfo(name=m["user"] or m["user2"]),
        "source": SourceInfo(ip=m["ip"], port=_port(m["port"])),
        "labels": {"preauth": str(m.string.endswith("[preauth]")).lower()},
    }


@_rule("sshd", r"^Did not receive identification string from (?P<ip>\S+)(?: port (?P<port>\d+))?")
def _ssh_no_ident(m: re.Match[str]) -> dict:
    # Typical of port scanners that open the socket and hang up.
    return {
        "event": EventInfo(category="network", action="ssh_no_identification"),
        "source": SourceInfo(ip=m["ip"], port=_port(m["port"])),
    }


# --- sudo -------------------------------------------------------------------


@_rule(
    "sudo",
    r"^\s*(?P<user>\S+) : (?P<attempts>\d+) incorrect password attempts? ; "
    r".*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$",
)
def _sudo_failed(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="process", action="sudo_command", outcome=Outcome.FAILURE),
        "user": UserInfo(name=m["user"], target=m["target"]),
        "labels": {"command": m["cmd"], "failed_attempts": m["attempts"]},
    }


@_rule(
    "sudo",
    r"^\s*(?P<user>\S+) : (?:[^;]*?TTY=[^;]*; )?PWD=[^;]*; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$",
)
def _sudo_command(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="process", action="sudo_command", outcome=Outcome.SUCCESS),
        "user": UserInfo(name=m["user"], target=m["target"]),
        "labels": {"command": m["cmd"]},
    }


# --- sessions (any PAM service) --------------------------------------------


_SESSION_PATTERN = (
    r"^pam_unix\((?P<service>[\w-]+):session\): session (?P<state>opened|closed) "
    r"for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?"
)


def _session(m: re.Match[str]) -> dict:
    labels = {"service": m["service"]}
    if m["by"]:
        labels["opened_by"] = m["by"]
    return {
        "event": EventInfo(category="session", action=f"session_{m['state']}", outcome=Outcome.SUCCESS),
        "user": UserInfo(name=m["user"]),
        "labels": labels,
    }


for _proc in ("sshd", "sudo", "su", "login", "systemd-logind", "cron", "CRON"):
    _rule(_proc, _SESSION_PATTERN)(_session)


# --- account management -----------------------------------------------------


@_rule("useradd", r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
def _user_created(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="iam", action="user_created", outcome=Outcome.SUCCESS),
        "user": UserInfo(target=m["user"]),
        "labels": {"uid": m["uid"]},
    }


@_rule("usermod", r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
def _user_group_added(m: re.Match[str]) -> dict:
    return {
        "event": EventInfo(category="iam", action="user_added_to_group", outcome=Outcome.SUCCESS),
        "user": UserInfo(target=m["user"]),
        "labels": {"group": m["group"]},
    }


# --- public API -------------------------------------------------------------


def _parse_timestamp(ts: str, iso: bool, reference: datetime) -> datetime:
    if iso:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    parsed = datetime.strptime(f"{reference.year} {ts}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=timezone.utc
    )
    if parsed - reference > timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed


def parse_line(line: str, reference: datetime | None = None) -> NormalizedEvent | None:
    """Parse one auth.log line. Returns None for lines we don't recognize."""
    line = line.rstrip("\r\n")
    header = _ISO_HEADER.match(line)
    iso = header is not None
    if header is None:
        header = _BSD_HEADER.match(line)
    if header is None:
        return None

    process = header["proc"].rsplit("/", 1)[-1]
    for pattern, builder in _RULES.get(process, []):
        match = pattern.search(header["msg"])
        if match:
            fields = builder(match)
            break
    else:
        return None

    reference = reference or datetime.now(timezone.utc)
    return NormalizedEvent(
        timestamp=_parse_timestamp(header["ts"], iso, reference),
        log_source=LOG_SOURCE,
        host=HostInfo(name=header["host"]),
        process=ProcessInfo(name=process, pid=_port(header["pid"])),
        raw=line,
        **fields,
    )
