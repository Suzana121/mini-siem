"""Parser for nginx access logs in the default "combined" format.

    203.0.113.9 - alice [26/Oct/2026:10:15:32 +0000] "GET /index.php?id=1 HTTP/1.1" 200 612 "https://example.com/" "curl/8.4.0"

Apache's combined format is identical, so it parses too. Every request becomes
an `http_request` event; details live in labels so rules can match on them:
`http_method`, `http_path` (percent-decoded, so `%2e%2e%2f` is seen as `../`),
`http_status`, `http_user_agent`. The outcome is `success` below 400 and
`failure` otherwise. The log carries no hostname, so `host.name` stays unset.
"""

import re
from datetime import datetime, timezone
from urllib.parse import unquote

from app.schema import EventInfo, NormalizedEvent, Outcome, ProcessInfo, SourceInfo, UserInfo

LOG_SOURCE = "nginx"

_LINE = re.compile(
    r"^(?P<ip>[0-9a-fA-F.:]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S*)(?: (?P<proto>HTTP/[\d.]+))?" '
    r"(?P<status>\d{3}) (?:\d+|-)"
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)

MAX_LABEL = 1024  # attackers can send very long URLs; keep stored events bounded


def _timestamp(value: str) -> datetime:
    parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    return parsed.astimezone(timezone.utc)


def parse_line(line: str, reference: datetime | None = None) -> NormalizedEvent | None:
    """Parse one access-log line. Returns None for lines we don't recognize.

    `reference` is accepted for parity with other parsers; timestamps here are complete.
    """
    line = line.rstrip("\r\n")
    m = _LINE.match(line)
    if m is None:
        return None
    try:
        timestamp = _timestamp(m["ts"])
    except ValueError:
        return None

    status = int(m["status"])
    labels = {
        "http_method": m["method"],
        "http_path": unquote(m["path"])[:MAX_LABEL],
        "http_status": str(status),
    }
    if m["agent"] and m["agent"] != "-":
        labels["http_user_agent"] = m["agent"][:MAX_LABEL]
    if m["referrer"] and m["referrer"] != "-":
        labels["http_referrer"] = m["referrer"][:MAX_LABEL]

    return NormalizedEvent(
        timestamp=timestamp,
        log_source=LOG_SOURCE,
        event=EventInfo(
            category="web",
            action="http_request",
            outcome=Outcome.SUCCESS if status < 400 else Outcome.FAILURE,
        ),
        process=ProcessInfo(name="nginx"),
        user=UserInfo(name=None if m["user"] == "-" else m["user"]),
        source=SourceInfo(ip=m["ip"]),
        labels=labels,
        raw=line,
    )
