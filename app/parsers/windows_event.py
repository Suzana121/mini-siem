"""Parser for Windows Security events exported as XML, one <Event> per line.

Produce the input on Windows with
    wevtutil qe Security /f:xml /rd:false
or from an .evtx file with a converter such as `evtx_dump -o xml`, then collapse
each event onto one line. Binary .evtx files are converted by scripts/evtx_to_xml.py (used by ship_logs and detect).

Handled event ids (everything else returns None):
    4624/4625  logon success/failure   -> win_logon      (labels.logon_type)
    4688       process created         -> process_created (labels.command, labels.process)
    4720       user account created    -> user_created   (user.target, labels.sid)
    4732       member added to a local group -> user_added_to_group (labels.group, labels.sid)
    1102       audit log cleared       -> audit_log_cleared
`labels.sid` is the account's SID, which lets a rule tie an account's creation
to a later group change even though the two events name the account differently.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.schema import EventInfo, HostInfo, NormalizedEvent, Outcome, ProcessInfo, SourceInfo, UserInfo

LOG_SOURCE = "windows"

MAX_LABEL = 2048
_FRACTION = re.compile(r"(\.\d{6})\d+")
_IP = re.compile(r"^[0-9a-fA-F.:]+$")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(_FRACTION.sub(r"\1", value).replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _data(event: ET.Element) -> dict[str, str]:
    """Flatten EventData / UserData children into {name: text}."""
    out: dict[str, str] = {}
    for section in event:
        if _local(section.tag) == "System":
            continue
        for node in section.iter():
            text = (node.text or "").strip()
            if text:
                out[node.get("Name") or _local(node.tag)] = text
    return out


def _clean(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value


def parse_line(line: str, reference: datetime | None = None) -> NormalizedEvent | None:
    """Parse one XML event. Returns None for anything not listed in the module docstring."""
    line = line.strip()
    if not line.startswith("<Event") or "<!" in line:  # no DTDs/entities from untrusted input
        return None
    try:
        root = ET.fromstring(line)
        system = next(c for c in root if _local(c.tag) == "System")
        fields = {_local(c.tag): c for c in system}
        event_id = int(fields["EventID"].text)
        timestamp = _timestamp(fields["TimeCreated"].get("SystemTime"))
        computer = (fields["Computer"].text or "").strip() or None
    except (ET.ParseError, StopIteration, KeyError, TypeError, ValueError):
        return None

    d = _data(root)
    event = user = None
    source = SourceInfo()
    labels: dict[str, str] = {}
    process = ProcessInfo()

    if event_id in (4624, 4625):
        ok = event_id == 4624
        event = EventInfo(category="authentication", action="win_logon", outcome=Outcome.SUCCESS if ok else Outcome.FAILURE)
        user = UserInfo(name=_clean(d.get("TargetUserName")))
        ip = _clean(d.get("IpAddress"))
        source = SourceInfo(ip=ip if ip and _IP.match(ip) else None, port=int(d["IpPort"]) if d.get("IpPort", "").isdigit() else None)
        labels = {"logon_type": d.get("LogonType", ""), "target_domain": d.get("TargetDomainName", "")}
        if not ok and d.get("SubStatus"):
            labels["sub_status"] = d["SubStatus"]
    elif event_id == 4688:
        event = EventInfo(category="process", action="process_created", outcome=Outcome.SUCCESS)
        user = UserInfo(name=_clean(d.get("SubjectUserName")))
        exe = d.get("NewProcessName", "")
        process = ProcessInfo(name=exe.rsplit("\\", 1)[-1] or None)
        labels = {"process": exe[:MAX_LABEL], "command": d.get("CommandLine", exe)[:MAX_LABEL]}
    elif event_id == 4720:
        event = EventInfo(category="iam", action="user_created", outcome=Outcome.SUCCESS)
        user = UserInfo(name=_clean(d.get("SubjectUserName")), target=_clean(d.get("TargetUserName")))
        labels = {"sid": d.get("TargetSid", "")}
    elif event_id == 4732:
        event = EventInfo(category="iam", action="user_added_to_group", outcome=Outcome.SUCCESS)
        user = UserInfo(name=_clean(d.get("SubjectUserName")), target=_clean(d.get("MemberName")))
        labels = {"group": d.get("TargetUserName", ""), "sid": d.get("MemberSid", "")}
    elif event_id == 1102:
        event = EventInfo(category="iam", action="audit_log_cleared", outcome=Outcome.SUCCESS)
        user = UserInfo(name=_clean(d.get("SubjectUserName")))
    else:
        return None

    return NormalizedEvent(
        timestamp=timestamp,
        log_source=LOG_SOURCE,
        event=event,
        host=HostInfo(name=computer),
        process=process,
        user=user,
        source=source,
        labels={k: v for k, v in labels.items() if v},
        raw=line,
    )
