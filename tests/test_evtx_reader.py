"""Binary .evtx support: XML collapsing, the python-evtx wrapper (faked), and script wiring."""

import sys
import types

import pytest

from app.parsers.windows_event import parse_line
from scripts import evtx_to_xml
from scripts.evtx_to_xml import EvtxUnavailable, collapse_xml, is_evtx, iter_event_xml

PRETTY = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	<System>
		<EventID Qualifiers="">4625</EventID>
		<TimeCreated SystemTime="2026-10-26 10:00:01.123456"></TimeCreated>
		<Computer>WS01</Computer>
	</System>
	<EventData>
		<Data Name="TargetUserName">admin</Data>
		<Data Name="LogonType">3</Data>
		<Data Name="IpAddress">203.0.113.50</Data>
		<Data Name="CommandLine">cmd /c
whoami</Data>
	</EventData>
</Event>
"""


class FakeRecord:
    def __init__(self, xml, fail=False):
        self._xml, self._fail = xml, fail

    def xml(self):
        if self._fail:
            raise ValueError("bad record")
        return self._xml


def install_fake_evtx(monkeypatch, records):
    class FakeEvtx:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def records(self):
            return iter(records)

    pkg = types.ModuleType("Evtx")
    mod = types.ModuleType("Evtx.Evtx")
    mod.Evtx = FakeEvtx
    pkg.Evtx = mod
    monkeypatch.setitem(sys.modules, "Evtx", pkg)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", mod)


def test_collapse_is_single_line_and_parses():
    line = collapse_xml(PRETTY)
    assert "\n" not in line and "\t" not in line
    assert line.startswith("<Event") and line.endswith("</Event>")
    assert "cmd /c whoami" in line  # newline inside text becomes a space
    event = parse_line(line)
    assert event is not None
    assert event.event.action == "win_logon"


def test_is_evtx():
    assert is_evtx("Security.EVTX") and is_evtx("a/b.evtx")
    assert not is_evtx("samples/windows_security.xml")


def test_iter_event_xml_skips_bad_records(monkeypatch, capsys):
    install_fake_evtx(monkeypatch, [FakeRecord(PRETTY), FakeRecord("", fail=True), FakeRecord(PRETTY)])
    lines = list(iter_event_xml("x.evtx"))
    assert len(lines) == 2 and all("\n" not in x for x in lines)
    assert "skipping unreadable record" in capsys.readouterr().err


def test_missing_dependency_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "Evtx", None)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", None)
    with pytest.raises(EvtxUnavailable, match="python-evtx"):
        list(iter_event_xml("x.evtx"))


def test_ship_reads_evtx_only_for_windows(monkeypatch, tmp_path):
    from scripts import ship_logs

    install_fake_evtx(monkeypatch, [FakeRecord(PRETTY)])
    path = tmp_path / "Security.evtx"
    path.write_bytes(b"ElfFile\x00")
    assert len(ship_logs.read_lines(str(path), "windows")) == 1
    assert ship_logs.read_lines(str(path), "auth.log") != []  # treated as text, not converted
