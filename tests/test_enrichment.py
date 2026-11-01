from datetime import datetime, timezone

from app.enrichment import Enricher, ThreatIntel
from app.schema import EventInfo, GeoInfo, NormalizedEvent, SourceInfo


def event(ip: str | None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 10, 26, tzinfo=timezone.utc),
        log_source="test",
        event=EventInfo(category="authentication", action="ssh_login"),
        source=SourceInfo(ip=ip),
        raw="",
    )


class FakeGeoIP:
    def __init__(self):
        self.calls = []

    def lookup(self, ip):
        self.calls.append(ip)
        return GeoInfo(country_iso="NL", country="Netherlands")


def test_intel_matches_ips_and_cidrs():
    intel = ThreatIntel({"a": ["8.8.8.8", "1.2.3.0/24"], "b": ["1.2.0.0/16"], "c": ["2001:db8::/32"]})
    assert intel.lookup("8.8.8.8") == ["a"]
    assert intel.lookup("1.2.3.4") == ["a", "b"]
    assert intel.lookup("1.2.9.9") == ["b"]
    assert intel.lookup("2001:db8::1") == ["c"]
    assert intel.lookup("9.9.9.9") == []
    assert intel.lookup("not-an-ip") == []


def test_intel_skips_invalid_entries():
    intel = ThreatIntel({"a": ["1.1.1.1", "garbage", "300.1.1.1"]})
    assert intel.sizes == {"a": 1}


def test_intel_loads_files_with_comments(tmp_path):
    (tmp_path / "drop.txt").write_text("; Spamhaus header\n5.6.7.0/24 ; SBL123\n\n")
    (tmp_path / "firehol.txt").write_text("# comment\n9.9.9.9  # inline\n")
    (tmp_path / "ignored.csv").write_text("1.1.1.1\n")
    intel = ThreatIntel.from_directories([tmp_path])
    assert intel.sizes == {"drop": 1, "firehol": 1}
    assert intel.lookup("5.6.7.8") == ["drop"]


def test_enricher_marks_external_ip_with_geo_and_intel():
    geo = FakeGeoIP()
    e = Enricher(geo, ThreatIntel({"bad": ["8.8.8.8"]})).enrich(event("8.8.8.8"))
    assert e.source.internal is False
    assert e.source.geo.country == "Netherlands"
    assert e.threat.listed and e.threat.feeds == ["bad"]


def test_enricher_skips_geo_for_internal_ips():
    geo = FakeGeoIP()
    e = Enricher(geo, ThreatIntel({"bad": ["10.0.0.0/8"]})).enrich(event("10.1.2.3"))
    assert e.source.internal is True
    assert e.source.geo is None
    assert geo.calls == []
    assert e.threat.feeds == ["bad"]  # intel still applies: lateral movement from a known-bad host


def test_enricher_ignores_events_without_ip():
    e = Enricher(FakeGeoIP(), ThreatIntel()).enrich(event(None))
    assert e.source.internal is None
    assert not e.threat.listed
