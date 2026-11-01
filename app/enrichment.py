"""Event enrichment: GeoIP and threat-intel lookups for source.ip.

Enrichment runs before detection, so rules can match on enriched fields
(e.g. `threat.listed: true`), and alerts carry the context to the analyst.

Both lookups are optional. Without a GeoIP database or intel feeds the
pipeline still works; events just aren't enriched with that data.
"""

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

import maxminddb

from app.schema import GeoInfo, NormalizedEvent

log = logging.getLogger("mini-siem.enrichment")


class GeoIP:
    """Reads a MaxMind-format city database (GeoLite2-City or DB-IP City Lite)."""

    def __init__(self, path: Path):
        self._reader = maxminddb.open_database(str(path))
        self.lookup = lru_cache(maxsize=65_536)(self._lookup)

    def _lookup(self, ip: str) -> GeoInfo | None:
        record = self._reader.get(ip)
        if not isinstance(record, dict):
            return None
        country = record.get("country") or {}
        location = record.get("location") or {}
        return GeoInfo(
            country_iso=country.get("iso_code"),
            country=(country.get("names") or {}).get("en"),
            city=((record.get("city") or {}).get("names") or {}).get("en"),
            lat=location.get("latitude"),
            lon=location.get("longitude"),
        )

    def close(self) -> None:
        self._reader.close()


class ThreatIntel:
    """IP/CIDR blocklists, each identified by a feed name.

    Lookups check one hash table per prefix length present in the feeds, so
    cost is bounded by ~33 (IPv4) set lookups regardless of list size.
    """

    def __init__(self, feeds: dict[str, list[str]] | None = None):
        # (ip version, prefix length) -> {network bits: {feed names}}
        self._tables: dict[tuple[int, int], dict[int, set[str]]] = {}
        self.sizes: dict[str, int] = {}
        for name, entries in (feeds or {}).items():
            self.add_feed(name, entries)

    def add_feed(self, name: str, entries: list[str]) -> None:
        count = 0
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            shift = network.max_prefixlen - network.prefixlen
            table = self._tables.setdefault((network.version, network.prefixlen), {})
            table.setdefault(int(network.network_address) >> shift, set()).add(name)
            count += 1
        self.sizes[name] = self.sizes.get(name, 0) + count

    def lookup(self, ip: str) -> list[str]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        feeds: set[str] = set()
        for (version, prefixlen), table in self._tables.items():
            if version == address.version:
                feeds |= table.get(int(address) >> (address.max_prefixlen - prefixlen), set())
        return sorted(feeds)

    @classmethod
    def from_directories(cls, directories: list[Path]) -> "ThreatIntel":
        """Load every *.txt file as a feed named after the file.

        One IP or CIDR per line; anything after '#' or ';' is a comment, which
        covers the common formats (FireHOL, Spamhaus DROP, plain lists).
        """
        intel = cls()
        for directory in directories:
            for path in sorted(directory.glob("*.txt")):
                entries = []
                for line in path.read_text(errors="replace").splitlines():
                    token = line.split("#", 1)[0].split(";", 1)[0].strip()
                    if token:
                        entries.append(token.split()[0])
                intel.add_feed(path.stem, entries)
        return intel


class Enricher:
    def __init__(self, geoip: GeoIP | None = None, intel: ThreatIntel | None = None):
        self.geoip = geoip
        self.intel = intel

    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        ip = event.source.ip
        if not ip:
            return event
        try:
            event.source.internal = not ipaddress.ip_address(ip).is_global
        except ValueError:
            return event
        if self.geoip and not event.source.internal:
            event.source.geo = self.geoip.lookup(ip)
        if self.intel:
            feeds = self.intel.lookup(ip)
            event.threat.listed = bool(feeds)
            event.threat.feeds = feeds
        return event
