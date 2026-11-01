"""Normalized event storage and the aggregate views built on alerts.

Events are kept for a retention period so analysts can pivot from an alert to
the surrounding log activity. Two implementations share the same semantics:
PostgresEventStore for real deployments, MemoryEventStore (bounded) for tests
and running without a database.
"""

import asyncio
import hashlib
import ipaddress
import logging
import re
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

import asyncpg

from app.detection.rules import get_field
from app.schema import NormalizedEvent
from app.store import SEVERITIES, STATUSES, StoredAlert  # noqa: F401  (re-exported)

log = logging.getLogger(__name__)

DEFAULT_MEMORY_LIMIT = 50_000
MAX_LIMIT = 1000
ALERT_EVENT_MARGIN = timedelta(minutes=5)
PRUNE_INTERVAL = 3600.0

# MITRE ATT&CK enterprise tactic order (kill-chain order).
TACTIC_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_RANK = {name.lower(): i for i, name in enumerate(TACTIC_ORDER)}

_WINDOW = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_window(value: str) -> timedelta:
    """Parse '90s', '15m', '2h' or '1d'. Raises ValueError otherwise."""
    match = _WINDOW.match(value.strip().lower())
    if not match:
        raise ValueError(f"invalid window {value!r}; use e.g. 30s, 15m, 2h, 1d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class EventStore(Protocol):
    async def add(self, events: list[NormalizedEvent]) -> None: ...

    async def query(
        self,
        *,
        source_ip: str | None = None,
        user: str | None = None,
        host: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedEvent]:
        """Matching events, newest first."""
        ...

    async def prune(self, older_than: datetime) -> int:
        """Delete events with timestamp before `older_than`. Returns how many."""
        ...

    async def close(self) -> None: ...


def _same_ip(a: str | None, b: str) -> bool:
    if a is None:
        return False
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def fingerprint(event: NormalizedEvent) -> str:
    """Identity of a log line, so re-shipping the same line doesn't store it twice.

    Two genuinely distinct lines with the same host, second and text collapse
    into one; real auth.log lines carry pids and ports, so this is rare.
    """
    payload = "\x1f".join(
        (event.log_source, event.host.name or "", _utc(event.timestamp).isoformat(), event.raw)
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


class MemoryEventStore:
    def __init__(self, max_events: int = DEFAULT_MEMORY_LIMIT):
        self._events: deque[NormalizedEvent] = deque(maxlen=max_events)
        self._seen: set[str] = set()

    async def add(self, events: list[NormalizedEvent]) -> None:
        for event in events:
            key = fingerprint(event)
            if key in self._seen:
                continue
            if self._events.maxlen is not None and len(self._events) == self._events.maxlen:
                self._seen.discard(fingerprint(self._events[0]))
            self._events.append(event)
            self._seen.add(key)

    async def query(
        self, *, source_ip=None, user=None, host=None, since=None, until=None, limit=100, offset=0
    ) -> list[NormalizedEvent]:
        since, until = _utc(since), _utc(until)
        matching = [
            e
            for e in self._events
            if (source_ip is None or _same_ip(e.source.ip, source_ip))
            and (user is None or e.user.name == user)
            and (host is None or e.host.name == host)
            and (since is None or _utc(e.timestamp) >= since)
            and (until is None or _utc(e.timestamp) <= until)
        ]
        matching.sort(key=lambda e: _utc(e.timestamp), reverse=True)  # stable: later arrivals first among ties
        return matching[offset : offset + limit]

    async def prune(self, older_than: datetime) -> int:
        older_than = _utc(older_than)
        kept = [e for e in self._events if _utc(e.timestamp) >= older_than]
        removed = len(self._events) - len(kept)
        self._events = deque(kept, maxlen=self._events.maxlen)
        self._seen = {fingerprint(e) for e in kept}
        return removed

    async def close(self) -> None:
        pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    host        TEXT,
    source_ip   INET,
    user_name   TEXT,
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    body        JSONB NOT NULL  -- the full NormalizedEvent document
);
-- Added after the first release; rows from before it have no fingerprint (NULLs never collide).
ALTER TABLE events ADD COLUMN IF NOT EXISTS fingerprint TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS events_fingerprint ON events (fingerprint);
CREATE INDEX IF NOT EXISTS events_source_ip_ts ON events (source_ip, ts);
CREATE INDEX IF NOT EXISTS events_host_ts ON events (host, ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
"""


def _ip(value: str | None):
    try:
        return ipaddress.ip_address(value) if value else None
    except ValueError:
        return None


class PostgresEventStore:
    def __init__(self, pool: asyncpg.Pool, retention: timedelta | None = None):
        self._pool = pool
        self.retention = retention

    @classmethod
    async def connect(cls, url: str, retention: timedelta | None = None) -> "PostgresEventStore":
        pool = await asyncpg.create_pool(url, min_size=1, max_size=5)
        async with pool.acquire() as conn:
            await conn.execute(SCHEMA)
        return cls(pool, retention)

    async def add(self, events: list[NormalizedEvent]) -> None:
        if not events:
            return
        rows = [
            (
                e.timestamp,
                e.host.name,
                _ip(e.source.ip),
                e.user.name,
                e.event.action,
                e.event.outcome.value,
                e.model_dump_json(),
                fingerprint(e),
            )
            for e in events
        ]
        await self._pool.executemany(
            "INSERT INTO events (ts, host, source_ip, user_name, action, outcome, body, fingerprint) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8) ON CONFLICT (fingerprint) DO NOTHING",
            rows,
        )

    async def query(
        self, *, source_ip=None, user=None, host=None, since=None, until=None, limit=100, offset=0
    ) -> list[NormalizedEvent]:
        clauses, params = [], []

        def add(sql: str, value: Any) -> None:
            params.append(value)
            clauses.append(sql.format(n=len(params)))

        if source_ip is not None:
            ip = _ip(source_ip)
            if ip is None:
                return []
            add("source_ip = ${n}", ip)
        if user is not None:
            add("user_name = ${n}", user)
        if host is not None:
            add("host = ${n}", host)
        if since is not None:
            add("ts >= ${n}", _utc(since))
        if until is not None:
            add("ts <= ${n}", _utc(until))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params += [limit, offset]
        rows = await self._pool.fetch(
            f"SELECT body FROM events {where} ORDER BY ts DESC, id DESC "
            f"LIMIT ${len(params) - 1} OFFSET ${len(params)}",
            *params,
        )
        return [NormalizedEvent.model_validate_json(row["body"]) for row in rows]

    async def prune(self, older_than: datetime) -> int:
        result = await self._pool.execute("DELETE FROM events WHERE ts < $1", _utc(older_than))
        return int(result.rsplit(" ", 1)[-1])

    async def close(self) -> None:
        await self._pool.close()


async def retention_loop(store: EventStore, retention: timedelta, interval: float = PRUNE_INTERVAL) -> None:
    """Prune events older than `retention` every `interval` seconds, until cancelled."""
    while True:
        try:
            removed = await store.prune(datetime.now(timezone.utc) - retention)
            if removed:
                log.info("event retention: pruned %d events", removed)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("event retention prune failed")
        await asyncio.sleep(interval)


# --- views derived from alerts ------------------------------------------------


async def alert_events(
    store: EventStore, alert: StoredAlert, limit: int = MAX_LIMIT
) -> list[NormalizedEvent]:
    """Events behind an alert: same host/source IP/group fields, first_seen-5m .. last_seen+5m.

    Returned oldest first, so they read like a log. An alert with no group fields and no
    source IP (e.g. a local sudo failure) would otherwise match every event on the host in
    the window, so its user name/target narrow the match instead.
    """
    group = {k: v for k, v in alert.group.items() if v is not None}
    source_ip = alert.source.ip or group.get("source.ip")
    if not group and not source_ip:
        group = {
            key: value
            for key, value in (("user.name", alert.user.name), ("user.target", alert.user.target))
            if value is not None
        }
    events = await store.query(
        source_ip=source_ip,
        host=alert.host,
        since=alert.first_seen - ALERT_EVENT_MARGIN,
        until=alert.last_seen + ALERT_EVENT_MARGIN,
        limit=MAX_LIMIT,
    )
    matched = []
    for event in events:
        doc = event.model_dump(mode="json")
        if all(str(get_field(doc, key)) == str(value) for key, value in group.items()):
            matched.append(event)
    matched.sort(key=lambda e: _utc(e.timestamp))
    return matched[:limit]


def attack_matrix(techniques: list[dict]) -> dict:
    """Technique rows from AlertStore.technique_counts, grouped by tactic in kill-chain order."""
    tactics: dict[str, list[dict]] = {}
    for row in techniques:
        tactics.setdefault(row["tactic"], []).append(
            {k: row[k] for k in ("id", "name", "alerts", "max_severity")}
        )
    ordered = sorted(tactics, key=lambda t: (_TACTIC_RANK.get(t.lower(), len(TACTIC_ORDER)), t))
    return {"tactics": [{"tactic": t, "techniques": sorted(tactics[t], key=lambda r: r["id"])} for t in ordered]}
