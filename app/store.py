"""Alert storage with deduplication and triage status.

Deduplication: an alert with the same rule, host and grouping key as an alert
that is still open (or acknowledged) and was last seen within the dedup window
is merged into it -- occurrences and evidence grow, no new alert is created
and no new notification goes out. Windows use event time, like detection.

Two implementations share those semantics: PostgresAlertStore for real
deployments, MemoryAlertStore for tests and running without a database.
"""

import hashlib
import ipaddress
import itertools
import json
from datetime import datetime, timedelta
from typing import Literal, Protocol

import asyncpg

from app.detection import Alert
from app.detection.engine import MAX_EVIDENCE

Status = Literal["open", "acknowledged", "closed"]
DEFAULT_DEDUP_WINDOW = timedelta(minutes=15)


class StoredAlert(Alert):
    dedup_key: str
    status: Status = "open"
    occurrences: int = 1
    last_seen: datetime


def dedup_key(alert: Alert) -> str:
    # Grouped rules already say what makes two alerts "the same"; for
    # single-event rules fall back to who did it and from where.
    identity = alert.group or {
        "source.ip": alert.source.ip,
        "user.name": alert.user.name,
        "user.target": alert.user.target,
    }
    payload = json.dumps([alert.rule_id, alert.host, identity], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _new(alert: Alert) -> StoredAlert:
    return StoredAlert(**alert.model_dump(), dedup_key=dedup_key(alert), last_seen=alert.timestamp)


def _merge(existing: StoredAlert, alert: Alert) -> StoredAlert:
    existing.occurrences += 1
    existing.count += alert.count
    existing.last_seen = max(existing.last_seen, alert.timestamp)
    existing.evidence = (existing.evidence + alert.evidence)[-MAX_EVIDENCE:]
    if alert.risk_score > existing.risk_score:
        existing.risk_score = alert.risk_score
        existing.risk_factors = alert.risk_factors
        existing.threat = alert.threat
    return existing


def _matches_text(alert: StoredAlert, q: str) -> bool:
    needle = q.lower()
    fields = (alert.rule_id, alert.title, alert.host, alert.source.ip, alert.user.name, alert.user.target)
    return any(f and needle in f.lower() for f in fields)


def _can_merge(existing: StoredAlert, alert: Alert, window: timedelta) -> bool:
    return existing.status != "closed" and existing.last_seen >= alert.timestamp - window


class AlertStore(Protocol):
    async def save(self, alert: Alert) -> tuple[StoredAlert, bool]:
        """Store or merge an alert. Returns (stored alert, True if newly created)."""
        ...

    async def list(
        self,
        status: Status | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        limit: int = 50,
        q: str | None = None,
        since: datetime | None = None,
        offset: int = 0,
    ) -> list[StoredAlert]: ...

    async def get(self, alert_id: str) -> StoredAlert | None: ...

    async def set_status(self, alert_id: str, status: Status) -> StoredAlert | None: ...

    async def close(self) -> None: ...


class MemoryAlertStore:
    def __init__(self, dedup_window: timedelta = DEFAULT_DEDUP_WINDOW):
        self.dedup_window = dedup_window
        self._alerts: dict[str, StoredAlert] = {}
        self._order: dict[str, int] = {}  # insertion order, to break last_seen ties
        self._counter = itertools.count()

    async def save(self, alert: Alert) -> tuple[StoredAlert, bool]:
        key = dedup_key(alert)
        candidates = [a for a in self._alerts.values() if a.dedup_key == key and _can_merge(a, alert, self.dedup_window)]
        if candidates:
            return _merge(max(candidates, key=lambda a: a.last_seen), alert), False
        stored = _new(alert)
        self._alerts[stored.id] = stored
        self._order[stored.id] = next(self._counter)
        return stored, True

    async def list(
        self, status=None, severity=None, rule_id=None, limit=50, q=None, since=None, offset=0
    ) -> list[StoredAlert]:
        matching = [
            a
            for a in self._alerts.values()
            if (status is None or a.status == status)
            and (severity is None or a.severity == severity)
            and (rule_id is None or a.rule_id == rule_id)
            and (since is None or a.last_seen >= since)
            and (not q or _matches_text(a, q))
        ]
        matching.sort(key=lambda a: (a.last_seen, self._order[a.id]), reverse=True)
        return matching[offset : offset + limit]

    async def get(self, alert_id: str) -> StoredAlert | None:
        return self._alerts.get(alert_id)

    async def set_status(self, alert_id: str, status: Status) -> StoredAlert | None:
        alert = self._alerts.get(alert_id)
        if alert:
            alert.status = status
        return alert

    async def close(self) -> None:
        pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    seq         BIGSERIAL UNIQUE,
    dedup_key   TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    risk_score  INT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed')),
    host        TEXT,
    source_ip   INET,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    occurrences INT NOT NULL DEFAULT 1,
    body        JSONB NOT NULL,  -- the full StoredAlert document
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_dedup ON alerts (dedup_key, last_seen DESC) WHERE status <> 'closed';
CREATE INDEX IF NOT EXISTS alerts_triage ON alerts (status, last_seen DESC);
"""


def _ip(value: str | None):
    try:
        return ipaddress.ip_address(value) if value else None
    except ValueError:
        return None


class PostgresAlertStore:
    def __init__(self, pool: asyncpg.Pool, dedup_window: timedelta):
        self._pool = pool
        self.dedup_window = dedup_window

    @classmethod
    async def connect(cls, url: str, dedup_window: timedelta = DEFAULT_DEDUP_WINDOW) -> "PostgresAlertStore":
        pool = await asyncpg.create_pool(url, min_size=1, max_size=5)
        async with pool.acquire() as conn:
            await conn.execute(SCHEMA)
        return cls(pool, dedup_window)

    async def save(self, alert: Alert) -> tuple[StoredAlert, bool]:
        key = dedup_key(alert)
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT body FROM alerts
                WHERE dedup_key = $1 AND status <> 'closed' AND last_seen >= $2
                ORDER BY last_seen DESC LIMIT 1
                FOR UPDATE
                """,
                key,
                alert.timestamp - self.dedup_window,
            )
            if row:
                stored = _merge(StoredAlert.model_validate_json(row["body"]), alert)
                await conn.execute(
                    """
                    UPDATE alerts SET risk_score = $2, last_seen = $3, occurrences = $4,
                                      body = $5::jsonb, updated_at = now()
                    WHERE id = $1
                    """,
                    stored.id,
                    stored.risk_score,
                    stored.last_seen,
                    stored.occurrences,
                    stored.model_dump_json(),
                )
                return stored, False

            stored = _new(alert)
            await conn.execute(
                """
                INSERT INTO alerts (id, dedup_key, rule_id, severity, risk_score, status, host,
                                    source_ip, first_seen, last_seen, occurrences, body)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)
                """,
                stored.id,
                stored.dedup_key,
                stored.rule_id,
                stored.severity,
                stored.risk_score,
                stored.status,
                stored.host,
                _ip(stored.source.ip),
                stored.first_seen,
                stored.last_seen,
                stored.occurrences,
                stored.model_dump_json(),
            )
            return stored, True

    async def list(
        self, status=None, severity=None, rule_id=None, limit=50, q=None, since=None, offset=0
    ) -> list[StoredAlert]:
        clauses, params = [], []
        for column, value in (("status", status), ("severity", severity), ("rule_id", rule_id)):
            if value is not None:
                params.append(value)
                clauses.append(f"{column} = ${len(params)}")
        if since is not None:
            params.append(since)
            clauses.append(f"last_seen >= ${len(params)}")
        if q:
            escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
            n = len(params)
            clauses.append(
                f"(rule_id ILIKE ${n} OR host ILIKE ${n} OR host(source_ip) ILIKE ${n}"
                f" OR body->>'title' ILIKE ${n} OR body->'user'->>'name' ILIKE ${n}"
                f" OR body->'user'->>'target' ILIKE ${n})"
            )
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params += [limit, offset]
        rows = await self._pool.fetch(
            f"SELECT body FROM alerts {where} ORDER BY last_seen DESC, seq DESC"
            f" LIMIT ${len(params) - 1} OFFSET ${len(params)}",
            *params,
        )
        return [StoredAlert.model_validate_json(row["body"]) for row in rows]

    async def get(self, alert_id: str) -> StoredAlert | None:
        row = await self._pool.fetchrow("SELECT body FROM alerts WHERE id = $1", alert_id)
        return StoredAlert.model_validate_json(row["body"]) if row else None

    async def set_status(self, alert_id: str, status: Status) -> StoredAlert | None:
        row = await self._pool.fetchrow(
            """
            UPDATE alerts SET status = $2, body = jsonb_set(body, '{status}', to_jsonb($2::text)), updated_at = now()
            WHERE id = $1 RETURNING body
            """,
            alert_id,
            status,
        )
        return StoredAlert.model_validate_json(row["body"]) if row else None

    async def close(self) -> None:
        await self._pool.close()
