"""Builds pipeline components from environment variables.

| Variable              | Default          | Meaning                                         |
|-----------------------|------------------|-------------------------------------------------|
| REDIS_URL             | (unset)          | Event stream; unset = run detection in the API  |
| DATABASE_URL          | (unset)          | PostgreSQL for alerts; unset = in memory        |
| RULES_DIR             | rules/           | Detection rules                                 |
| GEOIP_DB              | data/dbip-city-lite.mmdb | MaxMind-format city DB; skipped if absent |
| INTEL_DIRS            | intel/           | Threat-intel feed dirs, separated by ':'        |
| DEDUP_WINDOW          | 15m              | Merge repeats of an open alert within this      |
| WEBHOOK_URLS          | (unset)          | Comma-separated webhook URLs                    |
| WEBHOOK_MIN_SEVERITY  | high             | Lowest severity that triggers a webhook         |
| WEBHOOK_SECRET        | (unset)          | HMAC key for the X-MiniSIEM-Signature header    |
| EVENT_RETENTION       | 7d               | How long raw events are kept for drill-down     |
| ADMIN_USERNAME        | (unset)          | Creates this admin on first start if no users   |
| ADMIN_PASSWORD        | (unset)          | ...with this password (min 12 characters)       |
| COOKIE_SECURE         | true             | Set false to use the dashboard over plain HTTP  |
| WEB_DIR               | web/dist         | Built dashboard, served at /                    |
"""

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from pathlib import Path

from app.auth import AuthStore, MemoryAuthStore, PostgresAuthStore, ensure_admin
from app.detection import DEFAULT_RULES_DIR, DetectionEngine, Rule, load_rules
from app.detection.rules import parse_duration
from app.enrichment import Enricher, GeoIP, ThreatIntel
from app.events import EventStore, MemoryEventStore, PostgresEventStore, retention_loop
from app.notify import WebhookNotifier
from app.pipeline import Pipeline
from app.store import AlertStore, MemoryAlertStore, PostgresAlertStore

ROOT = DEFAULT_RULES_DIR.parent
log = logging.getLogger("mini-siem.config")


def load_rules_from_env() -> list[Rule]:
    return load_rules(Path(os.getenv("RULES_DIR", DEFAULT_RULES_DIR)))


def build_enricher() -> Enricher:
    geoip = None
    geoip_path = Path(os.getenv("GEOIP_DB", ROOT / "data" / "dbip-city-lite.mmdb"))
    if geoip_path.exists():
        geoip = GeoIP(geoip_path)
    else:
        log.info("GeoIP database %s not found, skipping geolocation", geoip_path)

    dirs = [Path(d) for d in os.getenv("INTEL_DIRS", str(ROOT / "intel")).split(":") if d]
    intel = ThreatIntel.from_directories([d for d in dirs if d.is_dir()])
    log.info("threat intel feeds: %s", intel.sizes or "none")
    return Enricher(geoip, intel)


async def build_store(stack: AsyncExitStack) -> AlertStore:
    window = parse_duration(os.getenv("DEDUP_WINDOW", "15m"))
    url = os.getenv("DATABASE_URL")
    store: AlertStore = await PostgresAlertStore.connect(url, window) if url else MemoryAlertStore(window)
    stack.push_async_callback(store.close)
    return store


def build_notifier(stack: AsyncExitStack) -> WebhookNotifier | None:
    urls = [u.strip() for u in os.getenv("WEBHOOK_URLS", "").split(",") if u.strip()]
    if not urls:
        return None
    notifier = WebhookNotifier(
        urls,
        min_severity=os.getenv("WEBHOOK_MIN_SEVERITY", "high"),
        secret=os.getenv("WEBHOOK_SECRET") or None,
    )
    stack.push_async_callback(notifier.close)
    return notifier


async def build_events(stack: AsyncExitStack, run_retention: bool = True) -> EventStore:
    retention = parse_duration(os.getenv("EVENT_RETENTION", "7d"))
    url = os.getenv("DATABASE_URL")
    events: EventStore = await PostgresEventStore.connect(url, retention) if url else MemoryEventStore()
    stack.push_async_callback(events.close)
    if run_retention:
        task = asyncio.create_task(retention_loop(events, retention))
        stack.callback(task.cancel)
    return events


async def build_auth(stack: AsyncExitStack) -> AuthStore:
    url = os.getenv("DATABASE_URL")
    auth: AuthStore = await PostgresAuthStore.connect(url) if url else MemoryAuthStore()
    stack.push_async_callback(auth.close)
    username, password = os.getenv("ADMIN_USERNAME"), os.getenv("ADMIN_PASSWORD")
    if username and password:
        if await ensure_admin(auth, username, password):
            log.info("created initial admin '%s'", username)
    else:
        log.info("ADMIN_USERNAME/ADMIN_PASSWORD not set; create users with scripts/create_user.py")
    return auth


async def build_pipeline(
    stack: AsyncExitStack, rules: list[Rule], store: AlertStore, events: EventStore | None = None
) -> Pipeline:
    return Pipeline(DetectionEngine(rules), store, build_enricher(), build_notifier(stack), events)
