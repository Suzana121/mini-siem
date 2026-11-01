"""Event store (memory + optional Postgres), alert views and the HTTP routes.

The Postgres variant runs when TEST_DATABASE_URL is set; it truncates the
events table, so never point it at real data.
"""

import os
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI

from app.events import (
    MemoryEventStore,
    PostgresEventStore,
    alert_events,
    attack_matrix,
    parse_window,
    retention_loop,
    summarize,
)
from app.detection.rules import MitreTechnique
from app.schema import EventInfo, HostInfo, NormalizedEvent, Outcome, SourceInfo, UserInfo
from app.store import MemoryAlertStore
from tests.conftest import T0, make_alert

pytestmark = pytest.mark.anyio


def make_event(seconds=0, ip="198.51.100.7", user="root", host="web01") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds),
        log_source="auth.log",
        event=EventInfo(category="authentication", action="ssh_login", outcome=Outcome.FAILURE),
        host=HostInfo(name=host),
        user=UserInfo(name=user),
        source=SourceInfo(ip=ip),
        raw=f"line at {seconds}",
    )


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield MemoryEventStore()
        return
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    store = await PostgresEventStore.connect(url, timedelta(days=1))
    await store._pool.execute("TRUNCATE events")
    yield store
    await store.close()


async def test_query_filters_and_orders_newest_first(store):
    await store.add([make_event(0), make_event(10, ip="203.0.113.9"), make_event(20, user="bob", host="db01")])
    assert [e.raw for e in await store.query()] == ["line at 20", "line at 10", "line at 0"]
    assert [e.raw for e in await store.query(source_ip="203.0.113.9")] == ["line at 10"]
    assert [e.raw for e in await store.query(user="bob")] == ["line at 20"]
    assert [e.raw for e in await store.query(host="web01")] == ["line at 10", "line at 0"]
    assert await store.query(source_ip="not-an-ip") == []


async def test_query_time_range_and_paging(store):
    await store.add([make_event(s) for s in (0, 10, 20, 30)])
    got = await store.query(since=T0 + timedelta(seconds=10), until=T0 + timedelta(seconds=20))
    assert [e.raw for e in got] == ["line at 20", "line at 10"]
    page = await store.query(limit=2, offset=1)
    assert [e.raw for e in page] == ["line at 20", "line at 10"]


async def test_roundtrip_preserves_event(store):
    event = make_event(5)
    await store.add([event])
    assert await store.query() == [event]


async def test_prune(store):
    await store.add([make_event(0), make_event(100)])
    assert await store.prune(T0 + timedelta(seconds=50)) == 1
    assert [e.raw for e in await store.query()] == ["line at 100"]


async def test_memory_store_is_bounded():
    store = MemoryEventStore(max_events=2)
    await store.add([make_event(0), make_event(1), make_event(2)])
    assert [e.raw for e in await store.query()] == ["line at 2", "line at 1"]


async def test_retention_loop_prunes_and_survives_errors():
    import asyncio

    class Flaky(MemoryEventStore):
        calls = 0

        async def prune(self, older_than):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise RuntimeError("boom")
            return await super().prune(older_than)

    s = Flaky()
    await s.add([make_event(0)])  # years older than "now"
    task = asyncio.create_task(retention_loop(s, timedelta(days=1), interval=0.01))
    await asyncio.sleep(0.2)
    task.cancel()
    assert Flaky.calls >= 2
    assert await s.query() == []


def test_parse_window():
    assert parse_window("15m") == timedelta(minutes=15)
    assert parse_window("2h") == timedelta(hours=2)
    with pytest.raises(ValueError):
        parse_window("soon")


async def test_alert_events_match_group_host_and_margin():
    es = MemoryEventStore()
    await es.add(
        [
            make_event(-600),  # outside the 5 minute margin
            make_event(-200),
            make_event(0),
            make_event(10, ip="203.0.113.9"),  # other source
            make_event(20, host="db01"),  # other host
            make_event(100),
            make_event(500),  # beyond last_seen + 5m
        ]
    )
    alerts = MemoryAlertStore()
    stored, _ = await alerts.save(make_alert(seconds=100))
    stored.first_seen = T0
    got = await alert_events(es, stored)
    assert [e.raw for e in got] == ["line at -200", "line at 0", "line at 100"]


async def test_alert_events_apply_group_fields():
    es = MemoryEventStore()
    await es.add([make_event(0, user="root"), make_event(1, user="bob")])
    stored, _ = await MemoryAlertStore().save(make_alert(group={"source.ip": "198.51.100.7", "user.name": "bob"}))
    assert [e.user.name for e in await alert_events(es, stored)] == ["bob"]


async def test_summarize():
    store = MemoryAlertStore()
    a, _ = await store.save(make_alert(ip="198.51.100.7", user="root", risk_score=70))
    await store.save(make_alert(rule_id="r2", ip="198.51.100.7", user="bob", severity="low", risk_score=90))
    await store.save(make_alert(rule_id="r3", ip="203.0.113.9", user="bob"))
    await store.set_status(a.id, "closed")
    out = summarize(await store.list(), now=T0 + timedelta(hours=1))
    assert out["by_status"] == {"open": 2, "acknowledged": 0, "closed": 1}
    assert out["by_severity"] == {"low": 1, "medium": 0, "high": 2, "critical": 0}
    assert out["last_24h"] == 3
    assert out["top_source_ips"][0] == {"ip": "198.51.100.7", "alerts": 2, "max_risk": 90}
    assert out["top_users"][0] == {"user": "bob", "alerts": 2}
    assert summarize(await store.list(), now=T0 + timedelta(days=2))["last_24h"] == 0


async def test_attack_matrix_orders_tactics():
    store = MemoryAlertStore()
    discovery = MitreTechnique(id="T1046", name="Network Service Discovery", tactic="Discovery")
    impact = MitreTechnique(id="T1486", name="Data Encrypted for Impact", tactic="Impact")
    recon = MitreTechnique(id="T1595", name="Active Scanning", tactic="Reconnaissance")
    for rule, mitre, sev in (
        ("a", [impact], "low"),
        ("b", [discovery, recon], "medium"),
        ("c", [discovery], "critical"),
        ("d", [], "low"),
    ):
        alert = make_alert(rule_id=rule, severity=sev)
        alert.mitre = mitre
        await store.save(alert)
    out = attack_matrix(await store.list())
    assert [t["tactic"] for t in out["tactics"]] == ["Reconnaissance", "Discovery", "Impact"]
    disc = out["tactics"][1]["techniques"][0]
    assert disc == {"id": "T1046", "name": "Network Service Discovery", "alerts": 2, "max_severity": "critical"}


# --- HTTP ---------------------------------------------------------------------


@pytest.fixture
async def client():
    from app.routes import events as routes

    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[routes.viewer] = lambda: object()
    app.state.events = MemoryEventStore()
    app.state.store = MemoryAlertStore()
    await app.state.events.add([make_event(0), make_event(60, ip="203.0.113.9"), make_event(7200)])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        c.app = app
        yield c


async def test_get_events_filters(client):
    r = await client.get("/events", params={"source_ip": "203.0.113.9"})
    assert r.status_code == 200
    assert [e["raw"] for e in r.json()] == ["line at 60"]


async def test_get_events_around_window(client):
    around = (T0 + timedelta(seconds=30)).isoformat()
    r = await client.get("/events", params={"around": around, "window": "5m"})
    assert [e["raw"] for e in r.json()] == ["line at 60", "line at 0"]
    assert (await client.get("/events", params={"around": around, "window": "bogus"})).status_code == 422


async def test_get_events_limit_validation(client):
    assert (await client.get("/events", params={"limit": 1001})).status_code == 422
    assert len((await client.get("/events", params={"limit": 1})).json()) == 1
    assert len((await client.get("/events", params={"offset": 2})).json()) == 1


async def test_alert_events_route(client):
    stored, _ = await client.app.state.store.save(make_alert(seconds=30))
    r = await client.get(f"/alerts/{stored.id}/events")
    assert r.status_code == 200
    assert [e["raw"] for e in r.json()] == ["line at 0"]
    assert (await client.get("/alerts/missing/events")).status_code == 404


async def test_stats_routes(client):
    await client.app.state.store.save(make_alert())
    summary = (await client.get("/stats/summary")).json()
    assert summary["by_status"]["open"] == 1
    assert summary["top_source_ips"][0]["ip"] == "198.51.100.7"
    attack = (await client.get("/stats/attack")).json()
    assert attack["tactics"][0]["tactic"] == "Credential Access"
    later = (T0 + timedelta(days=1)).isoformat()
    assert (await client.get("/stats/attack", params={"since": later})).json() == {"tactics": []}
