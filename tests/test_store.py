"""Runs against both store implementations so they keep identical semantics.

The Postgres variant runs when TEST_DATABASE_URL is set, e.g.:
    POSTGRES_PORT=55432 docker compose up -d postgres
    TEST_DATABASE_URL=postgresql://siem:siem-dev-only@localhost:55432/siem pytest
It truncates the alerts table, so never point it at real data.
"""

import os
from datetime import timedelta

import pytest

from app.detection.engine import MAX_EVIDENCE
from app.store import MemoryAlertStore, PostgresAlertStore
from tests.conftest import make_alert

pytestmark = pytest.mark.anyio
WINDOW = timedelta(minutes=15)


@pytest.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield MemoryAlertStore(WINDOW)
        return
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    store = await PostgresAlertStore.connect(url, WINDOW)
    await store._pool.execute("TRUNCATE alerts")
    yield store
    await store.close()


async def test_first_alert_is_created(store):
    stored, created = await store.save(make_alert())
    assert created
    assert stored.status == "open"
    assert stored.occurrences == 1
    assert stored.last_seen == stored.timestamp
    assert await store.get(stored.id) == stored


async def test_repeat_within_window_is_merged(store):
    first, _ = await store.save(make_alert(seconds=0, risk_score=70))
    second, created = await store.save(make_alert(seconds=600, risk_score=85, listed=True))
    assert not created
    assert second.id == first.id
    assert second.occurrences == 2
    assert second.count == 10
    assert second.last_seen == second.first_seen + timedelta(seconds=600)
    assert second.evidence == ["line at 0", "line at 600"]
    assert second.risk_score == 85
    assert second.threat.listed
    assert (await store.get(first.id)).occurrences == 2


async def test_repeat_after_window_is_new(store):
    await store.save(make_alert(seconds=0))
    _, created = await store.save(make_alert(seconds=16 * 60))
    assert created


async def test_window_slides_with_last_seen(store):
    await store.save(make_alert(seconds=0))
    await store.save(make_alert(seconds=10 * 60))
    _, created = await store.save(make_alert(seconds=20 * 60))
    assert not created


@pytest.mark.parametrize(
    "other",
    [
        {"group": {"source.ip": "198.51.100.99"}},
        {"rule_id": "ssh-scanner"},
        {"host": "db01"},
    ],
)
async def test_different_identity_is_not_merged(store, other):
    await store.save(make_alert())
    _, created = await store.save(make_alert(**other))
    assert created


async def test_ungrouped_alerts_dedup_by_user_and_source(store):
    await store.save(make_alert(rule_id="sudo-auth-failure", group={}, user="bob"))
    _, same = await store.save(make_alert(rule_id="sudo-auth-failure", group={}, user="bob", seconds=5))
    _, other = await store.save(make_alert(rule_id="sudo-auth-failure", group={}, user="eve", seconds=5))
    assert not same
    assert other


async def test_closed_alerts_are_not_reopened(store):
    first, _ = await store.save(make_alert())
    await store.set_status(first.id, "closed")
    _, created = await store.save(make_alert(seconds=5))
    assert created


async def test_acknowledged_alerts_still_merge(store):
    first, _ = await store.save(make_alert())
    await store.set_status(first.id, "acknowledged")
    merged, created = await store.save(make_alert(seconds=5))
    assert not created
    assert merged.status == "acknowledged"


async def test_evidence_is_capped(store):
    await store.save(make_alert(evidence=[f"a{i}" for i in range(15)]))
    merged, _ = await store.save(make_alert(seconds=1, evidence=[f"b{i}" for i in range(15)]))
    assert len(merged.evidence) == MAX_EVIDENCE
    assert merged.evidence[-1] == "b14"


async def test_list_orders_newest_first_and_filters(store):
    a, _ = await store.save(make_alert(rule_id="ssh-brute-force", seconds=0, severity="medium"))
    b, _ = await store.save(make_alert(rule_id="ssh-scanner", seconds=30, severity="low"))
    c, _ = await store.save(make_alert(rule_id="ssh-root-login", seconds=30, severity="high"))
    await store.set_status(b.id, "closed")

    assert [x.id for x in await store.list()] == [c.id, b.id, a.id]
    assert [x.id for x in await store.list(limit=1)] == [c.id]
    assert [x.id for x in await store.list(status="open")] == [c.id, a.id]
    assert [x.id for x in await store.list(severity="medium")] == [a.id]
    assert [x.id for x in await store.list(rule_id="ssh-scanner")] == [b.id]


async def test_set_status(store):
    stored, _ = await store.save(make_alert())
    updated = await store.set_status(stored.id, "acknowledged")
    assert updated.status == "acknowledged"
    assert (await store.get(stored.id)).status == "acknowledged"


async def test_unknown_id(store):
    assert await store.get("nope") is None
    assert await store.set_status("nope", "closed") is None
