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
from app.detection.rules import MitreTechnique
from app.store import MemoryAlertStore, PostgresAlertStore
from tests.conftest import T0, make_alert

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


async def test_summary_and_technique_counts_match_across_stores(store):
    """Same fixture through both stores must aggregate identically (ties, unicode, unknown IPs, since)."""
    recon = MitreTechnique(id="T1595", name="Active Scanning", tactic="Reconnaissance")
    disc = MitreTechnique(id="T1046", name="Network Service Discovery", tactic="Discovery")
    brute = MitreTechnique(id="T1110", name="Brute Force", tactic="Credential Access")
    fixture = [
        dict(rule_id="a", seconds=0, ip="198.51.100.7", user="root", severity="low", risk_score=40, mitre=[brute]),
        dict(rule_id="b", seconds=60, ip="198.51.100.7", user="bob", severity="critical", risk_score=95, mitre=[brute, disc]),
        dict(rule_id="c", seconds=120, ip="203.0.113.9", user="bob", severity="medium", risk_score=10, mitre=[recon]),
        dict(rule_id="d", seconds=180, ip="203.0.113.10", user="alice", severity="high", risk_score=70, mitre=[]),
        dict(rule_id="e", seconds=240, ip="10.0.0.2", user="Zoë", severity="high", risk_score=70, mitre=[disc, recon]),
        dict(rule_id="f", seconds=300, ip=None, user=None, severity="low", risk_score=5, mitre=[brute]),
    ]
    saved = []
    for spec in fixture:
        mitre = spec.pop("mitre")
        alert = make_alert(**spec)
        alert.mitre = mitre
        stored, _ = await store.save(alert)
        saved.append(stored)
    await store.set_status(saved[0].id, "closed")
    await store.set_status(saved[1].id, "acknowledged")

    now = T0 + timedelta(hours=24, seconds=90)  # alerts 0 and 60 are older than 24h
    summary = await store.summary(now=now)
    assert summary["by_status"] == {"open": 4, "acknowledged": 1, "closed": 1}
    assert summary["by_severity"] == {"low": 2, "medium": 1, "high": 2, "critical": 1}
    assert summary["last_24h"] == 4
    assert summary["top_source_ips"] == [
        {"ip": "198.51.100.7", "alerts": 2, "max_risk": 95},
        {"ip": "10.0.0.2", "alerts": 1, "max_risk": 70},
        {"ip": "203.0.113.10", "alerts": 1, "max_risk": 70},
        {"ip": "203.0.113.9", "alerts": 1, "max_risk": 10},
    ]
    assert summary["top_users"] == [
        {"user": "bob", "alerts": 2},
        {"user": "Zoë", "alerts": 1},
        {"user": "alice", "alerts": 1},
        {"user": "root", "alerts": 1},
    ]

    def by_key(rows):
        return {(r["tactic"], r["id"]): r for r in rows}

    techniques = by_key(await store.technique_counts())
    assert techniques[("Credential Access", "T1110")] == {
        "tactic": "Credential Access", "id": "T1110", "name": "Brute Force", "alerts": 3, "max_severity": "critical",
    }
    assert techniques[("Discovery", "T1046")]["max_severity"] == "critical"
    assert techniques[("Reconnaissance", "T1595")]["alerts"] == 2
    assert len(techniques) == 3

    recent = by_key(await store.technique_counts(since=T0 + timedelta(seconds=100)))
    assert {k: v["alerts"] for k, v in recent.items()} == {
        ("Reconnaissance", "T1595"): 2,
        ("Discovery", "T1046"): 1,
        ("Credential Access", "T1110"): 1,
    }
