import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import MemoryAuthStore, ensure_admin
from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.enrichment import Enricher, ThreatIntel
from app.events import MemoryEventStore
from app.main import create_app
from app.pipeline import Pipeline
from app.sinks import MemorySink
from app.store import MemoryAlertStore

ROOT = Path(__file__).parent.parent
SAMPLE = ROOT / "samples" / "auth.log"
RULES = load_rules(DEFAULT_RULES_DIR)
ADMIN = ("admin", "correct-horse-battery")
CSRF = {"X-Requested-With": "mini-siem"}


@pytest.fixture
def store():
    return MemoryAlertStore()


@pytest.fixture
def sink(store):
    enricher = Enricher(intel=ThreatIntel.from_directories([ROOT / "samples" / "intel"]))
    return MemorySink(Pipeline(DetectionEngine(RULES), store, enricher))


@pytest.fixture
def anon_client(sink, store):
    auth = MemoryAuthStore()
    asyncio.run(ensure_admin(auth, *ADMIN))
    with TestClient(create_app(sink, store, RULES, MemoryEventStore(), auth), headers=CSRF) as c:
        yield c


@pytest.fixture
def client(anon_client):
    response = anon_client.post("/auth/login", json={"username": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200
    return anon_client


def test_endpoints_require_login(anon_client):
    for method, path in [("get", "/alerts"), ("get", "/rules"), ("get", "/sources"), ("post", "/ingest")]:
        assert getattr(anon_client, method)(path).status_code == 401, path


def test_alert_search_and_paging(client):
    ingest_sample(client)
    everything = client.get("/alerts").json()
    assert client.get("/alerts", params={"q": "203.0.113.45"}).json()
    assert client.get("/alerts", params={"q": "no-such-thing"}).json() == []
    assert client.get("/alerts", params={"limit": 1, "offset": 1}).json() == everything[1:2]


def ingest_sample(client):
    return client.post("/ingest", json={"source": "auth.log", "lines": SAMPLE.read_text().splitlines()})


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_sources(client):
    assert client.get("/sources").json() == ["auth.log"]


def test_ingest_sample(client, sink):
    response = ingest_sample(client)
    assert response.status_code == 200
    assert response.json() == {"received": 17, "parsed": 16, "unparsed": 1}
    assert len(sink.events) == 16
    assert sink.events[0].event.action == "ssh_no_identification"


def test_rules(client):
    rules = client.get("/rules").json()
    assert len(rules) == len(RULES)
    assert set(rules[0]) == {"id", "title", "description", "severity", "mitre"}


def test_alerts_are_enriched_and_scored(client):
    assert client.get("/alerts").json() == []
    ingest_sample(client)
    alerts = client.get("/alerts").json()
    assert len(alerts) == 8
    assert alerts[0]["rule_id"] == "sudo-credential-file-access"  # newest first

    intel_hit = next(a for a in alerts if a["rule_id"] == "ssh-login-threat-intel")
    assert intel_hit["threat"] == {"listed": True, "feeds": ["demo-blocklist"]}
    assert intel_hit["risk_score"] == 100
    assert intel_hit["status"] == "open"


def test_alert_filters(client):
    ingest_sample(client)
    critical = client.get("/alerts?severity=critical").json()
    assert {a["rule_id"] for a in critical} == {"ssh-brute-force-success", "ssh-login-threat-intel", "backdoor-account"}
    assert len(client.get("/alerts?limit=2").json()) == 2
    assert client.get("/alerts?status=bogus").status_code == 422


def test_triage_workflow(client):
    ingest_sample(client)
    alert_id = client.get("/alerts?rule_id=backdoor-account").json()[0]["id"]

    assert client.get(f"/alerts/{alert_id}").json()["status"] == "open"
    response = client.patch(f"/alerts/{alert_id}", json={"status": "acknowledged"})
    assert response.status_code == 200 and response.json()["status"] == "acknowledged"
    assert [a["id"] for a in client.get("/alerts?status=acknowledged").json()] == [alert_id]
    assert client.patch(f"/alerts/{alert_id}", json={"status": "deleted"}).status_code == 422


def test_unknown_alert(client):
    assert client.get("/alerts/nope").status_code == 404
    assert client.patch("/alerts/nope", json={"status": "closed"}).status_code == 404


def test_reingesting_deduplicates(client):
    ingest_sample(client)
    ingest_sample(client)
    alerts = client.get("/alerts").json()
    assert len(alerts) == 8
    assert {a["occurrences"] for a in alerts} == {2}


def test_unknown_source(client):
    response = client.post("/ingest", json={"source": "nope", "lines": ["x"]})
    assert response.status_code == 400


def test_too_many_lines(client):
    response = client.post("/ingest", json={"source": "auth.log", "lines": ["x"] * 10_001})
    assert response.status_code == 422
