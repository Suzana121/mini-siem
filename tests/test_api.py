from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.main import create_app
from app.sinks import MemorySink

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"
RULES = load_rules(DEFAULT_RULES_DIR)


@pytest.fixture
def sink():
    return MemorySink(DetectionEngine(RULES))


@pytest.fixture
def client(sink):
    with TestClient(create_app(sink, RULES)) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "sink": "MemorySink"}


def test_sources(client):
    assert client.get("/sources").json() == ["auth.log"]


def test_ingest_sample(client, sink):
    lines = SAMPLE.read_text().splitlines()
    response = client.post("/ingest", json={"source": "auth.log", "lines": lines})
    assert response.status_code == 200
    assert response.json() == {"received": 17, "parsed": 16, "unparsed": 1}
    assert len(sink.events) == 16
    assert sink.events[0].event.action == "ssh_no_identification"


def test_rules(client):
    rules = client.get("/rules").json()
    assert len(rules) == len(RULES)
    assert set(rules[0]) == {"id", "title", "description", "severity", "mitre"}


def test_alerts_after_ingest(client):
    assert client.get("/alerts").json() == []
    client.post("/ingest", json={"source": "auth.log", "lines": SAMPLE.read_text().splitlines()})
    alerts = client.get("/alerts").json()
    assert len(alerts) == 7
    assert alerts[0]["rule_id"] == "sudo-credential-file-access"  # newest first
    assert len(client.get("/alerts?limit=2").json()) == 2


def test_unknown_source(client):
    response = client.post("/ingest", json={"source": "nope", "lines": ["x"]})
    assert response.status_code == 400


def test_too_many_lines(client):
    response = client.post("/ingest", json={"source": "auth.log", "lines": ["x"] * 10_001})
    assert response.status_code == 422
