from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.sinks import MemorySink

SAMPLE = Path(__file__).parent.parent / "samples" / "auth.log"


@pytest.fixture
def sink():
    return MemorySink()


@pytest.fixture
def client(sink):
    with TestClient(create_app(sink)) as c:
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


def test_unknown_source(client):
    response = client.post("/ingest", json={"source": "nope", "lines": ["x"]})
    assert response.status_code == 400


def test_too_many_lines(client):
    response = client.post("/ingest", json={"source": "auth.log", "lines": ["x"] * 10_001})
    assert response.status_code == 422
