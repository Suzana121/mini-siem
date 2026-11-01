from datetime import datetime, timedelta, timezone

import pytest

from app.detection import Alert
from app.detection.rules import MitreTechnique
from app.schema import SourceInfo, ThreatInfo, UserInfo

T0 = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def anyio_backend():
    return "asyncio"


def make_alert(
    rule_id: str = "ssh-brute-force",
    seconds: float = 0,
    severity: str = "high",
    group: dict | None = None,
    ip: str | None = "198.51.100.7",
    user: str | None = "root",
    host: str = "web01",
    risk_score: int = 70,
    evidence: list[str] | None = None,
    listed: bool = False,
) -> Alert:
    ts = T0 + timedelta(seconds=seconds)
    return Alert(
        rule_id=rule_id,
        title=f"title of {rule_id}",
        severity=severity,
        mitre=[MitreTechnique(id="T1110", name="Brute Force", tactic="Credential Access")],
        timestamp=ts,
        first_seen=ts,
        host=host,
        group={"source.ip": ip} if group is None else group,
        count=5,
        evidence=evidence if evidence is not None else [f"line at {seconds}"],
        source=SourceInfo(ip=ip, internal=False),
        user=UserInfo(name=user),
        threat=ThreatInfo(listed=listed, feeds=["feed-a"] if listed else []),
        risk_score=risk_score,
    )


@pytest.fixture(autouse=True)
def _insecure_cookies(monkeypatch):
    # TestClient talks plain HTTP, which would drop Secure cookies.
    monkeypatch.setenv("COOKIE_SECURE", "false")
