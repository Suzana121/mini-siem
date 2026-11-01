from app.schema import GeoInfo
from app.scoring import score, severity_at_least
from tests.conftest import make_alert


def test_base_score_only():
    alert = make_alert(severity="medium", user="alice")
    alert.source.internal = True
    score(alert)
    assert alert.risk_score == 45
    assert alert.risk_factors == ["severity medium (+45)"]


def test_all_factors():
    alert = make_alert(severity="high", user="root", listed=True)
    alert.source.geo = GeoInfo(country="Netherlands")
    score(alert)
    assert alert.risk_score == 70 + 15 + 5 + 10
    assert alert.risk_factors[1:] == [
        "source IP on threat intel: feed-a (+15)",
        "external source (Netherlands) (+5)",
        "root account involved (+10)",
    ]


def test_score_is_capped_at_100():
    alert = score(make_alert(severity="critical", user="root", listed=True))
    assert alert.risk_score == 100


def test_severity_at_least():
    assert severity_at_least("critical", "high")
    assert severity_at_least("high", "high")
    assert not severity_at_least("medium", "high")
