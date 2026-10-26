from datetime import datetime, timedelta, timezone

import pytest
import yaml
from pydantic import ValidationError

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, Rule, RuleLoadError, load_rules
from app.detection.engine import MAX_EVIDENCE
from app.schema import EventInfo, NormalizedEvent, Outcome, SourceInfo, UserInfo

T0 = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)
MITRE = [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}]


def make_rule(**fields) -> Rule:
    return Rule.model_validate(
        {"id": "test", "title": "t", "description": "d", "severity": "low", "mitre": MITRE, **fields}
    )


def make_event(seconds=0, action="ssh_login", outcome=Outcome.FAILURE, user="root", ip="10.0.0.1", **labels):
    return NormalizedEvent(
        timestamp=T0 + timedelta(seconds=seconds),
        log_source="test",
        event=EventInfo(category="authentication", action=action, outcome=outcome),
        user=UserInfo(name=user),
        source=SourceInfo(ip=ip),
        labels=labels,
        raw=f"raw-{seconds}",
    )


def matches(match: dict, event: NormalizedEvent, exclude: dict | None = None) -> bool:
    rule = make_rule(match=match, exclude=exclude)
    return bool(DetectionEngine([rule]).process(event))


# --- selections --------------------------------------------------------------


def test_all_keys_must_match():
    assert matches({"event.action": "ssh_login", "user.name": "root"}, make_event())
    assert not matches({"event.action": "ssh_login", "user.name": "alice"}, make_event())


def test_list_means_any_of():
    assert matches({"user.name": ["alice", "root"]}, make_event())


def test_comparison_is_case_insensitive():
    assert matches({"user.name": "ROOT"}, make_event())


def test_yaml_booleans_match_label_strings():
    assert matches({"labels.invalid_user": True}, make_event(invalid_user="true"))


def test_missing_field_never_matches():
    assert not matches({"labels.command|contains": "x"}, make_event())


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("labels.command|contains", "SHADOW", True),
        ("labels.command|startswith", "/bin/", True),
        ("labels.command|endswith", "passwd", False),
        ("labels.command|re", r"^/bin/\w+ /etc/", True),
    ],
)
def test_modifiers(key, value, expected):
    assert matches({key: value}, make_event(command="/bin/cat /etc/shadow")) is expected


def test_exclude():
    assert not matches({"event.action": "ssh_login"}, make_event(), exclude={"user.name": "root"})


# --- rule validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {},  # neither match nor sequence
        {"match": {"a": 1}, "sequence": {"window": "1m", "group_by": ["x"], "steps": []}},
        {"match": {"a|nope": 1}},
        {"match": {"a|re": "("}},
        {"match": {}},
        {"match": {"a": 1}, "threshold": {"count": 1, "window": "1m"}},
        {"match": {"a": 1}, "threshold": {"count": 5, "window": "soon"}},
        {"match": {"a": 1}, "mitre": [{"id": "1110", "name": "x", "tactic": "y"}]},
        {"match": {"a": 1}, "unknown_key": True},
    ],
)
def test_invalid_rules_are_rejected(fields):
    with pytest.raises(ValidationError):
        make_rule(**fields)


def test_bundled_rules_load():
    rules = load_rules(DEFAULT_RULES_DIR)
    assert len(rules) >= 10
    assert all(rule.mitre for rule in rules)


def test_duplicate_rule_ids_are_rejected(tmp_path):
    spec = {"id": "dup", "title": "t", "description": "d", "severity": "low", "mitre": MITRE, "match": {"a": 1}}
    (tmp_path / "a.yml").write_text(yaml.safe_dump(spec))
    (tmp_path / "b.yml").write_text(yaml.safe_dump(spec))
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(tmp_path)


# --- engine state -------------------------------------------------------------


def threshold_rule(count=3, window="1m", **extra) -> Rule:
    return make_rule(
        match={"event.action": "ssh_login"},
        threshold={"count": count, "window": window, "group_by": ["source.ip"], **extra},
    )


def test_threshold_alert_contents():
    engine = DetectionEngine([threshold_rule()])
    alerts = [a for s in range(3) for a in engine.process(make_event(s))]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.count == 3
    assert alert.group == {"source.ip": "10.0.0.1"}
    assert alert.first_seen == T0
    assert alert.timestamp == T0 + timedelta(seconds=2)
    assert alert.evidence == ["raw-0", "raw-1", "raw-2"]
    assert alert.mitre[0].id == "T1110"


def test_events_missing_group_field_are_ignored():
    engine = DetectionEngine([threshold_rule()])
    assert not [a for s in range(5) for a in engine.process(make_event(s, ip=None))]


def test_distinct_counts_unique_values():
    engine = DetectionEngine([threshold_rule(distinct="user.name")])
    same_user = [a for s in range(5) for a in engine.process(make_event(s))]
    many_users = [a for s in range(3) for a in engine.process(make_event(s, user=f"u{s}", ip="10.0.0.2"))]
    assert not same_user
    assert len(many_users) == 1


def test_evidence_is_capped():
    engine = DetectionEngine([threshold_rule(count=30)])
    alerts = [a for s in range(30) for a in engine.process(make_event(s))]
    assert alerts[0].count == 30
    assert len(alerts[0].evidence) == MAX_EVIDENCE
    assert alerts[0].evidence[-1] == "raw-29"


def test_sweep_drops_idle_state():
    seq = make_rule(
        sequence={
            "window": "1m",
            "group_by": ["source.ip"],
            "steps": [{"name": "a", "match": {"event.outcome": "failure"}}, {"name": "b", "match": {"event.outcome": "success"}}],
        }
    )
    engine = DetectionEngine([threshold_rule(), seq])
    engine.process(make_event(0))
    assert engine._windows and engine._sequences
    engine._sweep(T0 + timedelta(minutes=5))
    assert not engine._windows and not engine._sequences
