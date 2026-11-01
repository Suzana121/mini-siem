"""Unit tests for lab/run_lab.py's scoring logic (no Docker, no network)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab"))

from run_lab import score_scenario  # noqa: E402


def _fake_clock():
    state = {"t": 0.0}

    def now():
        return state["t"]

    def sleep(seconds):
        state["t"] += seconds

    return now, sleep, state


def test_detects_all_expected_rules_before_timeout():
    now, sleep, state = _fake_clock()
    polls = [
        [],
        [{"rule_id": "ssh-brute-force"}],
        [{"rule_id": "ssh-brute-force"}, {"rule_id": "ssh-brute-force-success"}],
    ]

    calls = iter(polls)

    def fetch():
        return next(calls, [])

    result = score_scenario(
        ["ssh-brute-force", "ssh-brute-force-success"],
        fetch,
        timeout=10,
        poll_interval=1.0,
        sleep=sleep,
        now=now,
    )
    assert result["detected"] is True
    assert result["missing_rules"] == []
    assert result["unexpected_rules"] == []
    assert result["time_to_detect_s"] == {"ssh-brute-force": 1.0, "ssh-brute-force-success": 2.0}


def test_missing_rule_reported_after_timeout():
    now, sleep, state = _fake_clock()

    def fetch():
        return [{"rule_id": "ssh-brute-force"}]

    result = score_scenario(
        ["ssh-brute-force", "ssh-brute-force-success"],
        fetch,
        timeout=5,
        poll_interval=1.0,
        sleep=sleep,
        now=now,
    )
    assert result["detected"] is False
    assert result["missing_rules"] == ["ssh-brute-force-success"]
    assert result["time_to_detect_s"] == {"ssh-brute-force": 0.0}


def test_unexpected_rule_is_reported_separately():
    now, sleep, state = _fake_clock()

    def fetch():
        return [{"rule_id": "ssh-scanner"}]

    result = score_scenario([], fetch, timeout=3, poll_interval=1.0, sleep=sleep, now=now)
    assert result["detected"] is True  # nothing expected, nothing missing
    assert result["unexpected_rules"] == ["ssh-scanner"]
    assert result["time_to_detect_s"] == {}


def test_benign_scenario_with_zero_alerts_is_clean():
    now, sleep, state = _fake_clock()
    result = score_scenario([], lambda: [], timeout=2, poll_interval=1.0, sleep=sleep, now=now)
    assert result == {
        "detected": True,
        "missing_rules": [],
        "unexpected_rules": [],
        "overlapping_rules": [],
        "time_to_detect_s": {},
    }


def test_allowed_rules_are_overlap_not_unexpected():
    now, sleep, state = _fake_clock()
    alerts = [{"rule_id": "ssh-password-spraying"}, {"rule_id": "ssh-brute-force"}, {"rule_id": "sudo-root-shell"}]
    result = score_scenario(
        ["ssh-password-spraying"], lambda: alerts, ["ssh-brute-force"], timeout=2, poll_interval=1.0, sleep=sleep, now=now
    )
    assert result["detected"]
    assert result["overlapping_rules"] == ["ssh-brute-force"]
    assert result["unexpected_rules"] == ["sudo-root-shell"]


def test_stops_polling_as_soon_as_everything_is_seen():
    now, sleep, state = _fake_clock()
    poll_count = {"n": 0}

    def fetch():
        poll_count["n"] += 1
        return [{"rule_id": "ssh-scanner"}]

    score_scenario(["ssh-scanner"], fetch, timeout=90, poll_interval=1.0, sleep=sleep, now=now)
    assert poll_count["n"] == 1  # first poll already satisfies it; no further sleeps needed
