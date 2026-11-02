"""nginx access-log parsing and the web-* detection rules, using real combined-format lines."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.parsers import PARSERS
from app.parsers.nginx_access import parse_line
from app.schema import Outcome

RULES = load_rules(DEFAULT_RULES_DIR)
BASE = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)
SAMPLE = Path(__file__).parent.parent / "samples" / "nginx_access.log"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0"


def req(seconds, path="/", status=200, method="GET", ip="203.0.113.9", agent=BROWSER, user="-"):
    ts = f"{BASE + timedelta(seconds=seconds):%d/%b/%Y:%H:%M:%S} +0000"
    return f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"'


def fired(lines):
    engine = DetectionEngine(RULES)
    alerts = []
    for raw in lines:
        event = parse_line(raw)
        assert event is not None, raw
        alerts.extend(engine.process(event))
    return sorted(a.rule_id for a in alerts)


def test_registered_as_source():
    assert PARSERS["nginx"] is parse_line


def test_parses_combined_line():
    e = parse_line(
        '203.0.113.9 - alice [26/Oct/2026:12:15:32 +0200] "GET /a?b=1 HTTP/1.1" 200 612 "https://x.test/" "curl/8.4.0"'
    )
    assert e.timestamp == datetime(2026, 10, 26, 10, 15, 32, tzinfo=timezone.utc)
    assert e.source.ip == "203.0.113.9"
    assert e.user.name == "alice"
    assert e.event.action == "http_request" and e.event.outcome == Outcome.SUCCESS
    assert e.labels == {
        "http_method": "GET",
        "http_path": "/a?b=1",
        "http_status": "200",
        "http_user_agent": "curl/8.4.0",
        "http_referrer": "https://x.test/",
    }


def test_error_status_is_failure_and_anonymous_user_unset():
    e = parse_line(req(0, status=404))
    assert e.event.outcome == Outcome.FAILURE
    assert e.user.name is None


def test_path_is_percent_decoded_and_bounded():
    e = parse_line(req(0, path="/f?x=%2e%2e%2f%2e%2e%2fetc/passwd"))
    assert e.labels["http_path"] == "/f?x=../../etc/passwd"
    assert len(parse_line(req(0, path="/" + "a" * 5000)).labels["http_path"]) == 1024


def test_ipv6_and_missing_trailer():
    e = parse_line('2001:db8::1 - - [26/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5')
    assert e.source.ip == "2001:db8::1"
    assert "http_user_agent" not in e.labels


@pytest.mark.parametrize("line", ["", "garbage", "Oct 26 10:00:00 web01 sshd[1]: hi", '1.2.3.4 - - [bad] "GET / HTTP/1.1" 200 1'])
def test_unrecognized_lines_return_none(line):
    assert parse_line(line) is None


CASES = {
    "20 not-found in a minute": ([req(i, f"/p{i}", 404) for i in range(20)], ["web-scanner"]),
    "19 not-found is below threshold": ([req(i, f"/p{i}", 404) for i in range(19)], []),
    "20 not-found from 20 IPs": ([req(i, "/x", 404, ip=f"198.51.100.{i}") for i in range(20)], []),
    "union select": ([req(0, "/p?id=1%20UNION%20SELECT%20null,password%20FROM%20u")], ["web-sqli-attempt"]),
    "or 1=1 tautology": ([req(0, "/login?u=admin'%20or%20'1'='1")], ["web-sqli-attempt"]),
    "time based sleep": ([req(0, "/p?id=1;select%20sleep(5)")], ["web-sqli-attempt"]),
    "word union in prose is fine": ([req(0, "/blog/european-union-news")], []),
    "dot-dot traversal": ([req(0, "/dl?f=../../../../etc/hosts")], ["web-path-traversal"]),
    "encoded traversal": ([req(0, "/dl?f=%2e%2e%2f%2e%2e%2fetc%2fhosts")], ["web-path-traversal"]),
    "etc passwd": ([req(0, "/dl?f=/etc/passwd")], ["web-path-traversal"]),
    "single dot-dot is fine": ([req(0, "/docs/../index.html")], []),
    "10 rejected logins": ([req(i, "/wp-login.php", 403, "POST") for i in range(10)], ["web-login-brute-force"]),
    "9 rejected logins": ([req(i, "/wp-login.php", 403, "POST") for i in range(9)], []),
    "successful logins are not brute force": ([req(i, "/wp-login.php", 302, "POST") for i in range(10)], []),
    "GET on login path is not brute force": ([req(i, "/login", 401) for i in range(10)], []),
    "sqlmap agent": ([req(0, "/", agent="sqlmap/1.7.10#stable (https://sqlmap.org)")], ["web-attack-tool-agent"]),
    "normal browsing": ([req(i, "/", agent=BROWSER) for i in range(30)], []),
}


@pytest.mark.parametrize("lines,expected", CASES.values(), ids=CASES.keys())
def test_rule_case(lines, expected):
    assert fired(lines) == sorted(expected)


def test_every_web_rule_has_a_positive_case():
    covered = {rule_id for _, expected in CASES.values() for rule_id in expected}
    assert covered == {rule.id for rule in RULES if rule.id.startswith("web-")}


def test_sample_attack_scenario():
    assert fired(SAMPLE.read_text().splitlines()) == sorted(
        ["web-attack-tool-agent", "web-login-brute-force", "web-path-traversal", "web-scanner", "web-sqli-attempt"]
    )
