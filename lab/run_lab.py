"""Run every attack-lab scenario against a running stack and score detection.

Usage (from the repo root, with the lab stack already up):
    python lab/run_lab.py --url http://localhost:8793 \
        --admin-username admin --admin-password '<the ADMIN_PASSWORD you started the stack with>'

For each scenario in lab/scenarios.yml this runs the scenario script inside
the `attacker` container, then polls GET /alerts?since=<scenario start>
every second (up to --timeout) until every expected rule id has fired.
Writes benchmarks/results/lab.json (schema: see docs/stage5-contract.md)
and prints a summary table. Exits non-zero if any expected rule never
fired for any scenario.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCENARIOS = ROOT / "lab" / "scenarios.yml"
DEFAULT_RESULTS = ROOT / "benchmarks" / "results" / "lab.json"
SCENARIO_GAP_S = 2.5
COMPOSE_FILES = ["docker-compose.yml", "docker-compose.lab.yml"]


# --- pure scoring logic (unit-tested without Docker or a network) -----------


def score_scenario(
    expected_rules: list[str],
    fetch_alerts,
    allowed_rules: list[str] = (),
    timeout: float = 90.0,
    poll_interval: float = 1.0,
    sleep=time.sleep,
    now=time.monotonic,
) -> dict:
    """Poll `fetch_alerts()` (-> list of alert dicts with a "rule_id" key)
    until every expected rule has appeared or `timeout` elapses.

    `allowed_rules` are known, legitimate side effects of the attack (e.g. a
    spraying run also trips the brute-force rule); they are reported as
    "overlapping_rules", not as unexpected.

    Returns {"detected", "missing_rules", "unexpected_rules", "overlapping_rules", "time_to_detect_s"}.
    `time_to_detect_s` only covers expected rules that were actually seen.
    """
    start = now()
    expected = set(expected_rules)
    seen_at: dict[str, float] = {}

    while True:
        elapsed = now() - start
        for alert in fetch_alerts():
            rid = alert["rule_id"]
            if rid not in seen_at:
                seen_at[rid] = elapsed
        if expected <= set(seen_at) or elapsed >= timeout:
            break
        sleep(poll_interval)

    missing = sorted(expected - set(seen_at))
    extra = set(seen_at) - expected
    overlapping = sorted(extra & set(allowed_rules))
    unexpected = sorted(extra - set(allowed_rules))
    time_to_detect = {rid: round(t, 3) for rid, t in seen_at.items() if rid in expected}
    return {
        "detected": not missing,
        "missing_rules": missing,
        "unexpected_rules": unexpected,
        "overlapping_rules": overlapping,
        "time_to_detect_s": time_to_detect,
    }


# --- HTTP + process glue (not exercised by unit tests) -----------------------


class ApiSession:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self._cookie = ""

    def _request(self, path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Cookie": self._cookie, "X-Requested-With": "mini-siem"}
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def login(self, username: str, password: str) -> None:
        req = urllib.request.Request(
            f"{self.url}/auth/login",
            data=json.dumps({"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                raise RuntimeError(f"login failed: {resp.status}")
            cookies = resp.headers.get_all("Set-Cookie") or []
            self._cookie = "; ".join(c.split(";")[0] for c in cookies)

    def alerts_since(self, since_iso: str) -> list[dict]:
        query = urllib.parse.urlencode({"since": since_iso, "limit": 500})
        status, body = self._request(f"/alerts?{query}")
        if status != 200:
            raise RuntimeError(f"GET /alerts failed: {status} {body}")
        return body


def wait_for_health(url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{url}/health", timeout=3)
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(1)
    raise RuntimeError(f"API never became healthy: {last_err}")


def compose(*args: str) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose"]
    for f in COMPOSE_FILES:
        cmd += ["-f", f]
    cmd += list(args)
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def wait_for_victim_ssh(timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = compose("exec", "-T", "attacker", "nc", "-z", "-w", "2", "victim", "22")
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("victim:22 never became reachable from attacker")


def run_scenario_script(script: str) -> None:
    result = compose("exec", "-T", "attacker", "sh", f"/lab/scenarios/{script}")
    print(result.stdout, end="")
    if result.returncode != 0:
        print(f"  (scenario script exited {result.returncode}; stderr: {result.stderr.strip()})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--timeout", type=float, default=90.0, help="per-scenario detection timeout (s)")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    parser.add_argument("--out", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--only", nargs="*", help="run only these scenario names")
    args = parser.parse_args()

    scenarios = yaml.safe_load(args.scenarios.read_text())["scenarios"]
    if args.only:
        scenarios = [s for s in scenarios if s["name"] in args.only]

    print(f"waiting for {args.url}/health ...")
    wait_for_health(args.url)
    session = ApiSession(args.url)
    session.login(args.admin_username, args.admin_password)

    print("waiting for victim:22 to be reachable from attacker ...")
    wait_for_victim_ssh()

    results = []
    for scenario in scenarios:
        name, script, expected = scenario["name"], scenario["script"], scenario["expected_rules"]
        print(f"\n=== {name} ===")
        # Syslog timestamps are truncated to whole seconds, so an event logged just after the
        # scenario started can carry a timestamp up to 1s earlier than our start. Pause first so
        # the previous scenario's alerts fall outside the widened window.
        time.sleep(SCENARIO_GAP_S)
        start_iso = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        run_scenario_script(script)
        outcome = score_scenario(
            expected,
            lambda: session.alerts_since(start_iso),
            scenario.get("allowed_rules", []),
            timeout=args.timeout,
        )
        results.append({"name": name, "expected_rules": expected, **outcome})
        status = "OK" if outcome["detected"] else "MISSING RULES"
        print(f"  {status}  missing={outcome['missing_rules']} unexpected={outcome['unexpected_rules']} overlap={outcome['overlapping_rules']}")
        print(f"  time_to_detect_s={outcome['time_to_detect_s']}")

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "scenarios": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print("\n--- summary ---")
    any_missing = False
    for r in results:
        print(f"{r['name']:24} detected={r['detected']!s:5} missing={r['missing_rules']} unexpected={r['unexpected_rules']}")
        any_missing = any_missing or bool(r["missing_rules"])
    print(f"\nwrote {args.out}")
    return 1 if any_missing else 0


if __name__ == "__main__":
    sys.exit(main())
