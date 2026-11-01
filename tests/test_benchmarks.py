"""Benchmark tooling: generator determinism and ground truth, engine bench, report, e2e logic.

The e2e benchmark is exercised against the real FastAPI app in-process (no Docker).
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.auth import MemoryAuthStore, ensure_admin
from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.enrichment import Enricher, ThreatIntel
from app.events import MemoryEventStore
from app.main import create_app
from app.parsers.auth_log import parse_line
from app.pipeline import Pipeline
from app.sinks import MemorySink
from app.store import MemoryAlertStore
from benchmarks import bench_e2e, bench_engine, machine, report
from benchmarks.gen_logs import BACKGROUND_RATE, DEFAULT_START, generate, synthetic_feed

pytestmark = pytest.mark.anyio

RULES = load_rules(DEFAULT_RULES_DIR)
REFERENCE = DEFAULT_START + timedelta(days=2)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --- generator -----------------------------------------------------------------


def test_generator_is_deterministic_and_seeded():
    a = generate(3000, seed=5)
    assert a == generate(3000, seed=5)
    assert a != generate(3000, seed=6)


def test_generator_size_order_and_parseability():
    lines, truth = generate(5000, seed=2)
    assert len(lines) == 5000 and truth
    events = [parse_line(line, REFERENCE) for line in lines]
    stamps = [e.timestamp for e in events if e]
    assert stamps == sorted(stamps)
    unparsed = sum(e is None for e in events) / len(lines)
    assert 0.05 < unparsed < 0.25  # realistic: some lines are not security-relevant
    assert all(0 <= t["line_index"] < len(lines) for t in truth)


def test_generator_covers_every_rule_that_needs_no_feed():
    _, truth = generate(20_000, seed=1)
    covered = {t["rule_id"] for t in truth}
    expected = {r.id for r in RULES} - {"ssh-login-threat-intel"}
    assert covered == expected


def test_attack_ratio_zero_means_no_attacks():
    lines, truth = generate(3000, attack_ratio=0)
    assert truth == [] and len(lines) == 3000


def test_ground_truth_is_valid_and_background_is_quiet():
    """The real engine fires on every injected attack, and on nothing else."""
    lines, truth = generate(20_000, seed=3)
    engine = DetectionEngine(RULES)
    alerts = []
    for line in lines:
        if event := parse_line(line, REFERENCE):
            alerts += engine.process(event)
    result = bench_engine.check_detection(lines, truth, alerts, {r.id for r in RULES})
    assert result["detected"] == result["injected"] > 0, result["per_rule"]
    assert result["extra_alerts"] == 0, result["extra_by_rule"]


def test_synthetic_feed_size_and_isolation():
    feed = synthetic_feed(1000)
    assert len(feed) == 1000 and feed == synthetic_feed(1000)
    intel = ThreatIntel({"synthetic": feed})
    lines, _ = generate(2000)
    ips = {e.source.ip for line in lines if (e := parse_line(line, REFERENCE)) and e.source.ip}
    assert not any(intel.lookup(ip) for ip in ips)


# --- machine + engine bench ----------------------------------------------------------


def test_machine_header_fields():
    m = machine.collect()
    for key in ("cpu_model", "cpu_logical_cores", "ram_bytes", "os", "python", "commit", "generated_at"):
        assert key in m
    assert m["cpu_logical_cores"] and m["python"].startswith("CPython")


def test_build_rules_subset_and_duplication():
    base = len(RULES)
    assert len(bench_engine.build_rules(1)) == 1
    assert len(bench_engine.build_rules(6)) == 6
    assert len(bench_engine.build_rules(None)) == base
    big = bench_engine.build_rules(48)
    assert len(big) == 48 and len({r.id for r in big}) == 48
    assert big[base].selects is not None and big[base].id.endswith("-copy1")


def test_run_experiment_small():
    row = bench_engine.run_experiment("t", 6000, runs=2, intel_entries=500)
    assert row["lines"] == 6000 and row["events"] < 6000
    assert set(row["stages"]) == set(bench_engine.STAGES)
    assert all(len(s["runs_s"]) == 2 for s in row["stages"].values())
    assert row["lines_per_s"] > 0 and row["peak_rss_mb"] > 0
    assert row["intel_entries"] >= 500
    assert row["correctness"]["recall"] == 1.0 and row["correctness"]["extra_alerts"] == 0
    json.dumps(row)  # serialisable


def test_rule_duplicates_do_not_count_as_extra_alerts():
    row = bench_engine.run_experiment("dup", 6000, runs=1, rules_count=24)
    assert row["rules"] == 24 and row["correctness"]["extra_alerts"] == 0


def test_main_writes_engine_json(tmp_path):
    out = tmp_path / "engine.json"
    doc = bench_engine.main(["--lines", "4000", "--runs", "1", "--skip-scaling", "--no-isolate", "--out", str(out)])
    assert json.loads(out.read_text())["headline"][0]["lines"] == 4000
    assert doc["machine"]["cpu_logical_cores"]


# --- report --------------------------------------------------------------------------


def test_report_with_no_results(tmp_path):
    text = report.render(tmp_path)
    assert text.count("_not run_") == 3
    assert "Benchmark results" in text


def test_report_renders_engine_numbers_from_json(tmp_path):
    out = tmp_path / "engine.json"
    bench_engine.main(["--lines", "3000", "--runs", "1", "--skip-scaling", "--no-isolate", "--out", str(out)])
    lab = {
        "generated_at": "2026-11-01T00:00:00Z", "commit": "abc123def456",
        "scenarios": [{"name": "brute-force", "expected_rules": ["ssh-brute-force"], "detected": True,
                       "missing_rules": [], "unexpected_rules": [], "time_to_detect_s": {"ssh-brute-force": 2.5}}],
    }
    (tmp_path / "lab.json").write_text(json.dumps(lab))
    text = report.render(tmp_path)
    data = json.loads(out.read_text())["headline"][0]
    assert f"{data['lines_per_s']:,.0f}" in text  # numbers come from the file
    assert "ssh-brute-force: 2.5s" in text
    assert text.count("_not run_") == 1  # only e2e is missing


# --- e2e logic -----------------------------------------------------------------------


def test_percentile_interpolates():
    assert bench_e2e.percentile([], 50) is None
    assert bench_e2e.percentile([5], 99) == 5
    assert bench_e2e.percentile([1, 2, 3, 4], 50) == 2.5
    assert bench_e2e.percentile(list(range(101)), 95) == 95


def test_remote_hosts_are_refused():
    assert bench_e2e.is_local("http://localhost:8000") and bench_e2e.is_local("http://127.0.0.1:8000")
    assert not bench_e2e.is_local("https://siem.example.com")
    base = ["--admin-user", "a", "--admin-password", "b"]
    with pytest.raises(SystemExit):
        bench_e2e.parse_args(["--url", "http://10.1.2.3:8000", *base])
    assert bench_e2e.parse_args(["--url", "http://10.1.2.3:8000", "--allow-remote", *base]).allow_remote


def test_attacker_ips_are_unique_and_in_benchmark_range():
    ips = {bench_e2e.attacker_ip(i, 12345) for i in range(5000)}
    assert len(ips) == 5000
    assert all(ip.startswith(("198.18.", "198.19.")) for ip in ips)


def test_burst_lines_trigger_brute_force():
    now = datetime.now(timezone.utc)
    engine = DetectionEngine(RULES)
    alerts = []
    for line in bench_e2e.burst_lines("198.18.1.1", now):
        alerts += engine.process(parse_line(line, now + timedelta(minutes=1)))
    assert [a.rule_id for a in alerts] == ["ssh-brute-force"]


async def test_e2e_phases_against_in_process_app(tmp_path):
    store = MemoryAlertStore()
    enricher = Enricher(intel=ThreatIntel())
    sink = MemorySink(Pipeline(DetectionEngine(RULES), store, enricher))
    auth = MemoryAuthStore()
    await ensure_admin(auth, "admin", "correct-horse-battery")
    app = create_app(sink, store, RULES, MemoryEventStore(), auth)
    out = tmp_path / "e2e.json"
    argv = [
        "--admin-user", "admin", "--admin-password", "correct-horse-battery",
        "--batch-sizes", "100", "1000", "--ingest-lines", "2000", "--drain-lines", "2000",
        "--bursts", "4", "--burst-interval", "0.05", "--background-rate", "100",
        "--api-alerts", "30", "--api-runs", "3", "--poll-ms", "5", "--timeout", "10", "--out", str(out),
    ]
    a = bench_e2e.parse_args(argv)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=60) as client:
            result = await bench_e2e.run(a, client)

    assert result["errors"] == []
    assert [r["batch_size"] for r in result["ingest"]] == [100, 1000]
    assert all(r["lines_per_s"] > 0 for r in result["ingest"])
    assert result["drain"]["pipeline_lines_per_s"] > 0
    assert result["latency"]["missed"] == 0 and result["latency"]["p50_ms"] is not None
    assert result["api"] and all(r["stored_alerts"] >= 30 for r in result["api"])
    assert "admin_password" not in json.dumps(result["params"])
    (tmp_path / "e2e.json").write_text(json.dumps(result))
    text = report.render(tmp_path)
    assert "Ingest-to-alert latency" in text and "API read latency" in text
