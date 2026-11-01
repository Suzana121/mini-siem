"""Offline benchmark of the processing pipeline: parse -> enrich -> detect -> score -> store.

No services needed. Each stage is timed separately over the same generated
log (benchmarks/gen_logs.py), processed in batches like the real pipeline.

    python -m benchmarks.bench_engine                       # 100k and 1M lines, 3 runs each
    python -m benchmarks.bench_engine --lines 20000 --runs 1

Method: every experiment runs in its own subprocess (so peak RSS is its own),
does one discarded warm-up pass over the first 50k lines, then `--runs` timed
passes with a fresh engine and store each; the median is reported. Besides the
headline sizes it measures how cost scales with the number of rules and the
size of the threat-intel feed, and checks detection against the generator's
ground truth. Result: benchmarks/results/engine.json.
"""

import argparse
import asyncio
import gc
import json
import os
import re
import resource
import statistics
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, Rule, load_rules
from app.enrichment import Enricher, GeoIP, ThreatIntel
from app.parsers.auth_log import parse_line
from app.scoring import score
from app.store import MemoryAlertStore
from benchmarks import machine
from benchmarks.gen_logs import BACKGROUND_RATE, DEFAULT_START, generate, synthetic_feed

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = Path(__file__).resolve().parent / "results"
STAGES = ["parse", "enrich", "detect", "score", "store"]
WARMUP_LINES = 50_000
# Order used when a smaller rule set is requested: a mix of single-event, threshold and sequence rules.
RULE_ORDER = [
    "ssh-brute-force", "ssh-password-spraying", "ssh-brute-force-success",
    "ssh-scanner", "ssh-root-login", "sudo-auth-failure",
]
_COPY = re.compile(r"-copy\d+$")


def build_rules(count: int | None) -> list[Rule]:
    """The shipped rules (count=None), a subset, or the shipped rules duplicated up to `count`."""
    rules = load_rules(DEFAULT_RULES_DIR)
    if count is None or count == len(rules):
        return rules
    by_id = {r.id: r for r in rules}
    if count < len(rules):
        ordered = [by_id[i] for i in RULE_ORDER if i in by_id]
        ordered += [r for r in rules if r.id not in RULE_ORDER]
        return ordered[:count]
    out = list(rules)
    copy = 1
    while len(out) < count:
        for rule in rules:
            if len(out) == count:
                break
            out.append(rule.model_copy(update={"id": f"{rule.id}-copy{copy}"}))
        copy += 1
    return out


def build_intel(extra_entries: int) -> tuple[ThreatIntel, float]:
    started = time.perf_counter()
    intel = ThreatIntel.from_directories([ROOT / "samples" / "intel"])
    if extra_entries:
        intel.add_feed("synthetic", synthetic_feed(extra_entries))
    return intel, time.perf_counter() - started


def _current_rss_mb() -> float | None:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())], capture_output=True, text=True)
    try:
        return int(out.stdout.strip()) / 1024
    except ValueError:
        return None


def _peak_rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024  # bytes vs KB


def run_pipeline(lines, rules, intel, reference, geoip_path=None, batch_size=10_000) -> dict:
    """One full pass. Returns per-stage seconds, event/alert counts and the raw alerts."""
    enricher = Enricher(GeoIP(geoip_path) if geoip_path else None, intel)
    engine = DetectionEngine(rules)
    store = MemoryAlertStore()
    loop = asyncio.new_event_loop()
    spent = dict.fromkeys(STAGES, 0.0)
    alerts, events_total, stored_new = [], 0, 0
    clock = time.perf_counter

    async def save_all(batch):
        return sum([1 for a in batch if (await store.save(a))[1]])

    try:
        for i in range(0, len(lines), batch_size):
            t0 = clock()
            events = [e for line in lines[i : i + batch_size] if (e := parse_line(line, reference))]
            t1 = clock()
            for e in events:
                enricher.enrich(e)
            t2 = clock()
            found = []
            for e in events:
                found.extend(engine.process(e))
            t3 = clock()
            for a in found:
                score(a)
            t4 = clock()
            stored_new += loop.run_until_complete(save_all(found))
            t5 = clock()
            for stage, dt in zip(STAGES, (t1 - t0, t2 - t1, t3 - t2, t4 - t3, t5 - t4)):
                spent[stage] += dt
            events_total += len(events)
            alerts.extend(found)
    finally:
        loop.close()
        if enricher.geoip:
            enricher.geoip.close()
    return {"seconds": spent, "events": events_total, "alerts": alerts, "stored": stored_new}


def check_detection(lines, truth, alerts, rule_ids) -> dict:
    """Recall of injected attacks and count of alerts that match no injected attack."""
    want = [t for t in truth if t["rule_id"] in rule_ids]
    seen = {(_COPY.sub("", a.rule_id), a.evidence[-1]) for a in alerts}
    expected = {(t["rule_id"], lines[t["line_index"]]) for t in want}
    per_rule: dict[str, dict] = {}
    for t in want:
        row = per_rule.setdefault(t["rule_id"], {"injected": 0, "detected": 0})
        row["injected"] += 1
        row["detected"] += (t["rule_id"], lines[t["line_index"]]) in seen
    detected = sum(r["detected"] for r in per_rule.values())
    extra: dict[str, int] = {}
    for a in alerts:
        if (_COPY.sub("", a.rule_id), a.evidence[-1]) not in expected:
            base = _COPY.sub("", a.rule_id)
            extra[base] = extra.get(base, 0) + 1
    return {
        "injected": len(want),
        "detected": detected,
        "recall": detected / len(want) if want else None,
        "extra_alerts": sum(extra.values()),
        "extra_by_rule": extra,
        "per_rule": per_rule,
    }


def run_experiment(
    name: str,
    n_lines: int,
    runs: int = 3,
    rules_count: int | None = None,
    intel_entries: int = 0,
    seed: int = 1,
    attack_ratio: float = 0.02,
    batch_size: int = 10_000,
    geoip_path: str | None = None,
) -> dict:
    """Measure one configuration in this process (see module docstring for the method)."""
    started = time.perf_counter()
    lines, truth = generate(n_lines, seed=seed, attack_ratio=attack_ratio)
    gen_s = time.perf_counter() - started
    reference = DEFAULT_START + timedelta(seconds=n_lines / BACKGROUND_RATE + 3600)
    rules = build_rules(rules_count)
    intel, intel_build_s = build_intel(intel_entries)
    gc.collect()
    rss_setup = _current_rss_mb()

    run_pipeline(lines[:WARMUP_LINES], rules, intel, reference, geoip_path, batch_size)  # discarded
    results = []
    for _ in range(runs):
        gc.collect()
        results.append(run_pipeline(lines, rules, intel, reference, geoip_path, batch_size))

    totals = [sum(r["seconds"].values()) for r in results]
    median_total = statistics.median(totals)
    events = results[-1]["events"]
    n_alerts = len(results[-1]["alerts"])
    stages = {}
    for stage in STAGES:
        samples = [r["seconds"][stage] for r in results]
        median = statistics.median(samples)
        denominator = n_lines if stage == "parse" else events  # parse sees every line, the rest see parsed events
        stages[stage] = {
            "median_s": median,
            "runs_s": samples,
            "us_per_item": median / denominator * 1e6 if denominator else None,
            "share": median / median_total if median_total else None,
        }
        if stage in ("score", "store"):  # these only see alerts, so per-event cost hides the real unit cost
            stages[stage]["us_per_alert"] = median / n_alerts * 1e6 if n_alerts else None
    base_ids = {r.id for r in build_rules(None)}
    last = results[-1]
    return {
        "name": name,
        "lines": n_lines,
        "events": events,
        "unparsed_lines": n_lines - events,
        "rules": len(rules),
        "intel_entries": sum(intel.sizes.values()),
        "intel_build_s": intel_build_s,
        "generate_s": gen_s,
        "runs": runs,
        "warmup_lines": min(WARMUP_LINES, n_lines),
        "median_total_s": median_total,
        "total_runs_s": totals,
        "lines_per_s": n_lines / median_total if median_total else None,
        "events_per_s": events / median_total if median_total else None,
        "stages": stages,
        "alerts": len(last["alerts"]),
        "stored_alerts": last["stored"],
        "rss_setup_mb": rss_setup,
        "peak_rss_mb": _peak_rss_mb(),
        "correctness": check_detection(lines, truth, last["alerts"], base_ids & {r.id for r in rules}),
    }


def _isolated(spec: dict) -> dict:
    out = subprocess.run(
        [sys.executable, "-m", "benchmarks.bench_engine", "--worker", json.dumps(spec)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if out.returncode != 0:
        raise RuntimeError(f"worker failed for {spec['name']}:\n{out.stderr[-2000:]}")
    return json.loads(out.stdout.strip().splitlines()[-1])


def _print_row(r: dict) -> None:
    s = r["stages"]
    c = r["correctness"]
    recall = "n/a" if c["recall"] is None else f"{c['recall']:.0%}"
    print(
        f"  {r['name']:<22} {r['lines_per_s']:>9,.0f} lines/s | us/item "
        + " ".join(f"{k} {s[k]['us_per_item']:.1f}" for k in STAGES)
        + f" | peak RSS {r['peak_rss_mb']:.0f} MB | recall {recall}, extra {c['extra_alerts']}",
        flush=True,
    )


def main(argv: list[str] | None = None) -> dict | None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--lines", type=int, nargs="+", default=[100_000, 1_000_000], help="headline log sizes")
    p.add_argument("--runs", type=int, default=3, help="timed runs per experiment (median reported)")
    p.add_argument("--scaling-lines", type=int, help="log size for the rule/intel scaling tests (default: smallest --lines)")
    p.add_argument("--skip-scaling", action="store_true")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--attack-ratio", type=float, default=0.02)
    p.add_argument("--batch-size", type=int, default=10_000)
    p.add_argument("--geoip", help="optional MaxMind .mmdb to include GeoIP in the enrich stage")
    p.add_argument("--out", type=Path, default=RESULTS_DIR / "engine.json")
    p.add_argument("--no-isolate", action="store_true", help="run in-process (peak RSS then covers the whole run)")
    p.add_argument("--worker", help=argparse.SUPPRESS)
    args = p.parse_args(argv)

    if args.worker:
        print(json.dumps(run_experiment(**json.loads(args.worker))))
        return None

    common = {
        "runs": args.runs, "seed": args.seed, "attack_ratio": args.attack_ratio,
        "batch_size": args.batch_size, "geoip_path": args.geoip,
    }
    scaling_lines = args.scaling_lines or min(args.lines)
    plan = {"headline": [], "rules_scaling": [], "intel_scaling": []}
    for n in args.lines:
        plan["headline"].append({"name": f"{n:,} lines", "n_lines": n, **common})
    if not args.skip_scaling:
        for count in (1, 6, 12, 48):
            plan["rules_scaling"].append(
                {"name": f"{count} rules", "n_lines": scaling_lines, "rules_count": count, **common}
            )
        for entries in (100, 10_000, 1_000_000):
            plan["intel_scaling"].append(
                {"name": f"intel {entries:,}", "n_lines": scaling_lines, "intel_entries": entries, **common}
            )

    header = machine.collect(include_docker=False)
    document = {
        "tool": "bench_engine",
        "machine": header,
        "params": {k: v for k, v in vars(args).items() if k not in ("worker", "out")} | {"out": str(args.out)},
        "scaling_lines": scaling_lines,
        "method": (
            f"one discarded warm-up pass over the first {WARMUP_LINES:,} lines, then {args.runs} timed pass(es) "
            "with a fresh engine/store per pass; median reported; each experiment in its own subprocess"
            if not args.no_isolate
            else "in-process; one discarded warm-up pass, then timed passes; median reported"
        ),
    }
    for section, specs in plan.items():
        if not specs:
            continue
        print(f"{section}:", flush=True)
        document[section] = []
        for spec in specs:
            row = run_experiment(**spec) if args.no_isolate else _isolated(spec)
            document[section].append(row)
            _print_row(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2))
    print(f"wrote {args.out}")
    return document


if __name__ == "__main__":
    main()
