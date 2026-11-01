"""Render benchmarks/RESULTS.md from the JSON files in benchmarks/results/.

    python -m benchmarks.report

Reads engine.json, e2e.json and (if present) lab.json. A missing file renders
as "not run". Every number comes from those files; RESULTS.md is never edited by hand.
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"
OUTPUT = HERE / "RESULTS.md"
NOT_RUN = "_not run_"


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _n(value, digits: int = 0, unit: str = "") -> str:
    if value is None:
        return "–"
    return f"{value:,.{digits}f}{unit}"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return out + [""]


def machine_lines(m: dict | None) -> list[str]:
    if not m:
        return []
    ram = f"{m['ram_bytes'] / 2**30:.0f} GiB RAM" if m.get("ram_bytes") else "RAM unknown"
    cores = f"{m.get('cpu_physical_cores') or '?'} physical / {m.get('cpu_logical_cores') or '?'} logical cores"
    commit = (m.get("commit") or "unknown")[:10] + (" (dirty tree)" if m.get("dirty_tree") else "")
    lines = [
        f"- Machine: {m.get('cpu_model') or 'unknown CPU'}, {cores}, {ram}",
        f"- OS: {m.get('os')}; {m.get('python')}; pydantic {m.get('pydantic')}",
        f"- Commit: `{commit}`; measured {m.get('generated_at')}",
    ]
    d = m.get("docker")
    if d:
        lines.append(
            f"- Docker: {d.get('OperatingSystem')} {d.get('ServerVersion')}, {d.get('NCPU')} CPUs, "
            f"{(d.get('MemTotal') or 0) / 2**30:.1f} GiB memory available to containers"
        )
    return lines


def _engine_rows(rows: list[dict], first: str) -> list[list[str]]:
    out = []
    for r in rows:
        s, c = r["stages"], r["correctness"]
        recall = "–" if c["recall"] is None else f"{c['recall']:.1%} ({c['detected']}/{c['injected']})"
        out.append([
            r["name"], _n(r["lines_per_s"]),
            *(_n(s[k]["us_per_item"], 1) for k in ("parse", "enrich", "detect")),
            _n(r["peak_rss_mb"]), recall, str(c["extra_alerts"]),
        ])
    return out


def render_engine(d: dict | None) -> list[str]:
    out = ["## Engine (offline)", ""]
    if not d:
        return out + [NOT_RUN, ""]
    out += machine_lines(d.get("machine"))
    out += ["- Method: " + d.get("method", ""), ""]
    headers = ["config", "lines/s", "parse µs/line", "enrich µs/event", "detect µs/event", "peak RSS MB", "attack recall", "extra alerts"]
    if d.get("headline"):
        out += ["### Throughput by log size", ""]
        out += _table(headers, _engine_rows(d["headline"], "size"))
        out += ["Score and store only see alerts; their cost per alert:", ""]
        out += _table(
            ["config", "alerts", "stored (after dedup)", "score µs/alert", "store µs/alert", "store share of total"],
            [[r["name"], _n(r["alerts"]), _n(r["stored_alerts"]),
              _n(r["stages"]["score"].get("us_per_alert"), 1), _n(r["stages"]["store"].get("us_per_alert"), 1),
              _n((r["stages"]["store"].get("share") or 0) * 100, 1, "%")] for r in d["headline"]],
        )
    if d.get("rules_scaling"):
        out += [f"### Scaling with rule count ({_n(d.get('scaling_lines'))} lines)", ""]
        out += _table(headers, _engine_rows(d["rules_scaling"], "rules"))
    if d.get("intel_scaling"):
        out += [f"### Scaling with threat-intel feed size ({_n(d.get('scaling_lines'))} lines)", ""]
        out += _table(headers + ["intel build s"], [
            row + [_n(r["intel_build_s"], 1)] for row, r in zip(_engine_rows(d["intel_scaling"], "intel"), d["intel_scaling"])
        ])
    out += [
        "Peak RSS includes the generated log held in memory and the (empty-ish) interpreter; compare rows, not absolutes.",
        "",
    ]
    return out


def render_e2e(d: dict | None) -> list[str]:
    out = ["## End to end (docker compose stack)", ""]
    if not d:
        return out + [NOT_RUN, ""]
    out += machine_lines(d.get("machine")) + [""]
    if d.get("ingest"):
        out += ["### Ingest throughput (`POST /ingest`, accepted = parsed and queued)", ""]
        out += _table(
            ["batch size", "clients", "lines", "lines/s", "requests/s", "request p50 ms", "p95 ms", "p99 ms"],
            [[_n(r["batch_size"]), str(r["clients"]), _n(r["lines"]), _n(r["lines_per_s"]), _n(r["requests_per_s"], 1),
              _n(r["request_latency"]["p50_ms"], 1), _n(r["request_latency"]["p95_ms"], 1), _n(r["request_latency"]["p99_ms"], 1)]
             for r in d["ingest"]],
        )
    if d.get("drain"):
        r = d["drain"]
        out += ["### Detector drain", ""]
        if "error" in r:
            out += [f"Failed: {r['error']}", ""]
        else:
            out += _table(
                ["lines", "ingest s", "drain s after ingest", "total s", "pipeline lines/s"],
                [[_n(r["lines"]), _n(r["ingest_seconds"], 1), _n(r["drain_seconds_after_ingest"], 1),
                  _n(r["total_seconds"], 1), _n(r["pipeline_lines_per_s"])]],
            )
    if d.get("latency"):
        r = d["latency"]
        out += ["### Ingest-to-alert latency", ""]
        out += _table(
            ["bursts", "missed", "background lines/s", "p50 ms", "p95 ms", "p99 ms", "max ms"],
            [[_n(r["bursts"]), _n(r["missed"]), _n(r["background_lines_per_s_target"]),
              _n(r["p50_ms"], 0), _n(r["p95_ms"], 0), _n(r["p99_ms"], 0), _n(r["max_ms"], 0)]],
        )
        out += [f"Poll resolution {r['poll_ms']} ms; p99 over {r['n']} samples is indicative only.", ""]
    if d.get("api"):
        out += ["### API read latency", ""]
        rows = [r for r in d["api"] if "error" not in r]
        if rows:
            out += _table(
                ["endpoint", "stored alerts", "response KB", "p50 ms", "p95 ms", "p99 ms"],
                [[r["endpoint"], _n(r["stored_alerts"]), _n(r["bytes"] / 1024, 1), _n(r["p50_ms"], 1),
                  _n(r["p95_ms"], 1), _n(r["p99_ms"], 1)] for r in rows],
            )
        else:
            out += [f"Failed: {d['api'][0].get('error')}", ""]
    for e in d.get("errors", []):
        out += [f"Phase `{e['phase']}` failed: {e['error']}", ""]
    return out


def render_lab(d: dict | None) -> list[str]:
    out = ["## Attack lab", ""]
    if not d:
        return out + [NOT_RUN, ""]
    out += [f"- Commit: `{(d.get('commit') or 'unknown')[:10]}`; measured {d.get('generated_at')}", ""]
    rows = []
    for s in d.get("scenarios", []):
        ttd = s.get("time_to_detect_s") or {}
        rows.append([
            s["name"], ", ".join(s["expected_rules"]) or "none (must stay quiet)",
            "yes" if s["detected"] else "**NO**",
            ", ".join(f"{r}: {t:.1f}s" for r, t in sorted(ttd.items())) or "–",
            ", ".join(s["missing_rules"]) or "–", ", ".join(s["unexpected_rules"]) or "–",
        ])
    out += _table(["scenario", "expected rules", "detected", "time to detect", "missing", "unexpected"], rows)
    return out


def render(results_dir: Path = RESULTS_DIR) -> str:
    parts = [
        "# Benchmark results", "",
        "Generated by `python -m benchmarks.report` from `benchmarks/results/*.json`; do not edit by hand.",
        "See `benchmarks/README.md` for what each number means and its caveats.", "",
    ]
    parts += render_engine(_load(results_dir / "engine.json"))
    parts += render_e2e(_load(results_dir / "e2e.json"))
    parts += render_lab(_load(results_dir / "lab.json"))
    return "\n".join(parts).rstrip() + "\n"


def main() -> None:
    OUTPUT.write_text(render())
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
