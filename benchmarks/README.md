# Benchmarks

Numbers for the processing pipeline, measured by tools in this directory.
`RESULTS.md` is generated from `results/*.json`; never edit it by hand.

## Run

```bash
# 1. Offline engine benchmark (no services). 100k and 1M lines, 3 runs, plus scaling tests. A few minutes.
python -m benchmarks.bench_engine
python -m benchmarks.bench_engine --lines 20000 --runs 1      # quick check (~20 s)

# 2. End-to-end, needs the stack up (docker compose up -d). Localhost only unless --allow-remote.
python -m benchmarks.bench_e2e --url http://localhost:8000 \
    --admin-user admin --admin-password '...'                  # or ADMIN_USERNAME / ADMIN_PASSWORD
python -m benchmarks.bench_e2e --phases latency api ...        # run a subset

# 3. Render benchmarks/RESULTS.md (also picks up results/lab.json from lab/run_lab.py)
python -m benchmarks.report
```

`python -m benchmarks.gen_logs`-style use from code: `generate(n_lines, seed, attack_ratio, start)`
returns `(lines, ground_truth)`; same arguments give identical output.
`python -m benchmarks.machine` prints the machine header every result file embeds.

## What is measured

**Engine** (`bench_engine`): parse -> enrich -> detect -> score -> store, each stage timed separately
over generated auth.log traffic (about 2% attack lines, injected as bursts that satisfy the real
rules), in batches of 10,000 like the real pipeline. Reports lines/s, per-stage microseconds, peak RSS,
scaling with rule count (1, 6, 12, 48 duplicated) and threat-intel feed size (100, 10^4, 10^6 entries),
and checks detection against the generator's ground truth (recall of injected attacks, count of
alerts that match no injected attack).

**End to end** (`bench_e2e`):
- *ingest*: lines/s `POST /ingest` accepts per batch size with concurrent clients. "Accepted" = parsed
  and queued on the Redis stream; detection has not necessarily happened yet.
- *drain*: backlog ingested, then time until the single detector has worked through it, detected by a
  sentinel attack burst sent last (ordered stream, one consumer).
- *latency*: ingest-to-alert latency p50/p95/p99, for known brute-force bursts sent at a steady
  background rate and polled for on `GET /alerts`.
- *api*: read latency of `/alerts`, `/stats/summary`, `/stats/attack` with at least 10,000 stored alerts.

## Method and honesty rules

- A warm-up pass (first 50k lines) is discarded; the median of `--runs` (default 3) passes is reported,
  each with a fresh engine and store. All raw per-run times are kept in the JSON.
- Each engine experiment runs in its own subprocess so peak RSS belongs to that experiment alone.
- Every result file embeds CPU, cores, RAM, OS, Python, pydantic, git commit and dirty flag (and Docker
  limits for e2e). Quote numbers with that header.
- No numbers are hard-coded anywhere; the report only formats what is in the JSON.

## Reading the numbers, and caveats

- Single-threaded: the engine keeps state in one process (see the README design notes), so lines/s is
  per detector worker, not per machine.
- `parse` is per log line (including lines the parser ignores); `enrich` and `detect` are per parsed
  event. `score` and `store` only see alerts, so they are shown per alert as well.
- The generated traffic is synthetic. Its mix (logins, sudo, cron, noise) is plausible but real hosts
  differ; attack density (`--attack-ratio`) changes the share of stateful work and the alert count.
- `MemoryAlertStore.save` scans all stored alerts for a dedup match, so its cost grows with the number
  of alerts; the Postgres store used by the stack behaves differently. Treat the store stage as the
  in-memory reference, not as a prediction for Postgres (that is what the e2e phases measure).
- The synthetic threat-intel feed is stored as per-prefix-length hash tables, so lookup cost is nearly
  independent of feed size; the cost of a large feed is memory and load time (see `intel build s`).
  The feed uses address space the generator never emits, so it never produces hits or extra alerts.
- Enrichment runs without GeoIP unless `--geoip` is given (the database is not in the repo).
- e2e latency resolution is the poll interval (default 20 ms), and p99 over 60 bursts is a rough
  estimate. Docker Desktop on macOS adds virtualisation overhead; compare runs on the same setup.
- BSD syslog timestamps have no year; the generator and the e2e tool keep every run inside one
  calendar year relative to the parse time.
