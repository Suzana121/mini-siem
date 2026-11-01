# Mini-SIEM

A lightweight Security Information and Event Management pipeline: ingest raw logs, normalize them to a common schema, run detection rules mapped to MITRE ATT&CK, and surface alerts.

> **Status:** Stage 5 of 5 — attack lab and benchmarks, on top of stage 4: React dashboard (alert triage, raw-event drill-down, ATT&CK heatmap) with user accounts and roles, on top of enrichment, risk scoring, deduplicated alert storage and signed webhooks.

## Architecture

```
log shippers ──► Ingest API (FastAPI) ──► parser ──► Redis Stream "siem:events"
                       ▲                                     │ consumer group
                       │                                     ▼
        GET/PATCH /alerts                            detection worker
                       │          enrich (GeoIP, threat intel) → detect (YAML rules)
                       │          → score (0-100) → store/dedup → notify
                       ▼                                     │
                  PostgreSQL ◄──────── alerts ───────────────┤
                                                             └──► webhooks (Slack / JSON, HMAC-signed)
```

Every parser emits a `NormalizedEvent` (ECS-inspired: `event.category/action/outcome`, `user`, `source.ip`, `host`, `process`), so detection rules are written once against a stable set of fields, not per log format.

## Detection rules

Rules live in [`rules/`](rules) as YAML, in a small Sigma-inspired dialect. Three kinds:

```yaml
# Threshold: N matching events per group within a window
id: ssh-brute-force
severity: medium
mitre:
  - { id: T1110.001, name: "Brute Force: Password Guessing", tactic: Credential Access }
match:
  event.action: ssh_login
  event.outcome: failure
threshold: { count: 5, window: 60s, group_by: [source.ip] }
```

```yaml
# Sequence: ordered steps for the same group within a window
sequence:
  window: 10m
  group_by: [source.ip]
  steps:
    - { name: failures, match: { event.action: ssh_login, event.outcome: failure }, min_count: 5 }
    - { name: success,  match: { event.action: ssh_login, event.outcome: success } }
```

Selections AND their keys, OR list values, compare case-insensitively, and support Sigma modifiers (`|contains`, `|startswith`, `|endswith`, `|re`) plus `exclude`. Thresholds can count `distinct` values (e.g. usernames, for password spraying). Windows use **event time**, so replaying an old log gives the same alerts as watching it live.

| Rule | Severity | ATT&CK |
|---|---|---|
| `ssh-brute-force` — 5+ failed logins from one IP in 60s | medium | T1110.001 |
| `ssh-password-spraying` — 5+ distinct usernames from one IP in 5m | high | T1110.003 |
| `ssh-brute-force-success` — failures followed by a successful login | critical | T1110, T1078 |
| `ssh-scanner` — repeated banner-less connections | low | T1046 |
| `ssh-root-login` — direct SSH login as root | high | T1078.003 |
| `sudo-auth-failure` — wrong sudo password | medium | T1548.003 |
| `sudo-credential-file-access` — sudo on /etc/shadow, /etc/sudoers | high | T1003.008 |
| `sudo-root-shell` — interactive root shell via sudo | medium | T1548.003 |
| `local-account-created` | medium | T1136.001 |
| `privileged-group-change` — user added to sudo/wheel/docker… | high | T1098 |
| `backdoor-account` — new account made admin within 10m | critical | T1136.001, T1098 |
| `ssh-login-threat-intel` — successful login from an IP on a threat-intel feed | critical | T1078 |

Every rule has positive and negative test cases written as real log lines ([`tests/test_detection_rules.py`](tests/test_detection_rules.py)), and a test fails if any rule lacks a positive case.

## Enrichment & alerting

- **Threat intel.** Every `*.txt` file in `intel/` is a feed (one IP/CIDR per line, `#`/`;` comments). `python scripts/update_intel.py` downloads FireHOL Level 1, Spamhaus DROP and blocklist.de SSH. Lookups use one hash table per prefix length, so cost doesn't grow with list size. Matches set `threat.listed` / `threat.feeds`, which rules can match on.
- **GeoIP.** `python scripts/download_geoip.py` fetches the free DB-IP City Lite database (MaxMind format, CC BY 4.0). Private and documentation ranges are marked `source.internal` and skipped.
- **Risk score.** Rule severity sets a base score; threat-intel hits, external sources and the root account add points. Each point comes with a readable reason in `risk_factors`.
- **Deduplication.** Repeats of an open alert (same rule, host and grouping key within `DEDUP_WINDOW`, default 15m) are merged: `occurrences` and evidence grow, and no new notification is sent.
- **Webhooks.** New alerts at or above `WEBHOOK_MIN_SEVERITY` are POSTed to `WEBHOOK_URLS` (Slack-formatted for Slack URLs, JSON otherwise), with retries and exponential backoff. With `WEBHOOK_SECRET`, each request carries `X-MiniSIEM-Signature: sha256=<HMAC>`. Try it with `python scripts/webhook_receiver.py --secret s3cret`.

All settings are environment variables, documented in [`app/config.py`](app/config.py). Without a database, GeoIP file or feeds, everything still runs, just without that piece.

## Dashboard & access control

The dashboard (React + TypeScript, source in [`web/`](web)) is served at `/` by the API container: alerts with KPIs, filters and search; per-alert detail with risk factors, evidence and **related raw events** from the event store (`EVENT_RETENTION`, default 7d); an **ATT&CK heatmap** of tactics and techniques; and an Admin page for users (roles, disable, password reset) and API keys.

- **Roles.** `viewer` reads, `analyst` also triages (acknowledge/close), `admin` also manages users and API keys.
- **First admin.** Set `ADMIN_USERNAME` / `ADMIN_PASSWORD` (12+ characters) before the first start, or run `python -m scripts.create_user NAME --role admin`.
- **Sessions.** Passwords are argon2id hashes; sessions are opaque tokens stored hashed, in an HttpOnly, SameSite=Strict cookie, with a CSRF header on writes and login throttling. Set `COOKIE_SECURE=true` behind TLS (the compose file defaults to `false` for local HTTP).
- **Log shippers** authenticate with an API key (Admin page): `python scripts/ship_logs.py samples/auth.log --api-key msk_...` or `SIEM_API_KEY`. Transient failures (network, 5xx, 429) are retried with backoff; a permanent rejection (revoked key, unknown source, malformed batch) stops the shipper with a clear message instead of retrying forever. Re-sending the same lines is safe: the event store ignores exact duplicates (same source, host, timestamp and text) and alert dedup merges repeats.
- **Frontend development:** `cd web && npm ci && npm run dev` (proxies to the API on :8000); `npm test`, `npm run build`.

## Attack lab

[`lab/`](lab) runs real attacks against a real sshd and checks that the SIEM catches them. Everything lives in docker compose: a `victim` (OpenSSH, rsyslog, sudo), an `attacker` (hydra, nmap, ssh clients) on an isolated `internal` network with no route out, and a `shipper` that tails the victim's `auth.log` into `/ingest`.

```bash
ADMIN_PASSWORD='choose-a-long-passphrase' docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab up -d --build
python lab/run_lab.py --admin-username admin --admin-password 'choose-a-long-passphrase'
```

Eight scenarios (brute force, password spraying, brute force then success, scanning, root login, privilege escalation, persistence, benign noise) run in turn; the runner reports whether each expected rule fired, how long it took (attack start to alert visible), and any unexpected alerts. It exits non-zero if an expected rule is missed, so it works as a regression test. Results: [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md). Details: [`lab/README.md`](lab/README.md).

Running it against real OpenSSH 9.2 found a parser gap: scanners that hang up before sending a banner are logged as `Connection closed by <ip> port <n>` rather than the older "Did not receive identification string", so `ssh-scanner` never fired on real traffic until the parser learned the newer wording.

## Performance

Measured by [`benchmarks/`](benchmarks) (offline engine benchmark, end-to-end stack benchmark, reproducible with seeded log generation). Full tables, hardware and method are in [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md); regenerate with `python -m benchmarks.bench_engine` and `python -m benchmarks.report`.

Apple M2 Max, Docker Desktop (12 CPUs), single detector worker, 12 rules:

| What | Result |
|---|---|
| Detection engine, offline (parse → enrich → detect → score → store) | ~27.6k lines/s at 100k lines, ~23.3k lines/s at 1M lines (peak 496 MB); 100% of injected attacks found, 0 extra alerts |
| Where the time goes | parse ~13 µs, enrich ~4 µs, detect ~24 µs per event (detect grows linearly with rule count: 5.5 µs with 1 rule, 85 µs with 48) |
| Threat-intel size | lookup cost is flat up to 10⁶ entries; a 10⁶-entry feed costs ~300 MB of memory |
| `POST /ingest` (accepted = parsed and queued) | ~35-44k lines/s with 4 clients |
| Full pipeline through Redis → detector → PostgreSQL | ~7.2k lines/s sustained (100k-line backlog processed in 14 s) |
| Ingest → alert visible (p50 / p95 / p99) | 90 / 98 / 102 ms for attack bursts under 200 lines/s of background traffic, on a database already holding 10k alerts |
| Dashboard API at ~10k alerts | `/alerts` p50 ~6-8 ms (50 rows), `/stats/summary` p50 27 ms, `/stats/attack` p50 14 ms (aggregated in SQL; was ~360 ms and ~350 ms when aggregated in Python). Measured with the API running in-process on the host against Docker PostgreSQL, not the full compose stack |

The lab's time-to-detect is measured from the attack's start to the alert appearing, at about one second of resolution because syslog timestamps are whole seconds.

Known limit: `/stats/*` aggregate in SQL over the whole `alerts` table (a scan, no rollup table), so their cost still grows with history, though far more slowly than shipping every alert to Python did; a materialized or incrementally maintained rollup is the next step if history reaches millions of alerts.

Detection cost grows linearly with the number of rules, so the engine is single-worker by design (see Design notes).

## Supported sources

| Source | Events extracted |
|---|---|
| `auth.log` / `secure` (BSD and ISO syslog headers) | SSH login success/failure, invalid users, pre-auth disconnects, scanner probes, sudo commands & failed sudo, PAM sessions, user creation, group membership changes |

## Quick start

```bash
ADMIN_PASSWORD='choose-a-long-passphrase' docker compose up --build   # api + dashboard, detector, redis, postgres
# open http://localhost:8000, sign in as admin, create an API key under Admin, then:
python scripts/ship_logs.py samples/auth.log --api-key msk_...
```

The detector loads the demo feed in `samples/intel/`, which lists the sample attacker (203.0.113.45, a documentation address), so the brute-force alerts come out with a threat-intel match and a higher risk score.

Port 8000 taken? Run `API_PORT=8080 docker compose up --build` and pass `--url http://localhost:8080` to the shipper.

Run the rules over a file offline, no services needed:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m scripts.detect samples/auth.log
```

```bash
.venv/bin/python -m scripts.detect samples/auth.log --intel samples/intel
```

```
2026-10-26 10:15:47  CRITICAL risk 100  ssh-login-threat-intel       [T1078]
                                          threat intel: demo-blocklist
2026-10-26 10:16:12  CRITICAL risk  90  backdoor-account             [T1136.001, T1098]
...
8 alert(s), 12 rules, intel feeds: {'demo-blocklist': 2}
```

Running the API without `REDIS_URL` (`.venv/bin/uvicorn app.main:app --reload`) runs detection inline in memory. Interactive API docs: http://localhost:8000/docs

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login`, `/auth/logout`; `GET /auth/me` | Session handling |
| `GET/POST/PATCH` | `/users`, `/api-keys` | Admin only |
| `POST` | `/ingest` | API key or analyst+ session. `{"source": "auth.log", "lines": [...]}` (max 10,000 lines) → counts of parsed/unparsed |
| `GET` | `/alerts?status=&severity=&rule_id=&q=&since=&offset=&limit=50` | Alerts, newest first, with MITRE techniques, enrichment, risk score and evidence lines |
| `GET` | `/alerts/{id}/events`, `/events?source_ip=&user=&host=&around=&window=` | Raw-event drill-down |
| `GET` | `/stats/summary`, `/stats/attack` | KPIs, top sources, ATT&CK matrix |
| `GET` | `/alerts/{id}` | One alert |
| `PATCH` | `/alerts/{id}` | Analyst+. `{"status": "acknowledged" \| "closed"}` — triage |
| `GET` | `/rules` | Loaded detection rules |
| `GET` | `/sources` | Supported log sources |
| `GET` | `/health` | Public liveness and Redis connectivity |

## Design notes

- **Single detection worker.** Engine state (sliding windows, sequence progress) is in memory, so one worker must see every event for a given group key. Scaling out would mean partitioning the stream by key.
- **At-least-once processing.** The worker uses a Redis consumer group and acknowledges events only after their alerts are written; on restart it replays its unacknowledged entries first.
- **Bounded state.** Thresholds reset after firing (one alert per burst, not per event), evidence is capped at 20 lines, and idle state is swept periodically.

## Tests

```bash
.venv/bin/pytest
# include the PostgreSQL store tests (they TRUNCATE tables, so use a separate database):
docker compose up -d postgres
docker compose exec postgres createdb -U siem siem_test
TEST_DATABASE_URL=postgresql://siem:siem-dev-only@localhost:5432/siem_test .venv/bin/pytest
```

## Roadmap

1. ✅ Ingestion & normalization (auth.log)
2. ✅ Detection engine — YAML rules, thresholds, sequences, MITRE ATT&CK mapping
3. ✅ Enrichment & alerting — GeoIP, threat-intel feeds, severity scoring, dedup, webhooks, alert storage in PostgreSQL
4. ✅ Dashboard — alert triage, raw-event drill-down, ATT&CK heatmap, login with roles
5. ✅ Attack lab & benchmarks — scripted attacks against a local lab in docker compose, throughput/latency numbers

More parsers (nginx access, Windows EVTX) are planned.
