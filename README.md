# Mini-SIEM

A lightweight Security Information and Event Management pipeline: ingest raw logs, normalize them to a common schema, run detection rules mapped to MITRE ATT&CK, and surface alerts.

> **Status:** Stage 2 of 5 — detection engine with 11 MITRE-mapped rules.

## Architecture

```
log shippers ──► Ingest API (FastAPI) ──► parser ──► Redis Stream "siem:events"
                       ▲                                     │ consumer group
                       │                                     ▼
                  GET /alerts ◄── Redis Stream "siem:alerts" ◄── detection worker (YAML rules)
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

Every rule has positive and negative test cases written as real log lines ([`tests/test_detection_rules.py`](tests/test_detection_rules.py)), and a test fails if any rule lacks a positive case.

## Supported sources

| Source | Events extracted |
|---|---|
| `auth.log` / `secure` (BSD and ISO syslog headers) | SSH login success/failure, invalid users, pre-auth disconnects, scanner probes, sudo commands & failed sudo, PAM sessions, user creation, group membership changes |

## Quick start

```bash
docker compose up --build
python scripts/ship_logs.py samples/auth.log
curl localhost:8000/alerts
```

Port 8000 taken? Run `API_PORT=8080 docker compose up --build` and pass `--url http://localhost:8080` to the shipper.

Run the rules over a file offline, no services needed:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m scripts.detect samples/auth.log
```

```
2026-10-26 10:15:44  MEDIUM    ssh-brute-force              [T1110.001]  {'source.ip': '203.0.113.45'}
2026-10-26 10:15:47  CRITICAL  ssh-brute-force-success      [T1110, T1078]  {'source.ip': '203.0.113.45'}
2026-10-26 10:16:12  CRITICAL  backdoor-account             [T1136.001, T1098]  {'host.name': 'web01', 'user.target': 'backup2'}
...
7 alert(s), 11 rules loaded
```

Running the API without `REDIS_URL` (`.venv/bin/uvicorn app.main:app --reload`) runs detection inline in memory. Interactive API docs: http://localhost:8000/docs

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/ingest` | `{"source": "auth.log", "lines": [...]}` (max 10,000 lines) → counts of parsed/unparsed |
| `GET` | `/alerts?limit=50` | Most recent alerts, newest first, with MITRE techniques and evidence lines |
| `GET` | `/rules` | Loaded detection rules |
| `GET` | `/sources` | Supported log sources |
| `GET` | `/health` | Liveness, including Redis connectivity |

## Design notes

- **Single detection worker.** Engine state (sliding windows, sequence progress) is in memory, so one worker must see every event for a given group key. Scaling out would mean partitioning the stream by key.
- **At-least-once processing.** The worker uses a Redis consumer group and acknowledges events only after their alerts are written; on restart it replays its unacknowledged entries first.
- **Bounded state.** Thresholds reset after firing (one alert per burst, not per event), evidence is capped at 20 lines, and idle state is swept periodically.

## Tests

```bash
.venv/bin/pytest
```

## Roadmap

1. ✅ Ingestion & normalization (auth.log)
2. ✅ Detection engine — YAML rules, thresholds, sequences, MITRE ATT&CK mapping
3. Enrichment & alerting — GeoIP, threat-intel feeds, severity scoring, dedup, webhooks, alert storage in PostgreSQL
4. Dashboard — alert triage, raw-event drill-down, ATT&CK heatmap
5. Attack lab & benchmarks — scripted attacks against a local lab VM, throughput/latency numbers

More parsers (nginx access, Windows EVTX) are planned alongside stage 3.
