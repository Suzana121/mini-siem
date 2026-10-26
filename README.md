# Mini-SIEM

A lightweight Security Information and Event Management pipeline: ingest raw logs, normalize them to a common schema, run detection rules mapped to MITRE ATT&CK, and surface alerts.

> **Status:** Stage 1 of 5 — log ingestion & normalization.

## Architecture

```
log shippers ──► Ingest API (FastAPI) ──► parser ──► Redis Stream "siem:events"
                                                         │
                                       (stage 2) detection engine ──► alerts ──► dashboard
```

Every parser emits a `NormalizedEvent` (ECS-inspired: `event.category/action/outcome`, `user`, `source.ip`, `host`, `process`), so detection rules are written once against a stable set of fields, not per log format.

## Supported sources

| Source | Events extracted |
|---|---|
| `auth.log` / `secure` (BSD and ISO syslog headers) | SSH login success/failure, invalid users, pre-auth disconnects, scanner probes, sudo commands & failed sudo, PAM sessions, user creation, group membership changes |

## Quick start

```bash
docker compose up --build
python scripts/ship_logs.py samples/auth.log
# {'received': 17, 'parsed': 16, 'unparsed': 1}
```

Port 8000 taken? Run `API_PORT=8080 docker compose up --build` and pass `--url http://localhost:8080` to the shipper.

Without Docker (events kept in memory):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload
```

Interactive API docs: http://localhost:8000/docs

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/ingest` | `{"source": "auth.log", "lines": [...]}` (max 10,000 lines) → counts of parsed/unparsed |
| `GET` | `/sources` | Supported log sources |
| `GET` | `/health` | Liveness, including Redis connectivity |

## Tests

```bash
.venv/bin/pytest
```

## Roadmap

1. ✅ Ingestion & normalization (auth.log)
2. Detection engine — Sigma-style YAML rules, time-window thresholds, event correlation, MITRE ATT&CK mapping
3. Enrichment & alerting — GeoIP, threat-intel feeds, severity scoring, dedup, webhooks
4. Dashboard — alert triage, raw-event drill-down, ATT&CK heatmap
5. Attack lab & benchmarks — scripted attacks against a local lab VM, per-rule tests, throughput/latency numbers

More parsers (nginx access, Windows EVTX) are planned alongside stage 2.
