# Attack lab

A disposable docker-compose lab that generates genuine `sshd`/`sudo`/`useradd`
log lines (not synthetic data) and runs them through the real Mini-SIEM
pipeline, so the detection rules are checked against real attacker tooling.

## Topology

- **victim** -- Debian + `openssh-server`, `rsyslog`, `sudo`. Accounts:
  `deploy` (strong random password, set at image build time), `intern`
  (weak password, also in the attacker's wordlist, and a sudoer -- this is
  the intentionally vulnerable path), `root` (SSH login enabled). rsyslog
  writes `/var/log/auth.log`.
- **attacker** -- `hydra`, `nmap`, `netcat`, `sshpass`. Scenario scripts
  live in `lab/scenarios/`.
- **shipper** -- the main repo image, running `python -m scripts.ship_logs
  --follow` against the victim's shared log volume, shipping to the real
  `/ingest` API.
- **lab-init** -- one-shot: logs in as admin and creates an API key named
  `lab-shipper` for the shipper (`scripts/create_api_key.py`), written to a
  small shared volume the shipper waits on.

`victim` and `attacker` are the only members of `lab-net`, an
`internal: true` Docker network with no route to the internet or to the
rest of the stack -- attack traffic can only ever reach `victim`. `shipper`
and `lab-init` need no network route to the lab at all: they read the
victim's `auth.log` through a shared Docker volume and only ever talk to
`api` over the stack's normal network, so `api` itself needs no change for
the lab to work.

## Running it

```
ADMIN_PASSWORD='<choose a long passphrase>' API_PORT=8793 \
  docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab up -d --build

.venv/bin/python lab/run_lab.py --url http://localhost:8793 \
  --admin-username admin --admin-password '<the same passphrase>'
```

`run_lab.py` runs each scenario in `lab/scenarios.yml` inside `attacker`,
polls `GET /alerts?since=<scenario start>` until every expected rule id
has fired (default timeout 90s per scenario), and writes
`benchmarks/results/lab.json`. It exits non-zero if any expected rule
never fired, so it doubles as a regression check in CI once Docker is
available there.

Tear down with:

```
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab down
```

(keep the `lab-logs`/`lab-shared`/`lab-shipper` volumes with `-v` omitted,
so a re-run doesn't need everything rebuilt from scratch; the next
`lab-init` run creates a fresh API key regardless).

## Dedup window

Rules dedup repeats of the same alert for `DEDUP_WINDOW` (default 15m).
Running scenarios back-to-back would otherwise hide a later scenario's
alert behind an earlier one for the same rule id. The overlay sets
`DEDUP_WINDOW=1s` for the `detector` service instead of having the runner
close previous alerts via `PATCH` -- simpler, and fine for a lab whose
alerts are thrown away each run.

## Scenarios

See `lab/scenarios.yml` for the authoritative list (scenario name -> script
-> expected rule ids). Every script is idempotent (safe to re-run) and
prints a `SCENARIO_START <name> <timestamp>` marker.

## Known caveats

- `DEPLOY_PASSWORD` has a fixed fallback (long, outside the wordlist) if
  not set explicitly; pass a freshly generated one (e.g. `DEPLOY_PASSWORD=$(openssl rand -base64 24)`)
  for a true per-run random password.
- Attacker source IPs are private Docker addresses, so GeoIP enrichment
  won't show external geography and risk scores skip the "external IP"
  boost; this is expected, not a bug. Listing the attacker's lab IP in
  `samples/intel` would let the `ssh-login-threat-intel` rule fire too.
