"""End-to-end benchmark against a running stack (docker compose up).

    python -m benchmarks.bench_e2e --url http://localhost:8000 \
        --admin-user admin --admin-password '...'        # or ADMIN_USERNAME / ADMIN_PASSWORD

Phases (select with --phases):
  ingest   lines/s accepted by POST /ingest per batch size, with concurrent clients.
           "Accepted" means parsed and queued, not yet detected.
  drain    ingest a backlog, then time how long until the detector has worked through
           it. Completion is observed with a sentinel attack burst appended last: the
           stream is ordered and there is one consumer, so when the sentinel's alert is
           visible everything before it has been processed.
  latency  ingest->alert latency: known brute-force bursts injected at a steady
           background line rate; each is polled for on GET /alerts until its alert shows.
  api      read latency of /alerts, /stats/summary, /stats/attack with >= --api-alerts
           stored alerts (more are generated via ingest if needed).

Refuses to run against anything but localhost unless --allow-remote. Results:
benchmarks/results/e2e.json. Latency resolution is bounded by --poll-ms.
"""

import argparse
import asyncio
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from benchmarks import machine
from benchmarks.gen_logs import MONTHS, generate

RESULTS_DIR = Path(__file__).resolve().parent / "results"
CSRF = {"X-Requested-With": "mini-siem"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
PHASES = ["ingest", "drain", "latency", "api"]
BURST_RULE = "ssh-brute-force"


# --- helpers (pure, unit-tested) ---------------------------------------------


def is_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in LOCAL_HOSTS or host.endswith(".localhost")


def percentile(values: list[float], p: float) -> float | None:
    """Linear-interpolated percentile (the numpy default); None for no data."""
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * p / 100
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def summarize_ms(seconds: list[float]) -> dict:
    ms = [s * 1000 for s in seconds]
    return {
        "n": len(ms),
        "p50_ms": percentile(ms, 50),
        "p95_ms": percentile(ms, 95),
        "p99_ms": percentile(ms, 99),
        "max_ms": max(ms) if ms else None,
    }


def attacker_ip(index: int, salt: int) -> str:
    """Unique address in 198.18.0.0/15 (RFC 2544 benchmarking range, never routed)."""
    n = (salt + index) % (2 * 256 * 254)
    return f"198.{18 + n // (256 * 254)}.{(n // 254) % 256}.{n % 254 + 1}"


def burst_lines(ip: str, when: datetime, host: str = "web01", failures: int = 6) -> list[str]:
    """`failures` failed logins from one IP inside a few seconds: trips ssh-brute-force (5 / 60s)."""
    lines = []
    for i in range(failures):
        t = when + timedelta(milliseconds=200 * i)
        port = 40000 + (i * 37) % 20000
        lines.append(
            f"{MONTHS[t.month - 1]} {t.day:>2} {t:%H:%M:%S} {host} sshd[{3000 + i}]: "
            f"Failed password for root from {ip} port {port} ssh2"
        )
    return lines


def background_lines(n: int, seed: int) -> list[str]:
    """Ordinary traffic ending just before now (no attacks)."""
    start = datetime.now(timezone.utc) - timedelta(seconds=n / 4 + 120)
    lines, _ = generate(n, seed=seed, attack_ratio=0, start=start)
    return lines


# --- client ----------------------------------------------------------------------


class Stack:
    def __init__(self, client: httpx.AsyncClient, api_key: str | None):
        self.client = client
        # Session-cookie writes need the CSRF header; an API key takes precedence when given.
        self.headers = {**CSRF, **({"Authorization": f"Bearer {api_key}"} if api_key else {})}

    async def ingest(self, lines: list[str]) -> float:
        """POST one batch; returns request seconds. Raises on non-200."""
        t0 = time.perf_counter()
        r = await self.client.post("/ingest", json={"source": "auth.log", "lines": lines}, headers=self.headers)
        r.raise_for_status()
        return time.perf_counter() - t0

    async def alert_for(self, rule_id: str, ip: str) -> bool:
        r = await self.client.get("/alerts", params={"rule_id": rule_id, "q": ip, "limit": 5})
        r.raise_for_status()
        return any(a.get("source", {}).get("ip") == ip for a in r.json())

    async def wait_for_alert(self, rule_id: str, ip: str, timeout: float, poll: float) -> float | None:
        """Seconds (perf_counter timestamp) at which the alert was first seen, or None on timeout."""
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            if await self.alert_for(rule_id, ip):
                return time.perf_counter()
            await asyncio.sleep(poll)
        return None

    async def alert_total(self) -> int:
        r = await self.client.get("/stats/summary")
        r.raise_for_status()
        return sum(r.json()["by_status"].values())


async def login(client: httpx.AsyncClient, user: str, password: str) -> None:
    r = await client.post("/auth/login", json={"username": user, "password": password}, headers=CSRF)
    if r.status_code != 200:
        raise SystemExit(f"login failed ({r.status_code}): {r.text[:200]}")


async def send_batches(stack: Stack, batches: list[list[str]], clients: int) -> list[float]:
    """Send batches with `clients` concurrent workers; returns per-request seconds."""
    queue: asyncio.Queue = asyncio.Queue()
    for b in batches:
        queue.put_nowait(b)
    latencies: list[float] = []

    async def worker():
        while True:
            try:
                batch = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            latencies.append(await stack.ingest(batch))

    await asyncio.gather(*(worker() for _ in range(clients)))
    return latencies


def chunk(lines: list[str], size: int) -> list[list[str]]:
    return [lines[i : i + size] for i in range(0, len(lines), size)]


# --- phases ---------------------------------------------------------------------


async def phase_ingest(stack: Stack, a) -> list[dict]:
    rows = []
    for size in a.batch_sizes:
        lines = background_lines(a.ingest_lines, seed=100 + size)
        t0 = time.perf_counter()
        lat = await send_batches(stack, chunk(lines, size), a.clients)
        wall = time.perf_counter() - t0
        rows.append({
            "batch_size": size, "clients": a.clients, "lines": len(lines), "requests": len(lat),
            "seconds": wall, "lines_per_s": len(lines) / wall, "requests_per_s": len(lat) / wall,
            "request_latency": summarize_ms(lat),
        })
        print(f"  ingest batch {size:>6}: {rows[-1]['lines_per_s']:>10,.0f} lines/s", flush=True)
    return rows


async def phase_drain(stack: Stack, a) -> dict:
    salt = random.randrange(2 * 256 * 254)
    lines = background_lines(a.drain_lines, seed=200)
    t0 = time.perf_counter()
    await send_batches(stack, chunk(lines, 1000), a.clients)
    t_ingested = time.perf_counter()
    sentinel = attacker_ip(0, salt)
    await stack.ingest(burst_lines(sentinel, datetime.now(timezone.utc)))
    t_seen = await stack.wait_for_alert(BURST_RULE, sentinel, a.timeout, a.poll_ms / 1000)
    if t_seen is None:
        return {"error": f"sentinel alert not seen within {a.timeout}s", "lines": len(lines)}
    return {
        "lines": len(lines),
        "ingest_seconds": t_ingested - t0,
        "drain_seconds_after_ingest": t_seen - t_ingested,
        "total_seconds": t_seen - t0,
        "pipeline_lines_per_s": len(lines) / (t_seen - t0),
        "note": "resolution is the poll interval; includes the sentinel burst (6 lines)",
    }


async def phase_latency(stack: Stack, a) -> dict:
    salt = random.randrange(2 * 256 * 254)
    stop = asyncio.Event()
    sent_background = 0

    async def background():
        nonlocal sent_background
        per_tick = max(1, int(a.background_rate * 0.1))
        pool = background_lines(max(per_tick * 20, 2000), seed=300)
        i = 0
        next_tick = time.perf_counter()
        while not stop.is_set():
            batch = [pool[(i + k) % len(pool)] for k in range(per_tick)]
            i += per_tick
            await stack.ingest(batch)
            sent_background += len(batch)
            next_tick += 0.1
            await asyncio.sleep(max(0.0, next_tick - time.perf_counter()))

    async def one_burst(index: int):
        ip = attacker_ip(index + 1, salt)
        t_sent = time.perf_counter()
        await stack.ingest(burst_lines(ip, datetime.now(timezone.utc)))
        t_seen = await stack.wait_for_alert(BURST_RULE, ip, a.timeout, a.poll_ms / 1000)
        return None if t_seen is None else t_seen - t_sent

    bg = asyncio.create_task(background())
    await asyncio.sleep(1.0)  # let the background rate settle before the first burst
    tasks = []
    for i in range(a.bursts):
        tasks.append(asyncio.create_task(one_burst(i)))
        await asyncio.sleep(a.burst_interval)
    results = await asyncio.gather(*tasks)
    stop.set()
    await bg
    seen = [r for r in results if r is not None]
    return {
        "bursts": a.bursts, "missed": len(results) - len(seen),
        "background_lines_per_s_target": a.background_rate, "background_lines_sent": sent_background,
        "burst_interval_s": a.burst_interval, "poll_ms": a.poll_ms,
        **summarize_ms(seen),
        "note": "latency = burst POST start to first poll that sees the alert (includes up to one poll interval)",
    }


async def phase_api(stack: Stack, a) -> list[dict]:
    salt = random.randrange(2 * 256 * 254)
    have = await stack.alert_total()
    need = max(0, a.api_alerts - have)
    if need:
        print(f"  generating {need} alerts ({have} stored)...", flush=True)
        lines = []
        for i in range(need):
            lines += burst_lines(attacker_ip(100_000 + i, salt), datetime.now(timezone.utc), failures=5)
        await send_batches(stack, chunk(lines, 5000), a.clients)
        sentinel = attacker_ip(99_999, salt)
        await stack.ingest(burst_lines(sentinel, datetime.now(timezone.utc)))
        if await stack.wait_for_alert(BURST_RULE, sentinel, a.timeout * 4, a.poll_ms / 1000) is None:
            return [{"error": "generated alerts not visible in time"}]
    stored = await stack.alert_total()

    endpoints = [
        ("/alerts?limit=50", "GET /alerts?limit=50"),
        ("/alerts?limit=1000", "GET /alerts?limit=1000"),
        (f"/alerts?rule_id={BURST_RULE}&limit=50", "GET /alerts?rule_id=..&limit=50"),
        (f"/alerts?q={attacker_ip(100_000, salt)}", "GET /alerts?q=<ip>"),
        ("/stats/summary", "GET /stats/summary"),
        ("/stats/attack", "GET /stats/attack"),
    ]
    rows = []
    for path, label in endpoints:
        for _ in range(3):  # warm-up, discarded
            (await stack.client.get(path)).raise_for_status()
        samples = []
        for _ in range(a.api_runs):
            t0 = time.perf_counter()
            r = await stack.client.get(path)
            r.raise_for_status()
            samples.append(time.perf_counter() - t0)
        rows.append({"endpoint": label, "stored_alerts": stored, "bytes": len(r.content), **summarize_ms(samples)})
        print(f"  {label:<36} p50 {rows[-1]['p50_ms']:.1f} ms  p95 {rows[-1]['p95_ms']:.1f} ms", flush=True)
    return rows


# --- main ------------------------------------------------------------------------


async def run(a, client: httpx.AsyncClient) -> dict:
    await login(client, a.admin_user, a.admin_password)
    stack = Stack(client, a.api_key)
    out: dict = {
        "tool": "bench_e2e",
        "machine": machine.collect(include_docker=True),
        "params": {k: v for k, v in vars(a).items() if k not in ("admin_password", "api_key", "out")},
        "errors": [],
    }
    runners = {"ingest": phase_ingest, "drain": phase_drain, "latency": phase_latency, "api": phase_api}
    for name in PHASES:
        if name not in a.phases:
            continue
        print(f"{name}:", flush=True)
        try:
            out[name] = await runners[name](stack, a)
        except Exception as exc:  # keep partial results from earlier phases
            out["errors"].append({"phase": name, "error": repr(exc)})
            print(f"  FAILED: {exc!r}", flush=True)
    return out


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--admin-user", default=os.getenv("ADMIN_USERNAME"))
    p.add_argument("--admin-password", default=os.getenv("ADMIN_PASSWORD"))
    p.add_argument("--api-key", default=os.getenv("SIEM_API_KEY"), help="Bearer key for /ingest (default: session cookie)")
    p.add_argument("--allow-remote", action="store_true", help="permit a non-localhost --url")
    p.add_argument("--phases", nargs="+", choices=PHASES, default=PHASES)
    p.add_argument("--clients", type=int, default=4, help="concurrent ingest clients")
    p.add_argument("--batch-sizes", type=int, nargs="+", default=[100, 1000, 10000])
    p.add_argument("--ingest-lines", type=int, default=50_000, help="lines per batch size in the ingest phase")
    p.add_argument("--drain-lines", type=int, default=100_000)
    p.add_argument("--bursts", type=int, default=60, help="attack bursts in the latency phase")
    p.add_argument("--burst-interval", type=float, default=1.0)
    p.add_argument("--background-rate", type=int, default=200, help="steady background lines/s during the latency phase")
    p.add_argument("--api-alerts", type=int, default=10_000, help="minimum stored alerts for the api phase")
    p.add_argument("--api-runs", type=int, default=30)
    p.add_argument("--poll-ms", type=int, default=20)
    p.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for an alert")
    p.add_argument("--out", type=Path, default=RESULTS_DIR / "e2e.json")
    a = p.parse_args(argv)
    if not a.allow_remote and not is_local(a.url):
        p.error(f"refusing to benchmark non-local host {urlparse(a.url).hostname!r}; pass --allow-remote to override")
    if not (a.admin_user and a.admin_password):
        p.error("admin credentials required (--admin-user/--admin-password or ADMIN_USERNAME/ADMIN_PASSWORD)")
    return a


async def amain(argv=None) -> dict:
    a = parse_args(argv)
    limits = httpx.Limits(max_connections=a.clients * 2 + 16)
    async with httpx.AsyncClient(base_url=a.url, timeout=120, limits=limits) as client:
        out = await run(a, client)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2))
    print(f"wrote {a.out}")
    return out


if __name__ == "__main__":
    asyncio.run(amain())
