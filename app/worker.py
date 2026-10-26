"""Detection worker: consumes events from Redis, runs rules, publishes alerts.

Runs as a single consumer because engine state is in memory (see
app/detection/engine.py). On startup it first replays entries that were
delivered but never acknowledged, so a crash doesn't drop events.

    python -m app.worker
"""

import asyncio
import logging
import os
from pathlib import Path

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.schema import NormalizedEvent
from app.sinks import ALERT_STREAM_KEY, STREAM_KEY

GROUP = "detectors"
CONSUMER = "detector-1"
BATCH = 500
ALERT_STREAM_MAXLEN = 100_000

log = logging.getLogger("mini-siem.worker")


async def handle(redis: Redis, engine: DetectionEngine, entries: list) -> None:
    alerts = []
    for _, fields in entries:
        alerts.extend(engine.process(NormalizedEvent.model_validate_json(fields[b"event"])))

    async with redis.pipeline(transaction=False) as pipe:
        for alert in alerts:
            log.warning("ALERT [%s] %s %s", alert.severity, alert.rule_id, alert.group)
            pipe.xadd(
                ALERT_STREAM_KEY,
                {"alert": alert.model_dump_json()},
                maxlen=ALERT_STREAM_MAXLEN,
                approximate=True,
            )
        pipe.xack(STREAM_KEY, GROUP, *[entry_id for entry_id, _ in entries])
        await pipe.execute()


async def run(redis_url: str, rules_dir: Path) -> None:
    rules = load_rules(rules_dir)
    engine = DetectionEngine(rules)
    log.info("loaded %d rules from %s", len(rules), rules_dir)

    redis = Redis.from_url(redis_url)
    try:
        await redis.xgroup_create(STREAM_KEY, GROUP, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    # "0" reads our own pending (unacknowledged) entries; ">" reads new ones.
    cursor = "0"
    while True:
        response = await redis.xreadgroup(GROUP, CONSUMER, {STREAM_KEY: cursor}, count=BATCH, block=5000)
        entries = response[0][1] if response else []
        if entries:
            await handle(redis, engine, entries)
        elif cursor == "0":
            cursor = ">"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    rules_dir = Path(os.getenv("RULES_DIR", DEFAULT_RULES_DIR))
    asyncio.run(run(os.environ["REDIS_URL"], rules_dir))


if __name__ == "__main__":
    main()
