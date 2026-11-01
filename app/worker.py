"""Detection worker: consumes events from Redis and runs the pipeline
(enrich -> detect -> score -> store -> notify).

Runs as a single consumer because engine state is in memory (see
app/detection/engine.py). Events are acknowledged only after their alerts are
stored; on startup the worker first replays entries that were delivered but
never acknowledged, so a crash doesn't drop events.

    python -m app.worker
"""

import asyncio
import logging
import os
from contextlib import AsyncExitStack

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.config import build_events, build_pipeline, build_store, load_rules_from_env
from app.schema import NormalizedEvent
from app.sinks import STREAM_KEY

GROUP = "detectors"
CONSUMER = "detector-1"
BATCH = 500

log = logging.getLogger("mini-siem.worker")


async def run(redis_url: str) -> None:
    async with AsyncExitStack() as stack:
        rules = load_rules_from_env()
        pipeline = await build_pipeline(stack, rules, await build_store(stack), await build_events(stack))
        log.info("loaded %d rules", len(rules))

        redis = Redis.from_url(redis_url)
        stack.push_async_callback(redis.aclose)
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
            if not entries:
                if cursor == "0":
                    cursor = ">"
                continue

            events = [NormalizedEvent.model_validate_json(fields[b"event"]) for _, fields in entries]
            for alert in await pipeline.handle(events):
                log.warning("ALERT [%s] risk=%d %s %s", alert.severity, alert.risk_score, alert.rule_id, alert.group)
            await redis.xack(STREAM_KEY, GROUP, *[entry_id for entry_id, _ in entries])


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run(os.environ["REDIS_URL"]))


if __name__ == "__main__":
    main()
