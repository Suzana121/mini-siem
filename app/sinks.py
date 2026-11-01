"""Where normalized events go after parsing.

With Redis, the ingest API appends events to a stream and the detection
worker (app/worker.py) runs the pipeline. Without Redis, MemorySink runs the
pipeline inline in the API process -- for tests and quick local runs.
"""

from typing import Protocol

from redis.asyncio import Redis

from app.pipeline import Pipeline
from app.schema import NormalizedEvent

STREAM_KEY = "siem:events"


class EventSink(Protocol):
    async def publish(self, events: list[NormalizedEvent]) -> None: ...

    async def close(self) -> None: ...


class RedisStreamSink:
    def __init__(self, url: str, stream: str = STREAM_KEY, maxlen: int = 1_000_000):
        self._redis = Redis.from_url(url)
        self._stream = stream
        self._maxlen = maxlen

    async def publish(self, events: list[NormalizedEvent]) -> None:
        async with self._redis.pipeline(transaction=False) as pipe:
            for event in events:
                pipe.xadd(
                    self._stream,
                    {"event": event.model_dump_json()},
                    maxlen=self._maxlen,
                    approximate=True,
                )
            await pipe.execute()

    async def ping(self) -> bool:
        return bool(await self._redis.ping())

    async def close(self) -> None:
        await self._redis.aclose()


class MemorySink:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self.events: list[NormalizedEvent] = []

    async def publish(self, events: list[NormalizedEvent]) -> None:
        self.events.extend(events)
        await self.pipeline.handle(events)

    async def close(self) -> None:
        pass
