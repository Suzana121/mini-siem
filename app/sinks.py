"""Where normalized events go after parsing.

The ingest API publishes to a Redis Stream; the detection engine (stage 2)
will consume from it with a consumer group. MemorySink is for tests and for
running the API without Redis.
"""

from typing import Protocol

from redis.asyncio import Redis

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
    def __init__(self) -> None:
        self.events: list[NormalizedEvent] = []

    async def publish(self, events: list[NormalizedEvent]) -> None:
        self.events.extend(events)

    async def close(self) -> None:
        pass
