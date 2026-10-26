"""Where normalized events go after parsing, and where alerts are read back.

With Redis, the ingest API appends events to a stream and the detection
worker (app/worker.py) consumes them and appends alerts to a second stream.
MemorySink runs detection inline instead -- for tests and for running the
API without Redis.
"""

from typing import Protocol

from redis.asyncio import Redis

from app.detection import Alert, DetectionEngine
from app.schema import NormalizedEvent

STREAM_KEY = "siem:events"
ALERT_STREAM_KEY = "siem:alerts"


class EventSink(Protocol):
    async def publish(self, events: list[NormalizedEvent]) -> None: ...

    async def recent_alerts(self, limit: int) -> list[Alert]: ...

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

    async def recent_alerts(self, limit: int) -> list[Alert]:
        entries = await self._redis.xrevrange(ALERT_STREAM_KEY, count=limit)
        return [Alert.model_validate_json(fields[b"alert"]) for _, fields in entries]

    async def ping(self) -> bool:
        return bool(await self._redis.ping())

    async def close(self) -> None:
        await self._redis.aclose()


class MemorySink:
    def __init__(self, engine: DetectionEngine | None = None) -> None:
        self.engine = engine
        self.events: list[NormalizedEvent] = []
        self.alerts: list[Alert] = []

    async def publish(self, events: list[NormalizedEvent]) -> None:
        self.events.extend(events)
        if self.engine:
            for event in events:
                self.alerts.extend(self.engine.process(event))

    async def recent_alerts(self, limit: int) -> list[Alert]:
        return self.alerts[::-1][:limit]

    async def close(self) -> None:
        pass
