import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from app.parsers import PARSERS
from app.sinks import EventSink, MemorySink, RedisStreamSink

MAX_LINES_PER_REQUEST = 10_000


class IngestRequest(BaseModel):
    source: str = Field(examples=["auth.log"])
    lines: list[str] = Field(max_length=MAX_LINES_PER_REQUEST)


class IngestResponse(BaseModel):
    received: int
    parsed: int
    unparsed: int


def _default_sink() -> EventSink:
    url = os.getenv("REDIS_URL")
    return RedisStreamSink(url) if url else MemorySink()


def create_app(sink: EventSink | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.sink = sink or _default_sink()
        yield
        await app.state.sink.close()

    app = FastAPI(title="Mini-SIEM", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    async def health(request: Request) -> dict:
        sink = request.app.state.sink
        status = {"status": "ok", "sink": type(sink).__name__}
        if isinstance(sink, RedisStreamSink):
            try:
                await sink.ping()
            except Exception:
                raise HTTPException(503, detail="redis unreachable")
        return status

    @app.get("/sources")
    async def sources() -> list[str]:
        return sorted(PARSERS)

    @app.post("/ingest", response_model=IngestResponse)
    async def ingest(body: IngestRequest, request: Request) -> IngestResponse:
        parser = PARSERS.get(body.source)
        if parser is None:
            raise HTTPException(400, detail=f"unknown source '{body.source}'")

        reference = datetime.now(timezone.utc)
        events = [e for line in body.lines if (e := parser(line, reference)) is not None]
        if events:
            await request.app.state.sink.publish(events)
        return IngestResponse(
            received=len(body.lines), parsed=len(events), unparsed=len(body.lines) - len(events)
        )

    return app


app = create_app()
