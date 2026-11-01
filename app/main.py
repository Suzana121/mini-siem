import os
from pathlib import Path
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.auth import AuthStore, require_ingest, require_role
from app.config import ROOT, build_auth, build_events, build_pipeline, build_store, load_rules_from_env
from app.detection import Rule
from app.events import EventStore
from app.parsers import PARSERS
from app.routes import auth as auth_routes
from app.routes import events as event_routes
from app.sinks import EventSink, MemorySink, RedisStreamSink
from app.store import AlertStore, Status, StoredAlert

MAX_LINES_PER_REQUEST = 10_000


class IngestRequest(BaseModel):
    source: str = Field(examples=["auth.log"])
    lines: list[str] = Field(max_length=MAX_LINES_PER_REQUEST)


class IngestResponse(BaseModel):
    received: int
    parsed: int
    unparsed: int


class StatusUpdate(BaseModel):
    status: Status


def create_app(
    sink: EventSink | None = None,
    store: AlertStore | None = None,
    rules: list[Rule] | None = None,
    events: EventStore | None = None,
    auth: AuthStore | None = None,
) -> FastAPI:
    """Components not passed in are built from environment variables (see app/config.py)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with AsyncExitStack() as stack:
            app.state.rules = rules if rules is not None else load_rules_from_env()
            app.state.store = store or await build_store(stack)
            app.state.events = events or await build_events(stack)
            app.state.auth = auth or await build_auth(stack)
            if sink:
                app.state.sink = sink
            elif url := os.getenv("REDIS_URL"):
                app.state.sink = RedisStreamSink(url)
                stack.push_async_callback(app.state.sink.close)
            else:
                # No Redis means no worker, so the pipeline runs inline.
                app.state.sink = MemorySink(await build_pipeline(stack, app.state.rules, app.state.store, app.state.events))
            yield

    app = FastAPI(title="Mini-SIEM", version="0.4.0", lifespan=lifespan)
    viewer, analyst = require_role("viewer"), require_role("analyst")
    app.include_router(auth_routes.router)
    app.include_router(event_routes.router)

    @app.get("/health")
    async def health(request: Request) -> dict:
        sink = request.app.state.sink
        status = {"status": "ok"}
        if isinstance(sink, RedisStreamSink):
            try:
                await sink.ping()
            except Exception:
                raise HTTPException(503, detail="redis unreachable")
        return status

    @app.get("/sources")
    async def sources(_=Depends(viewer)) -> list[str]:
        return sorted(PARSERS)

    @app.get("/rules")
    async def list_rules(request: Request, _=Depends(viewer)) -> list[dict]:
        return [
            rule.model_dump(include={"id", "title", "description", "severity", "mitre"})
            for rule in request.app.state.rules
        ]

    @app.get("/alerts")
    async def list_alerts(
        request: Request,
        status: Status | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        q: str | None = Query(None, max_length=200),
        since: datetime | None = None,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=1000),
        _=Depends(viewer),
    ) -> list[StoredAlert]:
        return await request.app.state.store.list(status, severity, rule_id, limit, q, since, offset)

    @app.get("/alerts/{alert_id}")
    async def get_alert(alert_id: str, request: Request, _=Depends(viewer)) -> StoredAlert:
        alert = await request.app.state.store.get(alert_id)
        if alert is None:
            raise HTTPException(404, detail="alert not found")
        return alert

    @app.patch("/alerts/{alert_id}")
    async def update_alert(
        alert_id: str, body: StatusUpdate, request: Request, _=Depends(analyst)
    ) -> StoredAlert:
        alert = await request.app.state.store.set_status(alert_id, body.status)
        if alert is None:
            raise HTTPException(404, detail="alert not found")
        return alert

    @app.post("/ingest", response_model=IngestResponse)
    async def ingest(body: IngestRequest, request: Request, _=Depends(require_ingest)) -> IngestResponse:
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

    web_dir = Path(os.getenv("WEB_DIR", ROOT / "web" / "dist"))
    if (web_dir / "index.html").is_file():
        if (web_dir / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=web_dir / "assets"), name="assets")

        @app.middleware("http")
        async def serve_spa(request: Request, call_next):
            # Browser navigations get the single-page app; fetch/XHR calls (no
            # text/html in Accept) reach the API, which shares paths like /alerts/{id}.
            path = request.url.path
            if (
                request.method == "GET"
                and "text/html" in request.headers.get("accept", "")
                and path not in ("/docs", "/redoc", "/openapi.json")
            ):
                candidate = (web_dir / path.lstrip("/")).resolve()
                if candidate.is_file() and candidate.is_relative_to(web_dir.resolve()):
                    return FileResponse(candidate)
                return FileResponse(web_dir / "index.html", headers={"Cache-Control": "no-cache"})
            return await call_next(request)

    return app


app = create_app()
