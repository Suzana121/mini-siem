"""Read-only event and statistics endpoints (viewer role or higher)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth import require_role
from app.events import alert_events, attack_matrix, fetch_alerts, parse_window, summarize
from app.schema import NormalizedEvent

router = APIRouter()
# Kept as a module attribute so tests can override this exact dependency.
viewer = require_role("viewer")


@router.get("/events")
async def list_events(
    request: Request,
    source_ip: str | None = None,
    user: str | None = None,
    host: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    around: datetime | None = None,
    window: str = "15m",
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _=Depends(viewer),
) -> list[NormalizedEvent]:
    if around is not None:
        try:
            delta = parse_window(window)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        if around.tzinfo is None:
            around = around.replace(tzinfo=timezone.utc)
        since, until = around - delta, around + delta
    return await request.app.state.events.query(
        source_ip=source_ip, user=user, host=host, since=since, until=until, limit=limit, offset=offset
    )


@router.get("/alerts/{alert_id}/events")
async def events_for_alert(request: Request, alert_id: str, _=Depends(viewer)) -> list[NormalizedEvent]:
    alert = await request.app.state.store.get(alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    return await alert_events(request.app.state.events, alert)


@router.get("/stats/summary")
async def stats_summary(request: Request, _=Depends(viewer)) -> dict:
    return summarize(await fetch_alerts(request.app.state.store))


@router.get("/stats/attack")
async def stats_attack(request: Request, since: datetime | None = None, _=Depends(viewer)) -> dict:
    return attack_matrix(await fetch_alerts(request.app.state.store, since))
