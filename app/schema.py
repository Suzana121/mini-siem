"""Normalized event schema, loosely modeled on Elastic Common Schema (ECS).

Every parser turns a raw log line into a NormalizedEvent so the detection
engine can write rules against one set of field names regardless of source.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventInfo(BaseModel):
    category: str  # e.g. "authentication", "process", "session"
    action: str  # e.g. "ssh_login", "sudo_command"
    outcome: Outcome = Outcome.UNKNOWN


class HostInfo(BaseModel):
    name: str | None = None


class ProcessInfo(BaseModel):
    name: str | None = None
    pid: int | None = None


class UserInfo(BaseModel):
    name: str | None = None
    target: str | None = None  # user being switched to (sudo/su)


class GeoInfo(BaseModel):
    country_iso: str | None = None
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None


class SourceInfo(BaseModel):
    ip: str | None = None
    port: int | None = None
    # Filled in by enrichment (app/enrichment.py), not by parsers.
    internal: bool | None = None  # private, loopback, documentation ranges, ...
    geo: GeoInfo | None = None


class ThreatInfo(BaseModel):
    """Threat-intel matches for source.ip, filled in by enrichment."""

    listed: bool = False
    feeds: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    timestamp: datetime
    log_source: str  # e.g. "auth.log"
    event: EventInfo
    host: HostInfo = Field(default_factory=HostInfo)
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    user: UserInfo = Field(default_factory=UserInfo)
    source: SourceInfo = Field(default_factory=SourceInfo)
    threat: ThreatInfo = Field(default_factory=ThreatInfo)
    labels: dict[str, str] = Field(default_factory=dict)
    raw: str
