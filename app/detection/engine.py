"""Stateful detection engine.

Windows are measured in *event* time, not wall-clock time, so replaying an
old log file produces the same alerts as watching it live. Events are assumed
to arrive roughly in order per host.

State lives in memory, keyed by (rule id, group_by values). That means one
engine instance must see every event for a given key -- fine for a single
worker; scaling out would mean partitioning the stream by group key.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.detection.rules import MitreTechnique, Rule, get_field
from app.schema import NormalizedEvent, SourceInfo, ThreatInfo, UserInfo

MAX_EVIDENCE = 20
SWEEP_EVERY = 10_000  # events between purges of idle state


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    rule_id: str
    title: str
    severity: str
    mitre: list[MitreTechnique]
    timestamp: datetime  # time of the event that triggered the alert
    first_seen: datetime  # time of the earliest event in the evidence
    host: str | None
    group: dict[str, Any]
    count: int
    evidence: list[str]  # raw log lines, most recent MAX_EVIDENCE
    # Context copied from the triggering event (including enrichment).
    source: SourceInfo = Field(default_factory=SourceInfo)
    user: UserInfo = Field(default_factory=UserInfo)
    threat: ThreatInfo = Field(default_factory=ThreatInfo)
    # Set by app/scoring.py after detection.
    risk_score: int = 0
    risk_factors: list[str] = Field(default_factory=list)


@dataclass
class _SequenceState:
    started: datetime
    step: int = 0
    count: int = 1  # matches of the current step
    total: int = 1
    evidence: deque[str] = field(default_factory=lambda: deque(maxlen=MAX_EVIDENCE))


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._rules_by_id = {r.id: r for r in rules}
        # (rule_id, *group) -> deque of (timestamp, distinct value, raw line)
        self._windows: dict[tuple, deque[tuple[datetime, Any, str]]] = {}
        self._sequences: dict[tuple, _SequenceState] = {}
        self._processed = 0

    def process(self, event: NormalizedEvent) -> list[Alert]:
        doc = event.model_dump(mode="json")
        alerts = []
        for rule in self.rules:
            if rule.sequence:
                alert = self._sequence(rule, event, doc)
            elif not rule.selects(doc):
                continue
            elif rule.threshold:
                alert = self._threshold(rule, event, doc)
            else:
                alert = self._alert(rule, event, {}, 1, event.timestamp, [event.raw])
            if alert:
                alerts.append(alert)

        self._processed += 1
        if self._processed % SWEEP_EVERY == 0:
            self._sweep(event.timestamp)
        return alerts

    def _threshold(self, rule: Rule, event: NormalizedEvent, doc: dict) -> Alert | None:
        t = rule.threshold
        assert t is not None
        group = _group(t.group_by, doc)
        if group is None:
            return None

        key = (rule.id, *group)
        window = self._windows.setdefault(key, deque())
        window.append((event.timestamp, get_field(doc, t.distinct) if t.distinct else None, event.raw))
        cutoff = event.timestamp - t.window
        while window and window[0][0] < cutoff:
            window.popleft()

        if t.distinct:
            count = len({value for _, value, _ in window if value is not None})
        else:
            count = len(window)
        if count < t.count:
            return None

        # Reset so the next alert needs a fresh burst instead of firing per event.
        del self._windows[key]
        evidence = [raw for _, _, raw in window][-MAX_EVIDENCE:]
        return self._alert(rule, event, dict(zip(t.group_by, group)), count, window[0][0], evidence)

    def _sequence(self, rule: Rule, event: NormalizedEvent, doc: dict) -> Alert | None:
        seq = rule.sequence
        assert seq is not None
        group = _group(seq.group_by, doc)
        if group is None:
            return None

        key = (rule.id, *group)
        steps = seq.steps
        state = self._sequences.get(key)
        if state and event.timestamp - state.started > seq.window:
            del self._sequences[key]
            state = None

        if state is None:
            if not steps[0].selects(doc):
                return None
            state = self._sequences[key] = _SequenceState(started=event.timestamp)
        elif (
            state.count >= steps[state.step].min_count
            and state.step + 1 < len(steps)
            and steps[state.step + 1].selects(doc)
        ):
            state.step += 1
            state.count = 1
            state.total += 1
        elif steps[state.step].selects(doc):
            state.count += 1
            state.total += 1
        else:
            return None
        state.evidence.append(event.raw)

        last = len(steps) - 1
        if state.step < last or state.count < steps[last].min_count:
            return None
        del self._sequences[key]
        return self._alert(
            rule, event, dict(zip(seq.group_by, group)), state.total, state.started, list(state.evidence)
        )

    def _alert(
        self,
        rule: Rule,
        event: NormalizedEvent,
        group: dict[str, Any],
        count: int,
        first_seen: datetime,
        evidence: list[str],
    ) -> Alert:
        return Alert(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            mitre=rule.mitre,
            timestamp=event.timestamp,
            first_seen=first_seen,
            host=event.host.name,
            group=group,
            count=count,
            evidence=evidence,
            source=event.source.model_copy(deep=True),
            user=event.user.model_copy(),
            threat=event.threat.model_copy(deep=True),
        )

    def _sweep(self, now: datetime) -> None:
        """Drop state whose window has fully elapsed, so idle keys don't pile up."""
        for key, window in list(self._windows.items()):
            if not window or now - window[-1][0] > self._rules_by_id[key[0]].window:
                del self._windows[key]
        for key, state in list(self._sequences.items()):
            if now - state.started > self._rules_by_id[key[0]].window:
                del self._sequences[key]


def _group(fields: list[str], doc: dict) -> tuple | None:
    """Values of the group_by fields, or None if any is missing."""
    values = tuple(get_field(doc, f) for f in fields)
    return None if any(v is None for v in values) else values
