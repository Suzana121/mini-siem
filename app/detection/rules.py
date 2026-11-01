"""Detection rule format: a small, Sigma-inspired YAML dialect.

A rule is one of:

* single-event   -- `match` (+ optional `exclude`); fires on every matching event
* threshold      -- `match` + `threshold`; fires when N matching events (or N
                    distinct values of a field) occur within a time window,
                    counted separately per `group_by` key
* sequence       -- `sequence`; fires when ordered steps happen for the same
                    `group_by` key within a window (e.g. failures -> success)

Selections map field paths to expected values. All keys must match (AND); a
list of values means any of them (OR). Comparisons are case-insensitive.
Sigma-style modifiers: `field|contains`, `|startswith`, `|endswith`, `|re`.
"""

import re
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_MODIFIERS = {"eq", "contains", "startswith", "endswith", "re"}


def parse_duration(value: Any) -> timedelta:
    if isinstance(value, timedelta):
        return value
    match = _DURATION.match(str(value))
    if not match:
        raise ValueError(f"invalid duration '{value}', expected e.g. 30s, 5m, 1h")
    return timedelta(**{_UNITS[match[2]]: int(match[1])})


def get_field(doc: dict, path: str) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _normalize(value: Any) -> str:
    # Lowercasing also lets YAML `true` match the "true" strings parsers put in labels.
    return str(value).lower()


class _Condition:
    def __init__(self, key: str, expected: Any):
        self.field, _, modifier = key.partition("|")
        self.modifier = modifier or "eq"
        if self.modifier not in _MODIFIERS:
            raise ValueError(f"unknown modifier '{modifier}' in '{key}'")
        values = expected if isinstance(expected, list) else [expected]
        if self.modifier == "re":
            try:
                self.patterns = [re.compile(str(v), re.IGNORECASE) for v in values]
            except re.error as exc:
                raise ValueError(f"invalid regex in '{key}': {exc}") from exc
        else:
            self.values = [_normalize(v) for v in values]

    def matches(self, doc: dict) -> bool:
        actual = get_field(doc, self.field)
        if isinstance(actual, list):  # e.g. threat.feeds: any element may match
            return any(self._matches_value(item) for item in actual)
        return self._matches_value(actual)

    def _matches_value(self, actual: Any) -> bool:
        if actual is None:
            return False
        if self.modifier == "re":
            return any(p.search(str(actual)) for p in self.patterns)
        actual = _normalize(actual)
        if self.modifier == "eq":
            return actual in self.values
        if self.modifier == "contains":
            return any(v in actual for v in self.values)
        if self.modifier == "startswith":
            return any(actual.startswith(v) for v in self.values)
        return any(actual.endswith(v) for v in self.values)


class Selection:
    def __init__(self, spec: dict[str, Any]):
        if not spec:
            raise ValueError("selection must not be empty")
        self.conditions = [_Condition(k, v) for k, v in spec.items()]

    def matches(self, doc: dict) -> bool:
        return all(c.matches(doc) for c in self.conditions)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MitreTechnique(_Strict):
    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactic: str


class _Selects(_Strict):
    """Mixin for anything with match/exclude selections."""

    match: dict[str, Any]
    exclude: dict[str, Any] | None = None
    _match: Selection = PrivateAttr()
    _exclude: Selection | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _compile(self):
        self._match = Selection(self.match)
        self._exclude = Selection(self.exclude) if self.exclude else None
        return self

    def selects(self, doc: dict) -> bool:
        return self._match.matches(doc) and not (self._exclude and self._exclude.matches(doc))


class Threshold(_Strict):
    count: int = Field(ge=2)
    window: timedelta
    group_by: list[str] = Field(default_factory=list)
    distinct: str | None = None  # count unique values of this field instead of events

    _window = field_validator("window", mode="before")(parse_duration)


class Step(_Selects):
    name: str
    min_count: int = Field(default=1, ge=1)


class Sequence(_Strict):
    window: timedelta
    group_by: list[str] = Field(min_length=1)
    steps: list[Step] = Field(min_length=2)

    _window = field_validator("window", mode="before")(parse_duration)


class Rule(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    mitre: list[MitreTechnique] = Field(min_length=1)
    match: dict[str, Any] | None = None
    exclude: dict[str, Any] | None = None
    threshold: Threshold | None = None
    sequence: Sequence | None = None
    false_positives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    _match: Selection | None = PrivateAttr(default=None)
    _exclude: Selection | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _check_shape(self):
        if (self.match is None) == (self.sequence is None):
            raise ValueError("a rule needs exactly one of 'match' or 'sequence'")
        if self.sequence and (self.threshold or self.exclude):
            raise ValueError("'threshold' and 'exclude' are not allowed on sequence rules")
        if self.match is not None:
            self._match = Selection(self.match)
            self._exclude = Selection(self.exclude) if self.exclude else None
        return self

    def selects(self, doc: dict) -> bool:
        assert self._match is not None
        return self._match.matches(doc) and not (self._exclude and self._exclude.matches(doc))

    @property
    def window(self) -> timedelta:
        if self.sequence:
            return self.sequence.window
        return self.threshold.window if self.threshold else timedelta(0)


class RuleLoadError(Exception):
    pass


def load_rules(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    seen: dict[str, Path] = {}
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        try:
            rule = Rule.model_validate(yaml.safe_load(path.read_text()))
        except Exception as exc:
            raise RuleLoadError(f"{path.name}: {exc}") from exc
        if rule.id in seen:
            raise RuleLoadError(f"{path.name}: duplicate rule id '{rule.id}' (also in {seen[rule.id].name})")
        seen[rule.id] = path
        rules.append(rule)
    return rules
