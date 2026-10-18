"""OSV range evaluation for proposed remediation versions (Phase 5).

Reconstructs the affected intervals of one advisory entry from the stored
``ranges_json`` payload (the same data the Phase 3 ``AFFECTED_BY`` edge
carries) and evaluates whether a proposed version leaves every affected
interval.

Rules:

* only ``ECOSYSTEM``/``SEMVER`` ranges are version-comparable — ``GIT``
  ranges and explicit per-version enumerations that are not stored cannot be
  evaluated, so the result is explicitly ``unknown``;
* a proposed version is only reported as ``resolves`` when the advisory's own
  range data supports it *and* the same reconstruction re-confirms that the
  current resolved version is affected;
* unparsable ranges/versions yield ``unknown`` — nothing is ever guessed or
  coerced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from packaging.version import Version

from app.remediation.versions import parse_version

STATUS_RESOLVES = "resolves"
STATUS_NOT_RESOLVING = "not_resolving"
STATUS_UNKNOWN = "unknown"

#: OSV range types whose versions follow the ecosystem's version ordering.
_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


@dataclass(frozen=True)
class RangeEvaluation:
    """Outcome of validating one proposed version against stored ranges."""

    status: str
    detail: str
    affected_intervals: int = 0

    @property
    def resolves(self) -> bool:
        return self.status == STATUS_RESOLVES


@dataclass(frozen=True)
class _Interval:
    """One affected interval: ``lower`` (inclusive) to ``upper`` if any."""

    lower: Version | None
    upper: Version | None
    upper_inclusive: bool

    def contains(self, version: Version) -> bool:
        if self.lower is not None and version < self.lower:
            return False
        if self.upper is None:
            return True
        if self.upper_inclusive:
            return version <= self.upper
        return version < self.upper


def _parse_ranges(ranges_json: str | None) -> tuple[list[dict[str, Any]], str | None]:
    if not ranges_json:
        return [], "no version ranges are stored for this finding"
    try:
        parsed = json.loads(ranges_json)
    except (TypeError, ValueError):
        return [], "the stored range data is not valid JSON"
    if not isinstance(parsed, list):
        return [], "the stored range data has an unexpected shape"
    return [item for item in parsed if isinstance(item, dict)], None


def _intervals_for_range(range_obj: dict[str, Any]) -> tuple[list[_Interval], str | None]:
    """Reconstruct the affected intervals of one OSV range object."""
    events = range_obj.get("events")
    if not isinstance(events, list):
        return [], "an affected range has no events"

    intervals: list[_Interval] = []
    open_lower: Version | None = None
    open_started = False

    for event in events:
        if not isinstance(event, dict):
            continue
        for key in ("introduced", "fixed", "last_affected", "limit"):
            raw = event.get(key)
            if raw is None:
                continue
            parsed = parse_version(str(raw))
            if key == "introduced":
                if open_started:  # a new interval starts without closing the previous one
                    intervals.append(_Interval(open_lower, None, False))
                if parsed is None:
                    return [], f"introduced version {raw!r} is not comparable"
                open_lower = parsed
                open_started = True
            elif key == "fixed":
                if not open_started:  # implied introduced = 0
                    open_lower = Version("0")
                    open_started = True
                if parsed is None:
                    return [], f"fixed version {raw!r} is not comparable"
                intervals.append(_Interval(open_lower, parsed, False))
                open_started = False
            elif key == "last_affected":
                if not open_started:
                    open_lower = Version("0")
                    open_started = True
                if parsed is None:
                    return [], f"last_affected version {raw!r} is not comparable"
                intervals.append(_Interval(open_lower, parsed, True))
                open_started = False
            elif key == "limit":
                if not open_started:
                    open_lower = Version("0")
                    open_started = True
                if parsed is None:
                    return [], f"limit version {raw!r} is not comparable"
                intervals.append(_Interval(open_lower, parsed, False))
                open_started = False
    if open_started:  # an interval with no upper bound: affected to infinity
        intervals.append(_Interval(open_lower, None, False))
    return intervals, None


def evaluate_proposed_version(
    ranges_json: str | None,
    current: str | None,
    proposed: str | None,
) -> RangeEvaluation:
    """Validate a proposed version against one finding's stored OSV ranges."""
    ranges, problem = _parse_ranges(ranges_json)
    if problem is not None:
        return RangeEvaluation(STATUS_UNKNOWN, problem)
    evaluable = [
        item
        for item in ranges
        if str(item.get("type") or "").strip().upper() in _VERSION_RANGE_TYPES
    ]
    if not evaluable:
        return RangeEvaluation(
            STATUS_UNKNOWN,
            "the matched advisory entry has no version-comparable ranges "
            "(e.g. GIT-only or an explicit version list that is not stored)",
        )

    intervals: list[_Interval] = []
    for range_obj in evaluable:
        built, problem = _intervals_for_range(range_obj)
        if problem is not None:
            return RangeEvaluation(
                STATUS_UNKNOWN,
                f"an affected range cannot be evaluated: {problem}",
                len(intervals),
            )
        intervals.extend(built)
    if not intervals:
        return RangeEvaluation(
            STATUS_UNKNOWN,
            "the matched advisory entry contains no affected interval to evaluate",
        )

    current_version = parse_version(current)
    if current_version is None:
        return RangeEvaluation(
            STATUS_UNKNOWN,
            f"the current resolved version {current!r} is not comparable",
            len(intervals),
        )
    proposed_version = parse_version(proposed)
    if proposed_version is None:
        return RangeEvaluation(
            STATUS_UNKNOWN,
            f"the proposed version {proposed!r} is not comparable",
            len(intervals),
        )

    if not any(interval.contains(current_version) for interval in intervals):
        return RangeEvaluation(
            STATUS_UNKNOWN,
            "the stored ranges do not re-confirm that the current resolved version is "
            "affected, so a fix cannot be validated from them",
            len(intervals),
        )
    if any(interval.contains(proposed_version) for interval in intervals):
        return RangeEvaluation(
            STATUS_NOT_RESOLVING,
            "the proposed version still falls inside an affected range of the matched advisory entry",
            len(intervals),
        )
    return RangeEvaluation(
        STATUS_RESOLVES,
        "no affected range of the matched advisory entry contains the proposed version",
        len(intervals),
    )


__all__ = [
    "RangeEvaluation",
    "STATUS_NOT_RESOLVING",
    "STATUS_RESOLVES",
    "STATUS_UNKNOWN",
    "evaluate_proposed_version",
]
