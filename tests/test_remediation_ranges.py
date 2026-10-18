"""OSV range validation unit tests (Phase 5).

The rule under test: a proposed version is reported as ``resolves`` only when
the advisory's own stored range data supports it; anything unevaluable stays
``unknown`` and anything still inside an interval stays ``not_resolving``.
"""

from __future__ import annotations

import json

from app.remediation.ranges import (
    STATUS_NOT_RESOLVING,
    STATUS_RESOLVES,
    STATUS_UNKNOWN,
    evaluate_proposed_version,
)

from tests.remediation_support import ecosystem_range, ranges_json


def test_proposed_version_equal_to_fixed_boundary_resolves() -> None:
    evaluation = evaluate_proposed_version(
        ranges_json(ecosystem_range("0", fixed="2.32.1")), "2.32.0", "2.32.1"
    )
    assert evaluation.status == STATUS_RESOLVES
    assert evaluation.affected_intervals == 1


def test_proposed_version_above_fixed_boundary_resolves() -> None:
    evaluation = evaluate_proposed_version(
        ranges_json(ecosystem_range("0", fixed="2.32.1")), "2.32.0", "3.0.0"
    )
    assert evaluation.status == STATUS_RESOLVES


def test_proposed_version_inside_affected_interval_does_not_resolve() -> None:
    evaluation = evaluate_proposed_version(
        ranges_json(ecosystem_range("0", fixed="2.32.1")), "2.30.0", "2.31.0"
    )
    assert evaluation.status == STATUS_NOT_RESOLVING
    assert "still falls inside" in evaluation.detail


def test_last_affected_is_inclusive_and_above_it_resolves() -> None:
    ranges = ranges_json(ecosystem_range("0", last_affected="2.32.0"))
    assert evaluate_proposed_version(ranges, "2.31.0", "2.32.0").status == STATUS_NOT_RESOLVING
    assert evaluate_proposed_version(ranges, "2.31.0", "2.32.1").status == STATUS_RESOLVES


def test_limit_is_exclusive_and_below_it_does_not_resolve() -> None:
    ranges = ranges_json(ecosystem_range("0", limit="2.32.0"))
    assert evaluate_proposed_version(ranges, "2.31.0", "2.31.9").status == STATUS_NOT_RESOLVING
    assert evaluate_proposed_version(ranges, "2.31.0", "2.32.0").status == STATUS_RESOLVES


def test_multiple_intervals_in_one_range() -> None:
    events = [
        {"introduced": "0", "fixed": "2.32.1", "last_affected": None, "limit": None},
        {"introduced": "3.0.0", "fixed": "3.4.0", "last_affected": None, "limit": None},
    ]
    ranges = json.dumps([{"type": "ECOSYSTEM", "repo": None, "events": events}])
    # A version in the gap between the two affected branches leaves both.
    assert evaluate_proposed_version(ranges, "2.30.0", "2.35.0").status == STATUS_RESOLVES
    # The second branch still affects 3.1.0.
    assert evaluate_proposed_version(ranges, "2.30.0", "3.1.0").status == STATUS_NOT_RESOLVING
    # Fixing both branches is accepted.
    assert evaluate_proposed_version(ranges, "2.30.0", "3.4.0").status == STATUS_RESOLVES


def test_open_ended_range_never_resolves() -> None:
    events = [{"introduced": "0", "fixed": None, "last_affected": None, "limit": None}]
    ranges = json.dumps([{"type": "ECOSYSTEM", "repo": None, "events": events}])
    assert evaluate_proposed_version(ranges, "2.0.0", "99.0.0").status == STATUS_NOT_RESOLVING


def test_missing_or_unusable_range_data_is_unknown() -> None:
    assert evaluate_proposed_version(None, "2.0.0", "2.1.0").status == STATUS_UNKNOWN
    assert evaluate_proposed_version("", "2.0.0", "2.1.0").status == STATUS_UNKNOWN
    assert evaluate_proposed_version("{not json", "2.0.0", "2.1.0").status == STATUS_UNKNOWN
    assert evaluate_proposed_version('{"a": 1}', "2.0.0", "2.1.0").status == STATUS_UNKNOWN
    assert evaluate_proposed_version("[]", "2.0.0", "2.1.0").status == STATUS_UNKNOWN


def test_git_only_range_is_unknown() -> None:
    ranges = json.dumps(
        [{"type": "GIT", "repo": "https://example.test/repo", "events": [{"introduced": "abc"}]}]
    )
    evaluation = evaluate_proposed_version(ranges, "2.0.0", "2.1.0")
    assert evaluation.status == STATUS_UNKNOWN
    assert "version-comparable" in evaluation.detail


def test_unparsable_versions_are_unknown() -> None:
    ranges = ranges_json(ecosystem_range("0", fixed="2.32.1"))
    assert evaluate_proposed_version(ranges, "not-a-version", "2.32.1").status == STATUS_UNKNOWN
    assert evaluate_proposed_version(ranges, "2.30.0", "also-not").status == STATUS_UNKNOWN


def test_unparsable_range_events_are_unknown() -> None:
    ranges = json.dumps(
        [
            {
                "type": "ECOSYSTEM",
                "repo": None,
                "events": [{"introduced": "git:deadbeef", "fixed": None}],
            }
        ]
    )
    evaluation = evaluate_proposed_version(ranges, "2.30.0", "2.32.1")
    assert evaluation.status == STATUS_UNKNOWN
    assert "not comparable" in evaluation.detail


def test_current_version_not_reconfirmed_by_ranges_is_unknown() -> None:
    # OSV said the current version is affected, but the stored ranges disagree:
    # the validation must refuse rather than claim a fix.
    ranges = ranges_json(ecosystem_range("3.0.0", fixed="3.4.0"))
    evaluation = evaluate_proposed_version(ranges, "2.30.0", "3.5.0")
    assert evaluation.status == STATUS_UNKNOWN
    assert "re-confirm" in evaluation.detail


def test_ranges_without_events_are_unknown() -> None:
    ranges = json.dumps([{"type": "ECOSYSTEM", "repo": None, "events": []}])
    assert evaluate_proposed_version(ranges, "2.30.0", "2.32.1").status == STATUS_UNKNOWN


def test_any_containing_range_blocks_resolution() -> None:
    ranges = json.dumps(
        [
            {"type": "ECOSYSTEM", "repo": None, "events": [{"introduced": "0", "fixed": "2.32.1"}]},
            {"type": "ECOSYSTEM", "repo": None, "events": [{"introduced": "2.0.0", "fixed": "2.40.0"}]},
        ]
    )
    # 2.35.0 leaves the first range but is still inside the second one.
    assert evaluate_proposed_version(ranges, "2.30.0", "2.35.0").status == STATUS_NOT_RESOLVING
    assert evaluate_proposed_version(ranges, "2.30.0", "2.40.0").status == STATUS_RESOLVES
