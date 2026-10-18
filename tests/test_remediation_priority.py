"""Deterministic priority formula tests (Phase 5).

The BlastRadius priority score is a *custom* documented score.  These tests
pin the arithmetic, the normalization of every factor, the neutral handling of
missing data and the deterministic tie-break order.  Nothing here involves an
LLM, a network call or a graph database.
"""

from __future__ import annotations

from app.remediation.priority import (
    FACTOR_WEIGHTS,
    FORMULA_VERSION,
    MAX_DEPENDENT_COMPONENTS,
    NEUTRAL,
    REACHABILITY_VALUES,
    compute_priority,
    impact_factor,
    prioritize,
    remediation_factor,
    severity_factor,
)
from app.remediation.severity import parse_advisory_severity
from tests.remediation_support import make_input


def _score(inputs, *, edges: bool = True, entries: bool = True) -> float:
    _severity, _reachability, _factors, score = compute_priority(
        inputs,
        graph_has_dependency_edges=edges,
        entry_packages_defined=entries,
    )
    return score


# ---------------------------------------------------------------------------
# formula and factor arithmetic
# ---------------------------------------------------------------------------

def test_documented_formula_and_weights() -> None:
    assert FORMULA_VERSION == "blastradius-priority-v1"
    assert FACTOR_WEIGHTS == {
        "severity": 0.40,
        "reachability": 0.30,
        "impact": 0.20,
        "remediation": 0.10,
    }
    assert sum(FACTOR_WEIGHTS.values()) == 1.0


def test_score_matches_documented_arithmetic() -> None:
    # severity 9.8 -> 0.98, direct -> 1.0, no dependents -> 0.0, fix -> 1.0
    # 100 * (0.40*0.98 + 0.30*1.0 + 0.20*0.0 + 0.10*1.0) = 79.2
    severity, reachability, factors, score = compute_priority(
        make_input(),
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )
    assert score == 79.2
    assert severity.numeric_score == 9.8
    assert reachability.status == "direct"

    by_name = {factor.name: factor for factor in factors}
    assert list(by_name) == ["severity", "reachability", "impact", "remediation"]
    assert by_name["severity"].normalized == 0.98
    assert by_name["severity"].contribution == 0.392
    assert by_name["reachability"].normalized == 1.0
    assert by_name["reachability"].contribution == 0.3
    assert by_name["impact"].normalized == 0.0
    assert by_name["impact"].contribution == 0.0
    assert by_name["remediation"].normalized == 1.0
    assert by_name["remediation"].contribution == 0.1
    assert round(sum(factor.contribution for factor in factors), 4) == 0.792


def test_missing_severity_is_neutral_not_zero() -> None:
    severity = parse_advisory_severity(())
    assert severity.numeric_score is None
    assert severity.quantified is False

    factor = severity_factor(severity)
    assert factor.normalized == NEUTRAL
    assert factor.contribution == 0.2
    assert "no severity entries" in factor.notes[0]

    # direct + no impact + advisory fix: 100 * (0.20 + 0.30 + 0.10) = 60
    assert _score(make_input(severities=())) == 60.0


def test_vector_only_severity_is_never_turned_into_a_cvss_score() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    severity = parse_advisory_severity((f"CVSS_V3 {vector}",))
    assert severity.quantified is False
    assert severity.numeric_score is None
    assert severity.vector == vector
    assert severity.vector_types == ["CVSS_V3"]
    assert "never computes scores from vectors" in severity.note

    factor = severity_factor(severity)
    assert factor.normalized == NEUTRAL
    assert factor.raw["quantified"] is False
    assert factor.raw["numeric_score"] is None
    assert factor.raw["vector_types"] == ["CVSS_V3"]


def test_highest_reported_numeric_severity_wins() -> None:
    severity = parse_advisory_severity(("CVSS_V3 6.5", "CVSS_V4 8.1", "CVSS_V2 5.0"))
    assert severity.numeric_score == 8.1
    assert severity.score_type == "CVSS_V4"
    assert severity.quantified is True


def test_unquantified_entries_do_not_create_a_score() -> None:
    severity = parse_advisory_severity(("MODERATE", "CVSS_V3 not-a-number"))
    assert severity.numeric_score is None
    assert severity.quantified is False
    assert severity.entries == ["MODERATE", "CVSS_V3 not-a-number"]


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------

def test_reachability_tiers() -> None:
    assert REACHABILITY_VALUES == {
        "direct": 1.0,
        "reachable_from_entry": 0.75,
        "not_reachable": 0.35,
        "unavailable": 0.5,
    }

    direct = compute_priority(
        make_input(dependency_role="direct"),
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )[1]
    assert direct.status == "direct"
    assert direct.evidence_available is True

    reachable = compute_priority(
        make_input(dependency_role="transitive", entry_points=("demo-app",), entry_min_hops=2),
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )[1]
    assert reachable.status == "reachable_from_entry"
    assert reachable.entry_points == ["demo-app"]
    assert reachable.min_hops == 2

    # The graph had everything needed to look and found no path.
    not_reachable = compute_priority(
        make_input(dependency_role="transitive"),
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )[1]
    assert not_reachable.status == "not_reachable"
    assert not_reachable.evidence_available is True

    # No dependency edges at all: evidence is unavailable, not "not reachable".
    unavailable = compute_priority(
        make_input(dependency_role="transitive"),
        graph_has_dependency_edges=False,
        entry_packages_defined=False,
    )[1]
    assert unavailable.status == "unavailable"
    assert unavailable.evidence_available is False


def test_no_modeled_path_is_never_scored_as_zero_risk() -> None:
    score = _score(make_input(dependency_role="transitive"), edges=True, entries=True)
    # 100 * (0.392 + 0.30*0.35 + 0.0 + 0.10) = 59.7
    assert score == 59.7
    assert score > 0.0


def test_root_project_is_an_entry_point_even_when_not_direct() -> None:
    reachability = compute_priority(
        make_input(dependency_role="unknown", is_root_project=True),
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )[1]
    assert reachability.status == "direct"


def test_reachability_notes_explain_missing_evidence() -> None:
    factor = compute_priority(
        make_input(dependency_role="transitive"),
        graph_has_dependency_edges=False,
        entry_packages_defined=False,
    )[2][1]
    assert "does not contain the dependency edges/entry points" in factor.notes[0]


# ---------------------------------------------------------------------------
# impact
# ---------------------------------------------------------------------------

def test_impact_uses_the_documented_log_scale() -> None:
    assert impact_factor(0).normalized == 0.0
    assert impact_factor(1).normalized == 0.3333
    assert impact_factor(3).normalized == 0.6667
    assert impact_factor(7).normalized == 1.0
    assert impact_factor(1000).normalized == 1.0

    factor = impact_factor(1)
    assert factor.contribution == 0.0667
    assert factor.raw == {"dependent_component_count": 1}
    assert "distinct packages" in factor.notes[0]


def test_negative_dependent_count_is_clamped() -> None:
    assert impact_factor(-5).normalized == 0.0


# ---------------------------------------------------------------------------
# remediation availability
# ---------------------------------------------------------------------------

def test_remediation_factor_reflects_advisory_evidence_only() -> None:
    available = remediation_factor(("2.32.1",))
    assert available.normalized == 1.0
    assert available.contribution == 0.1
    assert available.raw["available"] is True
    assert "2.32.1" in available.notes[0]

    missing = remediation_factor(())
    assert missing.normalized == 0.25
    assert missing.contribution == 0.025
    assert missing.raw["available"] is False
    assert "no fixed version" in missing.notes[0]

    # No fix is not zero risk: 100 * (0.392 + 0.30 + 0.0 + 0.025) = 71.7
    assert _score(make_input(fixed_versions=())) == 71.7


# ---------------------------------------------------------------------------
# ranking and determinism
# ---------------------------------------------------------------------------

def test_prioritize_ranks_by_score_descending() -> None:
    high = make_input(finding_id="finding_high", severities=("CVSS_V3 10.0",))
    low = make_input(finding_id="finding_low", severities=("CVSS_V3 4.0",))
    ranked = prioritize(
        [low, high], graph_has_dependency_edges=True, entry_packages_defined=True
    )
    assert [item.inputs.finding_id for item in ranked] == ["finding_high", "finding_low"]
    assert [item.priority.rank for item in ranked] == [1, 2]
    assert ranked[0].priority.score > ranked[1].priority.score


def test_equal_scores_tie_break_on_advisory_severity_then_finding_id() -> None:
    # Both score 52.5 with no advisory fix.
    #   A: severity 9.875 (0.9875) and no modeled path (0.35)
    #   B: severity 5.0   (0.5)    and direct        (1.0)
    # Tie-break 1 (higher advisory numeric severity) puts A first even though
    # B is more reachable; B and C then tie-break by finding_id ascending.
    inputs = [
        make_input(
            finding_id="finding_c",
            severities=("CVSS_V3 5.0",),
            dependency_role="direct",
            fixed_versions=(),
        ),
        make_input(
            finding_id="finding_a",
            severities=("CVSS_V3 9.875",),
            dependency_role="transitive",
            fixed_versions=(),
        ),
        make_input(
            finding_id="finding_b",
            severities=("CVSS_V3 5.0",),
            dependency_role="direct",
            fixed_versions=(),
        ),
    ]
    ranked = prioritize(
        inputs, graph_has_dependency_edges=True, entry_packages_defined=True
    )
    assert [item.inputs.finding_id for item in ranked] == [
        "finding_a",
        "finding_b",
        "finding_c",
    ]
    assert {item.priority.score for item in ranked} == {52.5}
    assert [item.priority.rank for item in ranked] == [1, 2, 3]


def test_missing_numeric_severity_sorts_last_among_equal_scores() -> None:
    quantified = make_input(finding_id="finding_quantified", severities=("CVSS_V3 5.0",))
    unquantified = make_input(
        finding_id="finding_unquantified",
        severities=("CVSS_V3 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",),
    )
    # Not an equal-score test: it pins that a vector-only advisory never gains a
    # numeric score and is ranked below a finding whose advisory reports one.
    ranked = prioritize(
        [unquantified, quantified],
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )
    assert [item.inputs.finding_id for item in ranked] == [
        "finding_quantified",
        "finding_unquantified",
    ]


def test_same_input_always_produces_the_same_ranking() -> None:
    inputs = [
        make_input(finding_id=f"finding_{index}", severities=(f"CVSS_V3 {5 + index}",))
        for index in range(5)
    ]
    first = prioritize(inputs, graph_has_dependency_edges=True, entry_packages_defined=True)
    shuffled = [inputs[3], inputs[0], inputs[4], inputs[1], inputs[2]]
    second = prioritize(
        shuffled, graph_has_dependency_edges=True, entry_packages_defined=True
    )
    assert [
        (item.inputs.finding_id, item.priority.score, item.priority.rank) for item in first
    ] == [
        (item.inputs.finding_id, item.priority.score, item.priority.rank) for item in second
    ]


def test_dependent_components_are_bounded_and_flagged() -> None:
    dependents = tuple(f"dependent_{index:02d}" for index in range(30))
    ranked = prioritize(
        [
            make_input(
                dependent_components=dependents,
                dependent_component_count=30,
            )
        ],
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )
    reachability = ranked[0].priority.reachability
    assert reachability.dependent_component_count == 30
    assert len(reachability.dependent_components) == MAX_DEPENDENT_COMPONENTS == 25
    assert reachability.dependent_components_truncated is True
    assert reachability.dependent_components[0] == "dependent_00"


def test_scope_exposure_is_derived_from_package_flags() -> None:
    cases = {
        "dev": make_input(is_dev=True, is_optional=True),
        "optional": make_input(is_optional=True),
        "runtime": make_input(dependency_role="transitive"),
        "unknown": make_input(dependency_role="unknown"),
    }
    for expected, item in cases.items():
        ranked = prioritize(
            [item], graph_has_dependency_edges=True, entry_packages_defined=True
        )
        assert ranked[0].priority.reachability.scope_exposure == expected


def test_priority_records_severity_and_remediation_separately() -> None:
    ranked = prioritize(
        [make_input(severities=("CVSS_V3 9.8",))],
        graph_has_dependency_edges=True,
        entry_packages_defined=True,
    )
    priority = ranked[0].priority
    assert priority.severity.numeric_score == 9.8
    assert priority.score == 79.2
    assert priority.remediation_available is True
    assert priority.formula_version == FORMULA_VERSION
    assert "no fixed version" not in (priority.remediation_note or "")
