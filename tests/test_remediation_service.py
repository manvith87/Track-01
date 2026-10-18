"""End-to-end service tests for deterministic prioritization/remediation (Phase 5).

The real ``RemediationService`` runs against canned graph query results through
``FakeGraphClient``: nothing is mocked at the service boundary, so ranking,
candidate selection, range validation, grouping and truncation are exercised
as production code.  No network, no FalkorDB, no LLM.
"""

from __future__ import annotations

import pytest

from app.graph.errors import GraphRecordNotFoundError
from app.models.ids import stable_id
from app.remediation.service import (
    MAX_UNRESOLVED_RELATIONSHIPS,
    RemediationService,
)
from tests.remediation_support import (
    ANALYSIS,
    COMMIT,
    PKG_REQUESTS,
    PKG_URLLIB3,
    REPO,
    VULN_REQUESTS,
    VULN_URLLIB3,
    analysis_row,
    declaration_row,
    ecosystem_range,
    edge_row,
    finding_row,
    install,
    make_service,
    package_row,
    ranges_json,
    urllib3_finding_row,
    urllib3_package_row,
)
from tests.support import FakeGraphClient


def _service(**kwargs) -> RemediationService:
    client = FakeGraphClient()
    install(client, **kwargs)
    return make_service(client)


def _finding_id(analysis_id: str, package_id: str, vulnerability_id: str) -> str:
    return stable_id("finding", analysis_id, package_id, vulnerability_id)


def _group_id(analysis_id: str, package_id: str, version: str) -> str:
    return stable_id("fixgroup", analysis_id, package_id, version)


# ---------------------------------------------------------------------------
# default scenario
# ---------------------------------------------------------------------------

def test_default_report_is_complete_and_ranked() -> None:
    service = _service()
    report = service.analyze(ANALYSIS)

    assert report.analysis_id == ANALYSIS
    assert report.repository_id == REPO
    assert report.commit_sha == COMMIT
    assert report.context.complete is True
    assert report.context.analysis_status == "success"
    assert report.context.resolved_packages == 2
    assert report.context.dependency_edges == 1
    assert report.context.vulnerability_edges == 2
    assert report.context.notes == []

    assert [finding.vulnerability_id for finding in report.findings] == [
        VULN_REQUESTS,
        VULN_URLLIB3,
    ]
    assert [finding.priority.rank for finding in report.findings] == [1, 2]
    assert [finding.priority.score for finding in report.findings] == [79.2, 46.5]
    assert report.findings[0].confidence == "verified"
    assert report.findings[0].confidence_reasons == []
    assert report.findings[0].package.package_name == "requests"

    # Scope facts are carried verbatim, not re-derived.
    assert report.findings[0].analysis_id == ANALYSIS
    assert report.findings[0].repository_id == REPO
    assert report.findings[0].commit_sha == COMMIT
    assert report.findings[0].aliases == ["CVE-2026-0001"]
    assert report.findings[0].advisory_references == [
        "ADVISORY https://example.test/advisory/1"
    ]
    assert report.findings[0].fixed_versions == ["2.32.1"]

    # One plan per affected package, in ranked-finding order.
    assert [plan.package_name for plan in report.plans] == ["requests", "urllib3"]

    requests_plan = report.plans[0]
    assert requests_plan.finding_ids == [
        _finding_id(ANALYSIS, PKG_REQUESTS, VULN_REQUESTS)
    ]
    assert requests_plan.no_candidate_reason is None
    assert len(requests_plan.candidates) == 1
    candidate = requests_plan.candidates[0]
    assert candidate.selected is True
    assert candidate.proposed_version == "2.32.1"
    assert candidate.origin == "osv_fixed_version"
    assert candidate.current_version == "2.32.0"
    assert candidate.resolver_executed is False
    assert candidate.compatibility == "constraints_satisfied"
    assert candidate.resolved_finding_ids == requests_plan.finding_ids
    assert candidate.unknown_finding_ids == []
    assert candidate.unresolved_finding_ids == []
    assert [check.origin for check in candidate.constraint_checks] == [
        "pyproject.toml:12",
        "from demo-app 0.1.0",
    ]
    assert all(check.satisfied is True for check in candidate.constraint_checks)
    assert candidate.resolves[0].status == "resolves"
    assert candidate.resolves[0].affected_intervals_reconstructed == 1

    urllib3_plan = report.plans[1]
    urllib3_candidate = urllib3_plan.candidates[0]
    assert urllib3_candidate.compatibility == "unverified"
    assert "no recorded constraints" in urllib3_candidate.compatibility_detail
    assert urllib3_candidate.resolved_finding_ids == urllib3_plan.finding_ids
    assert any("no direct dependent" in item for item in urllib3_plan.migration_concerns)

    # Two distinct packages => two groups, no finding counted twice.
    assert [group.package_name for group in report.groups] == ["requests", "urllib3"]
    assert [group.ranking.rank for group in report.groups] == [1, 2]
    requests_group = report.groups[0]
    assert requests_group.group_id == _group_id(ANALYSIS, PKG_REQUESTS, "2.32.1")
    assert requests_group.coverage == "confirmed_advisory"
    assert requests_group.verified_resolved_finding_ids == requests_plan.finding_ids
    assert requests_group.potential_resolved_finding_ids == []
    assert requests_group.ranking.verified_resolved_count == 1
    assert requests_group.ranking.verified_resolved_priority_sum == 79.2
    assert requests_group.ranking.reachable_resolved_count == 1
    assert requests_group.ranking.compatibility_tier == 2
    assert requests_group.ranking.compatibility_tier_label == "constraints_satisfied"
    assert requests_group.advisory_evidence[0].vulnerability_id == VULN_REQUESTS
    assert requests_group.candidates[0].selected is True

    urllib3_group = report.groups[1]
    assert urllib3_group.coverage == "confirmed_advisory"
    assert urllib3_group.ranking.compatibility_tier == 1
    assert urllib3_group.ranking.compatibility_tier_label == "unverified"

    seen: list[str] = []
    for group in report.groups:
        seen.extend(group.verified_resolved_finding_ids)
        seen.extend(group.potential_resolved_finding_ids)
        seen.extend(group.unresolved_finding_ids)
    assert sorted(seen) == sorted(finding.finding_id for finding in report.findings)

    assert report.unresolved_findings == []
    assert report.limitations == ["reachability_traversal_bounded_at_5_hops"]


def test_repeated_analysis_is_byte_for_byte_identical() -> None:
    service = _service()
    first = service.analyze(ANALYSIS).model_dump()
    second = service.analyze(ANALYSIS).model_dump()
    assert first == second


def test_service_issues_read_queries_only() -> None:
    client = FakeGraphClient()
    install(client)
    service = make_service(client)
    service.analyze(ANALYSIS)

    write_markers = ("CREATE ", "MERGE (", "DELETE ", " SET ", "REMOVE ")
    for cypher, _params in client.queries:
        upper = cypher.upper()
        assert not any(marker in upper for marker in write_markers), cypher
    assert client.nodes == {}
    assert client.affected_by == {}


# ---------------------------------------------------------------------------
# finding detail
# ---------------------------------------------------------------------------

def test_finding_detail_returns_plan_and_is_scoped_to_the_analysis() -> None:
    service = _service()
    finding_id = _finding_id(ANALYSIS, PKG_REQUESTS, VULN_REQUESTS)

    finding, plan, limitations = service.find_finding(ANALYSIS, finding_id)
    assert finding.finding_id == finding_id
    assert finding.priority.score == 79.2
    assert plan is not None
    assert plan.package_id == PKG_REQUESTS
    assert plan.candidates[0].proposed_version == "2.32.1"
    assert limitations == ["reachability_traversal_bounded_at_5_hops"]

    # A finding id minted for another analysis is not visible here.
    other_analysis_id = _finding_id("analysis_other", PKG_REQUESTS, VULN_REQUESTS)
    with pytest.raises(GraphRecordNotFoundError) as excinfo:
        service.find_finding(ANALYSIS, other_analysis_id)
    assert excinfo.value.details == {
        "analysis_id": ANALYSIS,
        "finding_id": other_analysis_id,
    }

    with pytest.raises(GraphRecordNotFoundError):
        service.find_finding(ANALYSIS, "finding_does_not_exist")


def test_group_detail_is_scoped_to_the_analysis() -> None:
    service = _service()
    group_id = _group_id(ANALYSIS, PKG_REQUESTS, "2.32.1")

    group, limitations = service.find_group(ANALYSIS, group_id)
    assert group.group_id == group_id
    assert group.package_name == "requests"
    assert group.ranking.verified_resolved_count == 1
    assert limitations == ["reachability_traversal_bounded_at_5_hops"]

    with pytest.raises(GraphRecordNotFoundError) as excinfo:
        service.find_group(
            ANALYSIS, _group_id("analysis_other", PKG_REQUESTS, "2.32.1")
        )
    assert excinfo.value.details == {
        "analysis_id": ANALYSIS,
        "group_id": _group_id("analysis_other", PKG_REQUESTS, "2.32.1"),
    }


def test_empty_identifiers_are_rejected() -> None:
    service = _service()
    with pytest.raises(Exception) as excinfo:
        service.find_finding(ANALYSIS, "   ")
    assert "finding_id must not be empty" in str(excinfo.value)
    with pytest.raises(Exception) as excinfo:
        service.find_group(ANALYSIS, "")
    assert "group_id must not be empty" in str(excinfo.value)


# ---------------------------------------------------------------------------
# missing data: no advisory fix, missing ids, partial analysis
# ---------------------------------------------------------------------------

def test_no_advisory_fixed_version_yields_no_candidate_and_an_explicit_reason() -> None:
    service = _service(
        packages=[package_row()],
        declarations=[],
        edges=[],
        findings=[
            finding_row(
                fixed_versions=[],
                ranges_json=None,
                severities=("CVSS_V3 7.0",),
            )
        ],
    )
    report = service.analyze(ANALYSIS)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.fixed_versions == []
    assert finding.priority.remediation_available is False
    assert finding.priority.score == 60.5

    plan = report.plans[0]
    assert plan.candidates == []
    assert "no advisory fixed version" in (plan.no_candidate_reason or "")
    assert len(plan.limitations) == 1

    assert report.groups == []
    assert [item.finding_id for item in report.unresolved_findings] == [
        finding.finding_id
    ]
    assert "no advisory fixed version" in report.unresolved_findings[0].reason
    assert report.context.dependency_edges == 0
    assert "no_modeled_dependency_edges" in report.limitations


def test_missing_ids_skip_the_row_instead_of_fabricating_a_finding() -> None:
    service = _service(
        packages=[package_row()],
        declarations=[],
        edges=[],
        findings=[
            finding_row(vulnerability_id=None),
            finding_row(package_id=None, vulnerability_id="GHSA-orphan"),
        ],
    )
    report = service.analyze(ANALYSIS)

    assert report.findings == []
    assert report.plans == []
    assert report.groups == []
    assert report.unresolved_findings == []


def test_partial_analysis_reduces_confidence_with_reasons() -> None:
    service = _service(
        analysis=analysis_row(status="partial", warning_count=2, error_count=1)
    )
    report = service.analyze(ANALYSIS)

    assert report.context.complete is False
    assert report.context.analysis_status == "partial"
    assert report.context.warning_count == 2
    assert report.context.error_count == 1
    assert any("status is 'partial'" in note for note in report.context.notes)
    assert any("1 error" in note for note in report.context.notes)
    assert any("2 warning" in note for note in report.context.notes)

    assert report.findings
    for finding in report.findings:
        assert finding.confidence == "reduced"
        assert len(finding.confidence_reasons) == 1
        assert "status is 'partial'" in finding.confidence_reasons[0]
        assert "errors=1" in finding.confidence_reasons[0]
        assert "warnings=2" in finding.confidence_reasons[0]


def test_analysis_without_repository_scope_is_not_found() -> None:
    service = _service(analysis=analysis_row(repository_id="", commit_sha=""))
    with pytest.raises(GraphRecordNotFoundError) as excinfo:
        service.analyze(ANALYSIS)
    assert "no associated repository/commit" in excinfo.value.message
    assert excinfo.value.details == {"analysis_id": ANALYSIS}


def test_analysis_context_reports_ingestion_quality_flags() -> None:
    service = _service(
        analysis=analysis_row(
            unknown_relation_packages=3,
            conflicting_packages=2,
            unsupported_formats=1,
        )
    )
    report = service.analyze(ANALYSIS)
    notes = "\n".join(report.context.notes)
    assert "3 resolved package(s) lack" in notes
    assert "2 conflicting package record(s)" in notes
    assert "1 manifest(s) use unsupported formats" in notes
    # Ingestion warnings/flags do not make a successful analysis incomplete.
    assert report.context.complete is True


# ---------------------------------------------------------------------------
# compatibility evidence
# ---------------------------------------------------------------------------

def test_exact_pin_violation_is_reported_not_hidden() -> None:
    service = _service(
        declarations=[
            declaration_row(
                version_constraint="==2.32.0",
                is_exact_pin=True,
                manifest_path="requirements.txt",
                line_number=3,
            )
        ],
        edges=[],
    )
    report = service.analyze(ANALYSIS)

    candidate = report.plans[0].candidates[0]
    assert candidate.selected is True
    assert candidate.proposed_version == "2.32.1"
    assert candidate.compatibility == "constraints_violated"
    assert "reject the proposed version" in candidate.compatibility_detail
    checks = candidate.constraint_checks
    assert len(checks) == 1
    assert checks[0].origin == "requirements.txt:3 (exact pin)"
    assert checks[0].constraint == "==2.32.0"
    assert checks[0].satisfied is False
    assert any("reject this proposed version" in item for item in candidate.limitations)

    group = report.groups[0]
    assert group.coverage == "confirmed_advisory"
    assert group.ranking.compatibility_tier == 0
    assert group.ranking.compatibility_tier_label == "constraints_violated"
    # Compatibility being violated does not corrupt the verified resolution count.
    assert group.ranking.verified_resolved_count == 1


def test_poetry_constraint_stays_unverified() -> None:
    service = _service(
        declarations=[
            declaration_row(version_constraint="^2.32", constraint_scheme="poetry")
        ],
        edges=[],
    )
    report = service.analyze(ANALYSIS)

    candidate = report.plans[0].candidates[0]
    assert candidate.compatibility == "unverified"
    assert candidate.constraint_checks[0].satisfied is None
    assert candidate.constraint_checks[0].scheme == "poetry"
    assert "cannot be evaluated" in candidate.constraint_checks[0].detail
    assert any("no resolver was executed" in item for item in candidate.limitations)

    group = report.groups[0]
    assert group.ranking.compatibility_tier == 1
    # Range evidence is still independent of compatibility.
    assert group.ranking.verified_resolved_count == 1


def test_no_recorded_constraints_is_unverified_not_satisfied() -> None:
    service = _service(declarations=[], edges=[])
    candidate = service.analyze(ANALYSIS).plans[0].candidates[0]
    assert candidate.constraint_checks == []
    assert candidate.compatibility == "unverified"
    assert candidate.resolver_executed is False


# ---------------------------------------------------------------------------
# candidate selection and grouping
# ---------------------------------------------------------------------------

def test_candidate_with_most_verified_resolutions_is_selected() -> None:
    service = _service(
        packages=[package_row()],
        declarations=[],
        edges=[],
        findings=[
            finding_row(
                vulnerability_id="GHSA-multi-a",
                summary="Advisory A",
                fixed_versions=["2.32.1"],
                ranges_json=ranges_json(ecosystem_range("0", fixed="2.32.1")),
                severities=("CVSS_V3 9.8",),
            ),
            finding_row(
                vulnerability_id="GHSA-multi-b",
                summary="Advisory B",
                fixed_versions=["2.32.2"],
                ranges_json=ranges_json(ecosystem_range("0", fixed="2.32.2")),
                severities=("CVSS_V3 6.5",),
            ),
        ],
    )
    report = service.analyze(ANALYSIS)

    plan = report.plans[0]
    assert [candidate.proposed_version for candidate in plan.candidates] == [
        "2.32.2",
        "2.32.1",
    ]
    selected, alternate = plan.candidates
    assert selected.selected is True
    assert alternate.selected is False
    assert len(selected.resolved_finding_ids) == 2
    assert alternate.resolved_finding_ids == [
        _finding_id(ANALYSIS, PKG_REQUESTS, "GHSA-multi-a")
    ]
    assert alternate.unresolved_finding_ids == [
        _finding_id(ANALYSIS, PKG_REQUESTS, "GHSA-multi-b")
    ]

    assert len(report.groups) == 1
    group = report.groups[0]
    assert group.proposed_version == "2.32.2"
    assert group.ranking.verified_resolved_count == 2
    expected_priority_sum = round(sum(f.priority.score for f in report.findings), 2)
    assert group.ranking.verified_resolved_priority_sum == expected_priority_sum
    assert group.ranking.highest_finding_priority == max(
        f.priority.score for f in report.findings
    )
    assert group.coverage == "confirmed_advisory"
    assert len(group.resolved_findings) == 2

    # Every finding appears exactly once in the grouped accounting.
    accounted = [
        *group.verified_resolved_finding_ids,
        *group.potential_resolved_finding_ids,
        *group.unresolved_finding_ids,
    ]
    assert sorted(accounted) == sorted(f.finding_id for f in report.findings)
    assert report.unresolved_findings == []


def test_group_ranking_uses_verified_count_before_priority_sum() -> None:
    # urllib3 has two low-priority findings (verified count 2, priority sum 50)
    # while requests has one high-priority finding (count 1, sum 80).
    # The documented order ranks by verified count first.
    service = _service(
        edges=[],
        declarations=[],
        findings=[
            urllib3_finding_row(
                vulnerability_id="GHSA-low-a",
                severities=("CVSS_V3 0.0",),
                fixed_versions=["2.0.7"],
                ranges_json=ranges_json(ecosystem_range("0", fixed="2.0.7")),
            ),
            urllib3_finding_row(
                vulnerability_id="GHSA-low-b",
                severities=("CVSS_V3 0.0",),
                fixed_versions=["2.0.7"],
                ranges_json=ranges_json(ecosystem_range("0", fixed="2.0.7")),
            ),
            finding_row(
                severities=("CVSS_V3 10.0",),
            ),
        ],
    )
    report = service.analyze(ANALYSIS)

    assert [group.package_name for group in report.groups] == ["urllib3", "requests"]
    first, second = report.groups
    assert first.ranking.verified_resolved_count == 2
    assert first.ranking.verified_resolved_priority_sum == 50.0
    assert second.ranking.verified_resolved_count == 1
    assert second.ranking.verified_resolved_priority_sum == 80.0


def test_not_resolving_candidate_is_visible_and_not_counted_as_coverage() -> None:
    service = _service(
        packages=[package_row()],
        declarations=[],
        edges=[],
        findings=[
            finding_row(
                fixed_versions=["2.32.1"],
                ranges_json=ranges_json(ecosystem_range("0", fixed="2.33.0")),
            )
        ],
    )
    report = service.analyze(ANALYSIS)

    candidate = report.plans[0].candidates[0]
    assert candidate.resolves[0].status == "not_resolving"
    assert candidate.resolved_finding_ids == []
    assert candidate.unknown_finding_ids == []
    assert len(candidate.unresolved_finding_ids) == 1

    group = report.groups[0]
    assert group.coverage == "no_advisory_resolution"
    assert group.ranking.verified_resolved_count == 0
    assert group.ranking.verified_resolved_priority_sum == 0.0

    assert [item.finding_id for item in report.unresolved_findings] == [
        report.findings[0].finding_id
    ]
    assert "does not support" in report.unresolved_findings[0].reason


def test_unknown_range_data_is_potential_coverage_only() -> None:
    service = _service(
        packages=[package_row()],
        declarations=[],
        edges=[],
        findings=[
            finding_row(
                fixed_versions=["2.32.1"],
                ranges_json=ranges_json({"type": "GIT", "repo": "https://x.test/r", "events": []}),
            )
        ],
    )
    report = service.analyze(ANALYSIS)

    candidate = report.plans[0].candidates[0]
    assert candidate.resolves[0].status == "unknown"
    assert candidate.resolved_finding_ids == []
    assert len(candidate.unknown_finding_ids) == 1
    assert candidate.unresolved_finding_ids == []
    assert any("could not be validated" in item for item in candidate.limitations)

    group = report.groups[0]
    assert group.coverage == "potential_only"
    assert group.potential_resolved_finding_ids == candidate.unknown_finding_ids
    assert group.ranking.verified_resolved_count == 0
    # Unknown coverage is reported, but never treated as a verified resolution.
    assert report.unresolved_findings == []


# ---------------------------------------------------------------------------
# entry paths / dependent impact
# ---------------------------------------------------------------------------

def test_entry_path_and_impact_rows_feed_reachability_and_groups() -> None:
    service = _service(
        entry_rows=[
            {"package_id": PKG_URLLIB3, "entry_points": ["demo-app"], "min_hops": 2}
        ],
        impact_rows=[
            {
                "package_id": PKG_REQUESTS,
                "dependents": ["demo-app"],
                "dependent_count": 1,
                "min_hops": 1,
            },
            {
                "package_id": PKG_URLLIB3,
                "dependents": ["requests"],
                "dependent_count": 1,
                "min_hops": 1,
            },
        ],
    )
    report = service.analyze(ANALYSIS)

    requests, urllib3 = report.findings
    assert requests.priority.reachability.status == "direct"
    assert requests.priority.reachability.dependent_component_count == 1
    assert requests.priority.reachability.dependent_components == ["demo-app"]
    assert requests.priority.score == 85.87

    assert urllib3.priority.reachability.status == "reachable_from_entry"
    assert urllib3.priority.reachability.entry_points == ["demo-app"]
    assert urllib3.priority.reachability.min_hops == 2
    assert urllib3.priority.reachability.dependent_components == ["requests"]
    assert urllib3.priority.score == 65.17

    urllib3_group = report.groups[1]
    assert urllib3_group.package_name == "urllib3"
    assert urllib3_group.affected_components == ["requests"]
    assert urllib3_group.entry_points == ["demo-app"]
    assert urllib3_group.ranking.reachable_resolved_count == 1


def test_no_entry_packages_token_is_reported() -> None:
    service = _service(
        packages=[urllib3_package_row()],
        declarations=[],
        edges=[edge_row(to_id=PKG_URLLIB3, to_name="urllib3", to_version="2.0.0")],
        findings=[urllib3_finding_row()],
    )
    report = service.analyze(ANALYSIS)
    assert "no_entry_packages_defined" in report.limitations
    reachability = report.findings[0].priority.reachability
    # Without entry packages the graph cannot model a path: unavailable, never
    # "not reachable".
    assert reachability.status == "unavailable"
    assert reachability.evidence_available is False


# ---------------------------------------------------------------------------
# bounds
# ---------------------------------------------------------------------------

def test_fetch_truncation_is_reported_explicitly() -> None:
    limitations: list[str] = []
    rows = [{"id": f"row_{index}"} for index in range(4)]
    kept = RemediationService._fetch(
        {"rows": rows}, 3, "packages_truncated", limitations
    )
    assert len(kept) == 3
    assert limitations == ["packages_truncated"]

    limitations = []
    kept = RemediationService._fetch(
        {"rows": rows[:3]}, 3, "packages_truncated", limitations
    )
    assert len(kept) == 3
    assert limitations == []


def test_unresolved_relationship_list_is_bounded() -> None:
    declarations = [
        declaration_row(
            normalized_name="many-things",
            resolved_version=None,
            manifest_path=f"requirements-{index}.txt",
            line_number=1,
        )
        for index in range(MAX_UNRESOLVED_RELATIONSHIPS + 3)
    ]
    items = RemediationService._unresolved_relationships(
        "many-things", declarations, []
    )
    assert len(items) == MAX_UNRESOLVED_RELATIONSHIPS + 1
    assert items[-1].startswith("unresolved_relationships_truncated (+3 more)")
