"""Remediation candidate generation (Phase 5).

For each affected package this module evaluates the *advisory-declared* fixed
versions against the stored OSV ranges (one validation per finding) and the
recorded dependency constraints (declarations + ``DEPENDS_ON`` edges).

Hard rules, encoded:

* proposed versions come only from advisory fixed-version data — they are
  never invented, and a version merely mentioned in advisory text is not a
  candidate;
* "resolves this finding" is only claimed when
  :func:`~app.remediation.ranges.evaluate_proposed_version` says the advisory's
  own range data supports it;
* compatibility is evaluated against recorded constraints only — no resolver
  is ever executed, so the best possible status is
  ``constraints_satisfied`` with ``resolver_executed=False``;
* packages without any advisory fixed version get an explicit
  ``no_candidate_reason`` instead of a manufactured target.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from app.remediation.models import (
    ConstraintCheck,
    ConstraintSource,
    FindingOut,
    FindingInput,
    PackageRef,
    PackageRemediationPlan,
    ProposedVersionEvaluation,
    RemediationCandidate,
)
from app.remediation.ranges import (
    STATUS_RESOLVES,
    STATUS_UNKNOWN,
    evaluate_proposed_version,
)
from app.remediation.versions import evaluate_constraint, parse_version, version_sort_key

COMPATIBILITY_SATISFIED = "constraints_satisfied"
COMPATIBILITY_VIOLATED = "constraints_violated"
COMPATIBILITY_UNVERIFIED = "unverified"

COMPATIBILITY_TIER: dict[str, int] = {
    COMPATIBILITY_SATISFIED: 2,
    COMPATIBILITY_UNVERIFIED: 1,
    COMPATIBILITY_VIOLATED: 0,
}


def _candidate_order(candidate: RemediationCandidate) -> tuple:
    """Documented candidate ordering (best first).

    1. candidates that do not violate a recorded constraint come first;
    2. more range-validated resolutions;
    3. higher compatibility tier;
    4. more possibly-validatable (unknown) resolutions;
    5. smaller proposed version (least disruptive by version order).
    """
    not_violated = 0 if candidate.compatibility == COMPATIBILITY_VIOLATED else 1
    return (
        -not_violated,
        -len(candidate.resolved_finding_ids),
        -COMPATIBILITY_TIER.get(candidate.compatibility, 0),
        -len(candidate.unknown_finding_ids),
        version_sort_key(candidate.proposed_version),
    )


def _evaluate_constraints(
    sources: Sequence[ConstraintSource], proposed: str
) -> list[ConstraintCheck]:
    checks: list[ConstraintCheck] = []
    for source in sources:
        satisfied, scheme, detail = evaluate_constraint(source.constraint, source.scheme, proposed)
        checks.append(
            ConstraintCheck(
                source=source.source,
                origin=source.origin,
                constraint=source.constraint,
                scheme=scheme,
                satisfied=satisfied,
                detail=detail,
            )
        )
    return checks


def _compatibility(checks: list[ConstraintCheck]) -> tuple[str, str]:
    if not checks:
        return (
            COMPATIBILITY_UNVERIFIED,
            "no recorded constraints exist for this package, so compatibility cannot be verified",
        )
    flags = [check.satisfied for check in checks]
    if any(flag is False for flag in flags):
        violated = sum(1 for flag in flags if flag is False)
        return (
            COMPATIBILITY_VIOLATED,
            f"{violated} recorded constraint(s) reject the proposed version",
        )
    if any(flag is None for flag in flags):
        unknown = sum(1 for flag in flags if flag is None)
        return (
            COMPATIBILITY_UNVERIFIED,
            f"{unknown} recorded constraint(s) cannot be evaluated with PEP 440 tooling; "
            "no resolver was executed",
        )
    return (
        COMPATIBILITY_SATISFIED,
        f"all {len(checks)} recorded constraint(s) are satisfied; no resolver was executed, "
        "so transitive resolution is not verified",
    )


def _evaluate_finding(
    finding: FindingOut,
    ranges_json: str | None,
    current_version: str | None,
    proposed: str,
) -> tuple[ProposedVersionEvaluation, str]:
    evaluation = evaluate_proposed_version(ranges_json, current_version, proposed)
    return (
        ProposedVersionEvaluation(
            vulnerability_id=finding.vulnerability_id,
            status=evaluation.status,
            detail=evaluation.detail,
            fixed_versions=list(finding.fixed_versions),
            affected_intervals_reconstructed=evaluation.affected_intervals,
        ),
        evaluation.status,
    )


def build_package_plan(
    *,
    package: PackageRef,
    findings: Sequence[FindingOut],
    finding_inputs: Mapping[str, FindingInput],
    constraint_sources: Sequence[ConstraintSource],
    unresolved_relationships: Sequence[str],
    migration_concerns: Sequence[str],
) -> PackageRemediationPlan:
    """Build the full candidate plan for one affected package."""
    current_version = package.package_version or ""
    finding_ids = [finding.finding_id for finding in findings]

    proposed_versions: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        for version in finding.fixed_versions:
            text = str(version).strip()
            if text and text not in seen:
                seen.add(text)
                proposed_versions.append(text)
    proposed_versions.sort(key=version_sort_key)

    common = dict(
        package_id=package.package_id,
        package_name=package.package_name,
        current_version=current_version,
        ecosystem=package.ecosystem,
        dependency_role=package.dependency_role,
        finding_ids=finding_ids,
        unresolved_relationships=list(unresolved_relationships),
        migration_concerns=list(migration_concerns),
    )

    if not proposed_versions:
        return PackageRemediationPlan(
            **common,
            candidates=[],
            no_candidate_reason=(
                "no advisory fixed version is recorded for this package; a remediation "
                "candidate cannot be established from the available evidence"
            ),
            limitations=[
                "the recorded advisory evidence contains no fixed-version information "
                "for this package, so no upgrade target can be proposed"
            ],
        )

    candidates: list[RemediationCandidate] = []
    for proposed in proposed_versions:
        resolved: list[str] = []
        unknown: list[str] = []
        unresolved: list[str] = []
        evaluations: list[ProposedVersionEvaluation] = []
        for finding in findings:
            inputs = finding_inputs.get(finding.finding_id)
            ranges_json = inputs.ranges_json if inputs is not None else None
            evaluation, status = _evaluate_finding(
                finding, ranges_json, package.package_version, proposed
            )
            evaluations.append(evaluation)
            if status == STATUS_RESOLVES:
                resolved.append(finding.finding_id)
            elif status == STATUS_UNKNOWN:
                unknown.append(finding.finding_id)
            else:
                unresolved.append(finding.finding_id)

        checks = _evaluate_constraints(constraint_sources, proposed)
        compatibility, compatibility_detail = _compatibility(checks)

        candidate_limitations: list[str] = []
        if unknown:
            candidate_limitations.append(
                "one or more proposed-version resolutions could not be validated from the "
                "stored advisory ranges"
            )
        if compatibility == COMPATIBILITY_VIOLATED:
            candidate_limitations.append(
                "recorded dependency constraints reject this proposed version; applying it "
                "requires a conscious constraint change"
            )
        if compatibility == COMPATIBILITY_UNVERIFIED:
            candidate_limitations.append(
                "compatibility is unverified: no resolver was executed and the recorded "
                "constraints could not be fully evaluated"
            )
        current_parsed = parse_version(package.package_version)
        proposed_parsed = parse_version(proposed)
        if (
            current_parsed is not None
            and proposed_parsed is not None
            and proposed_parsed < current_parsed
        ):
            candidate_limitations.append(
                "the proposed version orders below the current resolved version; verify the "
                "advisory range data before applying"
            )

        candidates.append(
            RemediationCandidate(
                package_id=package.package_id,
                package_name=package.package_name,
                ecosystem=package.ecosystem,
                current_version=current_version,
                proposed_version=proposed,
                dependency_role=package.dependency_role,
                selected=False,
                resolves=evaluations,
                resolved_finding_ids=resolved,
                unknown_finding_ids=unknown,
                unresolved_finding_ids=unresolved,
                constraint_checks=checks,
                compatibility=compatibility,
                compatibility_detail=compatibility_detail,
                resolver_executed=False,
                limitations=candidate_limitations,
            )
        )

    ordered = sorted(candidates, key=_candidate_order)
    selected = ordered[0].model_copy(update={"selected": True})
    ordered = [selected, *ordered[1:]]

    return PackageRemediationPlan(
        **common,
        candidates=ordered,
        no_candidate_reason=None,
        limitations=[],
    )


__all__ = [
    "COMPATIBILITY_SATISFIED",
    "COMPATIBILITY_TIER",
    "COMPATIBILITY_UNVERIFIED",
    "COMPATIBILITY_VIOLATED",
    "build_package_plan",
]
