"""Fix grouping and ranking (Phase 5).

A fix group is one dependency change: the selected candidate for one affected
package.  Grouping rules:

* each finding belongs to exactly one group (the group of its package), so
  nothing is counted twice;
* only *range-validated* resolutions count towards
  ``verified_resolved_count`` — a version that merely exists in the advisory
  text, or a shared upgrade in the dependency neighbourhood, never inflates a
  group;
* resolutions that could not be validated stay visible as
  ``potential_resolved_finding_ids`` and are excluded from the ranking;
* findings that no candidate can resolve (no advisory fix recorded, or the
  range data says the proposed version does not resolve them) are reported in
  ``unresolved_findings`` with the reason.

Group order (documented; higher first):

1. ``verified_resolved_count`` — findings the advisory range data says the
   change resolves;
2. ``verified_resolved_priority_sum`` — the BlastRadius priority scores of
   exactly those findings;
3. compatibility tier (satisfied > unverified > violated);
4. package name, then current version, then proposed version (stable ties).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from app.models.ids import stable_id
from app.remediation.candidates import COMPATIBILITY_TIER
from app.remediation.models import (
    AdvisoryEvidenceRef,
    FindingOut,
    FixGroup,
    GroupRanking,
    PackageRemediationPlan,
    UnresolvedFindingOut,
)
from app.remediation.priority import MAX_DEPENDENT_COMPONENTS
from app.remediation.versions import version_sort_key

_COVERAGE_CONFIRMED = "confirmed_advisory"
_COVERAGE_POTENTIAL = "potential_only"
_COVERAGE_NONE = "no_advisory_resolution"


def _coverage(verified: Sequence[str], potential: Sequence[str]) -> str:
    if verified:
        return _COVERAGE_CONFIRMED
    if potential:
        return _COVERAGE_POTENTIAL
    return _COVERAGE_NONE


def build_fix_group(
    *,
    analysis_id: str,
    repository_id: str,
    commit_sha: str,
    plan: PackageRemediationPlan,
    findings_by_id: Mapping[str, FindingOut],
) -> FixGroup:
    """Build the fix group for one package plan (plan must have candidates)."""
    selected = plan.candidates[0]
    verified_ids = [fid for fid in selected.resolved_finding_ids if fid in findings_by_id]
    potential_ids = [fid for fid in selected.unknown_finding_ids if fid in findings_by_id]
    unresolved_ids = [fid for fid in selected.unresolved_finding_ids if fid in findings_by_id]
    verified_findings = [findings_by_id[fid] for fid in verified_ids]

    components: set[str] = set()
    entry_points: set[str] = set()
    truncated = False
    for finding in verified_findings:
        reachability = finding.priority.reachability
        components.update(reachability.dependent_components)
        truncated = truncated or reachability.dependent_components_truncated
        entry_points.update(reachability.entry_points)
    ordered_components = sorted(components)
    if len(ordered_components) > MAX_DEPENDENT_COMPONENTS:
        ordered_components = ordered_components[:MAX_DEPENDENT_COMPONENTS]
        truncated = True

    evidence_ids = [*verified_ids, *potential_ids]
    advisory_evidence = [
        AdvisoryEvidenceRef(
            vulnerability_id=findings_by_id[fid].vulnerability_id,
            summary=findings_by_id[fid].vulnerability_summary,
            fixed_versions=list(findings_by_id[fid].fixed_versions),
            match_type=findings_by_id[fid].match_type,
            osv_modified=findings_by_id[fid].osv_modified,
        )
        for fid in evidence_ids
    ]

    priority_sum = round(sum(finding.priority.score for finding in verified_findings), 2)
    reachable_resolved = sum(
        1
        for finding in verified_findings
        if finding.priority.reachability.status in {"direct", "reachable_from_entry"}
    )
    highest = max((finding.priority.score for finding in verified_findings), default=None)
    tier = COMPATIBILITY_TIER.get(selected.compatibility, 0)
    tier_label = {
        2: "constraints_satisfied",
        1: "unverified",
        0: "constraints_violated",
    }[tier]

    return FixGroup(
        group_id=stable_id(
            "fixgroup", analysis_id, plan.package_id, selected.proposed_version
        ),
        analysis_id=analysis_id,
        repository_id=repository_id,
        commit_sha=commit_sha,
        package_id=plan.package_id,
        package_name=plan.package_name,
        ecosystem=plan.ecosystem,
        current_version=plan.current_version,
        proposed_version=selected.proposed_version,
        dependency_role=plan.dependency_role,
        coverage=_coverage(verified_ids, potential_ids),
        verified_resolved_finding_ids=verified_ids,
        potential_resolved_finding_ids=potential_ids,
        unresolved_finding_ids=unresolved_ids,
        resolved_findings=verified_findings,
        advisory_evidence=advisory_evidence,
        affected_components=ordered_components,
        affected_components_truncated=truncated,
        entry_points=sorted(entry_points),
        compatibility=selected.compatibility,
        constraint_checks=selected.constraint_checks,
        unresolved_relationships=list(plan.unresolved_relationships),
        migration_concerns=list(plan.migration_concerns),
        limitations=[*plan.limitations, *selected.limitations],
        candidates=list(plan.candidates),
        ranking=GroupRanking(
            rank=1,  # replaced by rank_fix_groups
            verified_resolved_count=len(verified_ids),
            verified_resolved_priority_sum=priority_sum,
            reachable_resolved_count=reachable_resolved,
            compatibility_tier=tier,
            compatibility_tier_label=tier_label,
            highest_finding_priority=highest,
        ),
    )


def rank_fix_groups(groups: Sequence[FixGroup]) -> list[FixGroup]:
    """Return the groups ordered and ranked by the documented metric order."""
    ordered = sorted(
        groups,
        key=lambda group: (
            -group.ranking.verified_resolved_count,
            -group.ranking.verified_resolved_priority_sum,
            -group.ranking.compatibility_tier,
            group.package_name,
            version_sort_key(group.current_version),
            version_sort_key(group.proposed_version),
        ),
    )
    ranked: list[FixGroup] = []
    for rank, group in enumerate(ordered, start=1):
        ranked.append(
            group.model_copy(update={"ranking": group.ranking.model_copy(update={"rank": rank})})
        )
    return ranked


def collect_unresolved_findings(
    plans: Sequence[PackageRemediationPlan],
    findings_by_id: Mapping[str, FindingOut],
) -> list[UnresolvedFindingOut]:
    """Findings that no candidate in this analysis can verifiably resolve."""
    unresolved: list[UnresolvedFindingOut] = []
    for plan in plans:
        package_findings = [
            findings_by_id[fid] for fid in plan.finding_ids if fid in findings_by_id
        ]
        if not plan.candidates:
            for finding in package_findings:
                unresolved.append(
                    UnresolvedFindingOut(
                        finding_id=finding.finding_id,
                        vulnerability_id=finding.vulnerability_id,
                        package_name=plan.package_name,
                        package_version=plan.current_version or None,
                        reason=(
                            "no advisory fixed version is recorded for this package; a "
                            "remediation candidate cannot be established"
                        ),
                    )
                )
            continue
        selected = plan.candidates[0]
        for finding_id in selected.unresolved_finding_ids:
            finding = findings_by_id.get(finding_id)
            if finding is None:
                continue
            unresolved.append(
                UnresolvedFindingOut(
                    finding_id=finding.finding_id,
                    vulnerability_id=finding.vulnerability_id,
                    package_name=plan.package_name,
                    package_version=plan.current_version or None,
                    reason=(
                        f"the advisory range data does not support that "
                        f"{selected.proposed_version} resolves this finding"
                    ),
                )
            )
    unresolved.sort(
        key=lambda item: (
            item.package_name,
            item.vulnerability_id,
            item.finding_id,
        )
    )
    return unresolved


__all__ = [
    "build_fix_group",
    "collect_unresolved_findings",
    "rank_fix_groups",
]
