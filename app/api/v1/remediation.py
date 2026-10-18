"""Prioritization and remediation API endpoints for BlastRadius Phase 5.

All endpoints are **read-only and deterministic**: they compute the
BlastRadius priority score, advisory-validated remediation candidates and
ranked fix groups from persisted graph/advisory facts.  No LLM is involved,
no graph writes happen, no repository file is touched, and no caller-supplied
advisory data is accepted — callers can only select analysis/finding/group
identifiers that the analysis itself produced, and query parameters outside
the documented pagination set are rejected with ``400 invalid_input``.

Routes are mounted under ``/api/v1`` by the version-one router:

* ``GET /api/v1/analyses/{analysis_id}/findings`` - ranked findings
* ``GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`` - risk explanation
* ``GET /api/v1/analyses/{analysis_id}/remediation/candidates`` - per-package candidates
* ``GET /api/v1/analyses/{analysis_id}/remediation/groups`` - ranked fix groups
* ``GET /api/v1/analyses/{analysis_id}/remediation/groups/{group_id}`` - one group's evidence
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query

from app.api.deps import get_remediation_service, only_query_parameters as _only_query_parameters
from app.api.v1.remediation_schemas import (
    FindingDetailResponse,
    FixGroupResponse,
    FixGroupsResponse,
    PrioritizedFindingsResponse,
    RemediationCandidatesResponse,
)
from app.core.logging import get_logger
from app.remediation.service import RemediationService

_log = get_logger("api.remediation")

router = APIRouter(tags=["remediation"])

_ANALYSIS_PATH = Path(
    ...,
    min_length=1,
    max_length=200,
    description="Analysis identifier produced by graph ingestion.",
)
_FINDING_PATH = Path(
    ...,
    min_length=1,
    max_length=200,
    description="Finding identifier returned by the findings endpoint.",
)
_GROUP_PATH = Path(
    ...,
    min_length=1,
    max_length=200,
    description="Fix-group identifier returned by the groups endpoint.",
)

#: Cap for the unresolved-findings list embedded in the groups response.
MAX_UNRESOLVED_INLINE = 200


@router.get(
    "/analyses/{analysis_id}/findings",
    response_model=PrioritizedFindingsResponse,
    summary="Ranked vulnerability findings for an analysis",
    description=(
        "Returns version-confirmed findings ranked by the deterministic BlastRadius "
        "priority formula. Severity (advisory-reported), reachability, impact and "
        "remediation availability are exposed per finding; the custom score is never "
        "a CVSS score."
    ),
)
def list_prioritized_findings(
    analysis_id: str = _ANALYSIS_PATH,
    skip: int = Query(0, ge=0, description="Ranked findings to skip."),
    limit: int = Query(50, ge=1, le=500, description="Page size (max 500)."),
    service: RemediationService = Depends(get_remediation_service),
    _query: None = Depends(_only_query_parameters("skip", "limit")),
) -> PrioritizedFindingsResponse:
    """Return one page of ranked findings for the analysis."""
    report = service.analyze(analysis_id)
    page = report.findings[skip : skip + limit]
    return PrioritizedFindingsResponse(
        analysis_id=report.analysis_id,
        repository_id=report.repository_id,
        commit_sha=report.commit_sha,
        count=len(page),
        total=len(report.findings),
        skip=skip,
        limit=limit,
        analysis_context=report.context,
        findings=page,
        limitations=report.limitations,
    )


@router.get(
    "/analyses/{analysis_id}/findings/{finding_id}",
    response_model=FindingDetailResponse,
    summary="Risk explanation for one finding",
    description=(
        "Returns the finding with every contributing priority factor, its graph "
        "evidence (entry points, dependent components) and the remediation plan for "
        "its package. Finding ids are scoped to the analysis: an id from another "
        "analysis is a 404."
    ),
)
def get_finding_detail(
    analysis_id: str = _ANALYSIS_PATH,
    finding_id: str = _FINDING_PATH,
    service: RemediationService = Depends(get_remediation_service),
    _query: None = Depends(_only_query_parameters()),
) -> FindingDetailResponse:
    """Return one finding and the remediation plan for its package."""
    finding, plan, limitations = service.find_finding(analysis_id, finding_id)
    return FindingDetailResponse(finding=finding, remediation=plan, limitations=limitations)


@router.get(
    "/analyses/{analysis_id}/remediation/candidates",
    response_model=RemediationCandidatesResponse,
    summary="Remediation candidates per affected package",
    description=(
        "Proposes advisory-sourced upgrade versions per affected package. Each "
        "candidate lists the range-validated resolutions, the recorded constraint "
        "checks and an explicit compatibility status. No resolver is executed and no "
        "repository file is modified."
    ),
)
def list_remediation_candidates(
    analysis_id: str = _ANALYSIS_PATH,
    skip: int = Query(0, ge=0, description="Package plans to skip."),
    limit: int = Query(50, ge=1, le=200, description="Page size (max 200)."),
    service: RemediationService = Depends(get_remediation_service),
    _query: None = Depends(_only_query_parameters("skip", "limit")),
) -> RemediationCandidatesResponse:
    """Return one page of per-package remediation plans."""
    report = service.analyze(analysis_id)
    page = report.plans[skip : skip + limit]
    return RemediationCandidatesResponse(
        analysis_id=report.analysis_id,
        repository_id=report.repository_id,
        commit_sha=report.commit_sha,
        count=len(page),
        total=len(report.plans),
        skip=skip,
        limit=limit,
        analysis_context=report.context,
        plans=page,
        limitations=report.limitations,
    )


@router.get(
    "/analyses/{analysis_id}/remediation/groups",
    response_model=FixGroupsResponse,
    summary="Ranked fix groups for an analysis",
    description=(
        "Groups findings by the dependency change that resolves them and ranks the "
        "groups by range-validated impact (never by claimed impact). Findings no "
        "candidate can verifiably resolve are reported separately with reasons."
    ),
)
def list_fix_groups(
    analysis_id: str = _ANALYSIS_PATH,
    skip: int = Query(0, ge=0, description="Ranked groups to skip."),
    limit: int = Query(20, ge=1, le=200, description="Page size (max 200)."),
    service: RemediationService = Depends(get_remediation_service),
    _query: None = Depends(_only_query_parameters("skip", "limit")),
) -> FixGroupsResponse:
    """Return one page of ranked fix groups."""
    report = service.analyze(analysis_id)
    page = report.groups[skip : skip + limit]
    unresolved = report.unresolved_findings
    truncated = len(unresolved) > MAX_UNRESOLVED_INLINE
    if truncated:
        unresolved = unresolved[:MAX_UNRESOLVED_INLINE]
    limitations = list(report.limitations)
    if truncated:
        limitations.append("unresolved_findings_truncated")
    return FixGroupsResponse(
        analysis_id=report.analysis_id,
        repository_id=report.repository_id,
        commit_sha=report.commit_sha,
        count=len(page),
        total=len(report.groups),
        skip=skip,
        limit=limit,
        analysis_context=report.context,
        groups=page,
        unresolved_findings=unresolved,
        unresolved_findings_truncated=truncated,
        limitations=limitations,
    )


@router.get(
    "/analyses/{analysis_id}/remediation/groups/{group_id}",
    response_model=FixGroupResponse,
    summary="Evidence and compatibility checks of one fix group",
    description=(
        "Returns a single fix group with its supporting advisory evidence, affected "
        "components, entry points, constraint checks and unresolved relationships. "
        "Group ids are scoped to the analysis."
    ),
)
def get_fix_group(
    analysis_id: str = _ANALYSIS_PATH,
    group_id: str = _GROUP_PATH,
    service: RemediationService = Depends(get_remediation_service),
    _query: None = Depends(_only_query_parameters()),
) -> FixGroupResponse:
    """Return one fix group with its evidence."""
    group, limitations = service.find_group(analysis_id, group_id)
    return FixGroupResponse(group=group, limitations=limitations)


__all__ = ["router"]
