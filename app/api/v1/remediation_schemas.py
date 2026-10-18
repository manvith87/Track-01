"""Response models for the Phase 5 prioritization/remediation API.

The heavy lifting is typed once in :mod:`app.remediation.models`; these
wrappers add the analysis scope, pagination envelope and the shared
limitations list, mirroring the Phase 3/4 API conventions.

Every endpoint is read-only: nothing here writes to the graph, the repository
or GitHub, and no caller-supplied advisory data is ever accepted.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.remediation.models import (
    AnalysisContext,
    FindingOut,
    FixGroup,
    PackageRemediationPlan,
    UnresolvedFindingOut,
)


class PrioritizedFindingsResponse(BaseModel):
    """Ranked findings for one analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    repository_id: str
    commit_sha: str
    count: int = Field(ge=0, description="Items in this page.")
    total: int = Field(ge=0, description="Ranked findings in the analysis.")
    skip: int = Field(ge=0)
    limit: int = Field(ge=1)
    analysis_context: AnalysisContext
    findings: list[FindingOut]
    limitations: list[str] = Field(default_factory=list)


class FindingDetailResponse(BaseModel):
    """One finding with its full risk explanation and package remediation plan."""

    model_config = ConfigDict(extra="forbid")

    finding: FindingOut
    remediation: PackageRemediationPlan | None = None
    limitations: list[str] = Field(default_factory=list)


class RemediationCandidatesResponse(BaseModel):
    """Per-package remediation candidates for one analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    repository_id: str
    commit_sha: str
    count: int = Field(ge=0, description="Items in this page.")
    total: int = Field(ge=0, description="Affected packages with a plan.")
    skip: int = Field(ge=0)
    limit: int = Field(ge=1)
    analysis_context: AnalysisContext
    plans: list[PackageRemediationPlan]
    limitations: list[str] = Field(default_factory=list)


class FixGroupsResponse(BaseModel):
    """Ranked fix groups (plus findings nothing can verifiably resolve)."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    repository_id: str
    commit_sha: str
    count: int = Field(ge=0, description="Items in this page.")
    total: int = Field(ge=0, description="Fix groups in the analysis.")
    skip: int = Field(ge=0)
    limit: int = Field(ge=1)
    analysis_context: AnalysisContext
    groups: list[FixGroup]
    unresolved_findings: list[UnresolvedFindingOut] = Field(default_factory=list)
    unresolved_findings_truncated: bool = False
    limitations: list[str] = Field(default_factory=list)


class FixGroupResponse(BaseModel):
    """One fix group with its evidence and compatibility checks."""

    model_config = ConfigDict(extra="forbid")

    group: FixGroup
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "FindingDetailResponse",
    "FixGroupResponse",
    "FixGroupsResponse",
    "PrioritizedFindingsResponse",
    "RemediationCandidatesResponse",
]
