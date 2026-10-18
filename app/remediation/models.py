"""Typed models for deterministic prioritization and remediation (Phase 5).

These models are the single source of truth for the Phase 5 output contract:
the FastAPI endpoints (`app/api/v1/remediation.py`), the MCP tools and the
agent all serialise exactly these shapes.

Ground rules encoded in the fields:

* advisory data (severity entries, fixed versions, ranges) is echoed
  *verbatim* from what Phase 3 stored — nothing is re-derived;
* the BlastRadius priority score is a custom, documented, deterministic score
  and is never a CVSS score: advisory severity (`SeverityEvidence`) and the
  custom score (`FindingPriority`) are separate fields;
* missing data stays ``None``/absent and is explained in ``limitations`` or
  ``detail`` strings instead of being replaced by an invented value;
* every remediation proposal carries its provenance (which advisory declared
  the version, which constraint sources were checked) and an explicit
  compatibility status — a resolver is never executed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# analysis context
# ---------------------------------------------------------------------------


class AnalysisContext(BaseModel):
    """Completeness facts about the analysis the findings were computed from."""

    model_config = ConfigDict(extra="forbid")

    analysis_status: str = Field(description="Graph ingestion status: success | partial | failed.")
    complete: bool = Field(description="True when the ingestion reported success with no errors.")
    warning_count: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    resolved_packages: int = Field(default=0, ge=0)
    dependency_edges: int = Field(default=0, ge=0)
    vulnerability_edges: int = Field(default=0, ge=0)
    declaration_targets_without_version: int = Field(
        default=0, ge=0, description="Declared packages with no lockfile-resolved version."
    )
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# findings and their priority factors
# ---------------------------------------------------------------------------


class FindingInput(BaseModel):
    """Merged graph facts for one finding, before prioritization.

    Internal input to the deterministic engine (priority factors, candidate
    generation).  Every field is either verbatim graph data or ``None`` —
    nothing is defaulted to a guessed value.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    vulnerability_id: str
    vulnerability_summary: str | None = None
    aliases: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    withdrawn: str | None = None
    severities: tuple[str, ...] = ()
    package_id: str
    package_name: str
    package_version: str | None = None
    ecosystem: str | None = None
    dependency_role: str = "unknown"
    is_dev: bool = False
    is_optional: bool = False
    is_root_project: bool = False
    groups: tuple[str, ...] = ()
    marker: str | None = None
    source_manifest: str | None = None
    match_type: str | None = None
    fixed_versions: tuple[str, ...] = ()
    ranges_json: str | None = None
    osv_modified: str | None = None
    last_synced_at: str | None = None
    entry_points: tuple[str, ...] = ()
    entry_min_hops: int | None = None
    dependent_components: tuple[str, ...] = ()
    dependent_component_count: int = 0
    dependent_min_hops: int | None = None


class SeverityEvidence(BaseModel):
    """Advisory severity exactly as stored (never computed by BlastRadius)."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(default="osv", description="The only severity source: the OSV record.")
    quantified: bool = Field(description="True when a numeric advisory-reported score exists.")
    numeric_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Advisory-reported numeric score (e.g. 'CVSS_V3 9.8'); never computed.",
    )
    score_type: str | None = Field(default=None, description="Type of the numeric score, e.g. CVSS_V3.")
    vector: str | None = Field(default=None, description="First CVSS vector string, kept verbatim.")
    vector_types: list[str] = Field(default_factory=list)
    entries: list[str] = Field(default_factory=list, description="Verbatim stored severity entries.")
    note: str | None = None


class FactorContribution(BaseModel):
    """One documented factor of the BlastRadius priority score."""

    model_config = ConfigDict(extra="forbid")

    name: str
    weight: float = Field(ge=0.0, le=1.0)
    normalized: float = Field(ge=0.0, le=1.0, description="Factor value after normalization.")
    contribution: float = Field(ge=0.0, le=1.0, description="weight * normalized.")
    raw: dict[str, Any] = Field(default_factory=dict, description="The facts the factor was derived from.")
    notes: list[str] = Field(default_factory=list)


class ReachabilityEvidence(BaseModel):
    """Modeled reachability of the affected package from entry points."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        description=(
            "direct | reachable_from_entry | not_reachable | unavailable. "
            "'not_reachable' means the graph had the data needed to look for a "
            "path and none was found; it never means proven unexploitable."
        )
    )
    entry_points: list[str] = Field(default_factory=list, description="Direct/root packages with a modeled path.")
    min_hops: int | None = Field(default=None, ge=1, description="Shortest modeled path length.")
    dependent_component_count: int = Field(
        default=0, ge=0, description="Distinct packages (transitively) depending on the affected package."
    )
    dependent_components: list[str] = Field(default_factory=list, description="Dependent package names (sorted).")
    dependent_components_truncated: bool = False
    scope_exposure: str = Field(
        default="unknown",
        description="runtime | dev | optional | unknown — derived from package/edge scope flags.",
    )
    evidence_available: bool = Field(
        default=False,
        description="True when the analysis has dependency edges and defined entry packages.",
    )
    notes: list[str] = Field(default_factory=list)


class FindingPriority(BaseModel):
    """The BlastRadius priority result: a custom score, never a CVSS score."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=100.0, description="BlastRadius priority score (custom; not CVSS).")
    formula_version: str
    rank: int = Field(ge=1, description="Position in the ranked finding list of this analysis.")
    factors: list[FactorContribution]
    severity: SeverityEvidence
    reachability: ReachabilityEvidence
    remediation_available: bool = Field(
        description="True when at least one finding of this package has an advisory fixed version."
    )
    remediation_note: str | None = None


class PackageRef(BaseModel):
    """The resolved package a finding belongs to."""

    model_config = ConfigDict(extra="forbid")

    package_id: str
    package_name: str
    package_version: str | None = None
    ecosystem: str | None = None
    dependency_role: str = Field(default="unknown", description="direct | transitive | unknown.")
    is_dev: bool = False
    is_optional: bool = False
    is_root_project: bool = False
    groups: list[str] = Field(default_factory=list)
    marker: str | None = None
    source_manifest: str | None = None


class FindingOut(BaseModel):
    """One prioritized finding: a version-confirmed package/vulnerability pair."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    analysis_id: str
    repository_id: str
    commit_sha: str
    vulnerability_id: str
    vulnerability_summary: str | None = None
    aliases: list[str] = Field(default_factory=list)
    advisory_references: list[str] = Field(default_factory=list, description="Verbatim 'TYPE url' strings.")
    advisory_withdrawn: bool = Field(default=False, description="The OSV record carries a withdrawn timestamp.")
    package: PackageRef
    match_type: str | None = Field(default=None, description="Always 'version' for stored findings.")
    fixed_versions: list[str] = Field(default_factory=list, description="Advisory fixed versions for this package.")
    osv_modified: str | None = None
    last_synced_at: str | None = None
    priority: FindingPriority
    confidence: str = Field(description="verified | reduced.")
    confidence_reasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# remediation candidates
# ---------------------------------------------------------------------------


class ConstraintSource(BaseModel):
    """One recorded constraint that a proposed upgrade must satisfy.

    Internal input to candidate evaluation; the evaluated form is
    :class:`ConstraintCheck`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(description="declaration | dependency_edge.")
    origin: str = Field(description="Manifest path/line (declaration) or 'from-package version' (edge).")
    constraint: str | None = None
    scheme: str | None = Field(default=None, description="Declared scheme for declarations; None for edges.")


class ConstraintCheck(BaseModel):
    """Evaluation of one recorded constraint against a proposed version."""

    model_config = ConfigDict(extra="forbid")

    source: str
    origin: str
    constraint: str | None = None
    scheme: str
    satisfied: bool | None = Field(
        default=None, description="True/False when PEP 440-evaluable; None when it cannot be evaluated."
    )
    detail: str


class ProposedVersionEvaluation(BaseModel):
    """Range-based validation of one proposed version against one finding."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    status: str = Field(description="resolves | not_resolving | unknown.")
    detail: str
    fixed_versions: list[str] = Field(default_factory=list)
    affected_intervals_reconstructed: int = Field(default=0, ge=0)


class RemediationCandidate(BaseModel):
    """One advisory-sourced proposed version for one affected package."""

    model_config = ConfigDict(extra="forbid")

    package_id: str
    package_name: str
    ecosystem: str | None = None
    current_version: str
    proposed_version: str = Field(description="Taken from advisory fixed-version data; never invented.")
    origin: str = Field(default="osv_fixed_version")
    dependency_role: str = "unknown"
    selected: bool = False
    resolves: list[ProposedVersionEvaluation] = Field(default_factory=list)
    resolved_finding_ids: list[str] = Field(default_factory=list, description="Range-validated resolutions.")
    unknown_finding_ids: list[str] = Field(default_factory=list, description="Resolution could not be validated.")
    unresolved_finding_ids: list[str] = Field(default_factory=list, description="Range data says it does not resolve.")
    constraint_checks: list[ConstraintCheck] = Field(default_factory=list)
    compatibility: str = Field(
        default="unverified",
        description="constraints_satisfied | constraints_violated | unverified.",
    )
    compatibility_detail: str
    resolver_executed: bool = Field(default=False, description="Always False: no resolver is ever run.")
    limitations: list[str] = Field(default_factory=list)


class PackageRemediationPlan(BaseModel):
    """All remediation candidates for one affected package."""

    model_config = ConfigDict(extra="forbid")

    package_id: str
    package_name: str
    current_version: str
    ecosystem: str | None = None
    dependency_role: str = "unknown"
    finding_ids: list[str] = Field(default_factory=list)
    candidates: list[RemediationCandidate] = Field(default_factory=list)
    no_candidate_reason: str | None = Field(
        default=None, description="Set when no advisory fixed version exists for this package."
    )
    unresolved_relationships: list[str] = Field(default_factory=list)
    migration_concerns: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# fix groups
# ---------------------------------------------------------------------------


class AdvisoryEvidenceRef(BaseModel):
    """Supporting advisory evidence for one finding inside a fix group."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    summary: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    match_type: str | None = None
    osv_modified: str | None = None


class GroupRanking(BaseModel):
    """The exposed metrics the group ordering is computed from."""

    model_config = ConfigDict(extra="forbid")

    rank: int = Field(ge=1)
    verified_resolved_count: int = Field(ge=0, description="Range-validated findings only.")
    verified_resolved_priority_sum: float = Field(ge=0.0)
    reachable_resolved_count: int = Field(ge=0)
    compatibility_tier: int = Field(ge=0, le=2, description="2 satisfied, 1 unverified, 0 violated.")
    compatibility_tier_label: str
    highest_finding_priority: float | None = None


class FixGroup(BaseModel):
    """A dependency change that (partially) addresses the findings of one package."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    analysis_id: str
    repository_id: str
    commit_sha: str
    package_id: str
    package_name: str
    ecosystem: str | None = None
    current_version: str
    proposed_version: str
    dependency_role: str = "unknown"
    coverage: str = Field(description="confirmed_advisory | potential_only | no_advisory_resolution.")
    verified_resolved_finding_ids: list[str] = Field(default_factory=list)
    potential_resolved_finding_ids: list[str] = Field(default_factory=list)
    unresolved_finding_ids: list[str] = Field(default_factory=list)
    resolved_findings: list[FindingOut] = Field(
        default_factory=list, description="Full findings validated against the proposed version."
    )
    advisory_evidence: list[AdvisoryEvidenceRef] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_components_truncated: bool = False
    entry_points: list[str] = Field(default_factory=list)
    compatibility: str
    constraint_checks: list[ConstraintCheck] = Field(default_factory=list)
    unresolved_relationships: list[str] = Field(default_factory=list)
    migration_concerns: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    candidates: list[RemediationCandidate] = Field(default_factory=list, description="Selected first, alternates after.")
    ranking: GroupRanking


class UnresolvedFindingOut(BaseModel):
    """A finding no candidate in this analysis can verifiably resolve."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    vulnerability_id: str
    package_name: str
    package_version: str | None = None
    reason: str


# ---------------------------------------------------------------------------
# service report container
# ---------------------------------------------------------------------------


class AnalysisReport(BaseModel):
    """Everything the remediation engine computes for one analysis."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    repository_id: str
    commit_sha: str
    context: AnalysisContext
    findings: list[FindingOut] = Field(default_factory=list, description="Ranked best-first.")
    plans: list[PackageRemediationPlan] = Field(default_factory=list)
    groups: list[FixGroup] = Field(default_factory=list, description="Ranked best-first.")
    unresolved_findings: list[UnresolvedFindingOut] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "AdvisoryEvidenceRef",
    "AnalysisContext",
    "AnalysisReport",
    "ConstraintCheck",
    "ConstraintSource",
    "FactorContribution",
    "FindingInput",
    "FindingOut",
    "FindingPriority",
    "FixGroup",
    "GroupRanking",
    "PackageRef",
    "PackageRemediationPlan",
    "ProposedVersionEvaluation",
    "ReachabilityEvidence",
    "RemediationCandidate",
    "SeverityEvidence",
    "UnresolvedFindingOut",
]
