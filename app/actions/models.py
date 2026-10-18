"""Typed models for the Phase 6 approved GitHub action workflow.

The workflow has two halves and the models make the boundary explicit:

* :class:`IssuePreviewOut` is a *proposal*.  It carries exactly what a write
  would create (title, body), the canonical server-side repository target, the
  server-issued ``action_id``, the payload digest and an expiry.  Generating a
  preview never calls GitHub.
* :class:`IssueConfirmOut` is the *result* of a confirmation that was
  authorized with the dedicated confirmation secret and executed through the
  GitHub REST API.  It is only ever produced from a real GitHub response (or a
  reconciled one) — never from an assumption.

:class:`ActionRecord` is the persistent, non-secret bookkeeping row of the
action store.  It never contains a GitHub token or the confirmation secret.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: Explicit action states.  Transitions are enforced atomically by the store:
#:
#: PREVIEWED -> EXECUTING -> SUCCEEDED | FAILED
#: PREVIEWED -> EXPIRED
ACTION_STATES = ("PREVIEWED", "EXECUTING", "SUCCEEDED", "FAILED", "EXPIRED")
ActionState = Literal["PREVIEWED", "EXECUTING", "SUCCEEDED", "FAILED", "EXPIRED"]

#: Human-readable note always attached to a preview so no caller can mistake
#: the response for an executed write.
PREVIEW_NOTES = (
    "No GitHub write has been performed. The issue is created only after an "
    "explicitly authorized confirmation of this action (before it expires).",
)


class RepositoryTarget(BaseModel):
    """The canonical GitHub write target, resolved from server-side records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "github.com"
    owner: str
    name: str
    full_name: str
    canonical_id: str
    canonical_url: str


class IssueSubjectSelection(BaseModel):
    """Which server-issued identifier the preview was generated from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    group_id: str | None = None
    finding_id: str | None = None


class IssuePreviewRequest(BaseModel):
    """Preview selector.  Only server-issued identifiers are accepted.

    Exactly one of ``group_id`` / ``finding_id`` must be provided.  Security
    facts (CVEs, severities, fixed versions, repository names, issue bodies)
    are never accepted from a caller: unknown fields fail validation.
    """

    model_config = ConfigDict(extra="forbid")

    group_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Fix-group id returned by the remediation groups endpoint/tool.",
    )
    finding_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        description="Finding id returned by the prioritized findings endpoint/tool.",
    )

    @model_validator(mode="after")
    def _exactly_one_selector(self) -> "IssuePreviewRequest":
        selected = [value for value in (self.group_id, self.finding_id) if value]
        if len(selected) != 1:
            raise ValueError("Provide exactly one of group_id or finding_id")
        return self


class IssuePreviewOut(BaseModel):
    """The exact, digest-bound proposal a confirmation would create."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    state: ActionState
    template_version: str
    created_at: datetime
    expires_at: datetime
    payload_digest: str = Field(
        description="sha256 over the canonical payload (repository, analysis, selection, title, body)."
    )
    repository: RepositoryTarget
    commit_sha: str
    analysis_id: str
    selection: IssueSubjectSelection
    title: str
    body: str
    coverage: str | None = Field(
        default=None, description="Group coverage: confirmed_advisory | potential_only."
    )
    compatibility: str | None = Field(
        default=None,
        description="constraints_satisfied | constraints_violated | unverified (never 'tested').",
    )
    verified_finding_count: int = Field(default=0, ge=0)
    potential_finding_count: int = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=lambda: list(PREVIEW_NOTES))


class IssueConfirmRequest(BaseModel):
    """Confirmation of one previewed action, bound to its payload digest."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=5, max_length=200)
    payload_digest: str = Field(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="The digest returned by the preview; a mismatch is rejected.",
    )


class IssueConfirmOut(BaseModel):
    """The verified outcome of the confirmed write."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    state: ActionState
    repository: RepositoryTarget
    analysis_id: str
    commit_sha: str
    title: str
    issue_number: int = Field(ge=1)
    issue_url: str
    created: bool = Field(
        description="False when the stored result of an already completed action was returned."
    )
    reconciled: bool = Field(
        default=False,
        description=(
            "True when the issue was recovered by the unique action marker after an "
            "ambiguous write outcome (instead of from the create response)."
        ),
    )
    executed_at: datetime


class ActionRecord(BaseModel):
    """Persistent, non-secret bookkeeping row of one previewed action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    state: ActionState
    analysis_id: str
    repository_id: str
    repository_owner: str
    repository_name: str
    commit_sha: str
    group_id: str | None = None
    finding_id: str | None = None
    payload_digest: str
    title: str
    body: str
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    issue_number: int | None = None
    issue_url: str | None = None
    failure_category: str | None = Field(
        default=None, description="Stable ErrorCode value of a failed attempt."
    )
    failure_message: str | None = Field(
        default=None, description="Safe failure summary; never contains tokens or secrets."
    )
    reconciled: bool = False


__all__ = [
    "ACTION_STATES",
    "PREVIEW_NOTES",
    "ActionRecord",
    "ActionState",
    "IssueConfirmOut",
    "IssueConfirmRequest",
    "IssuePreviewOut",
    "IssuePreviewRequest",
    "IssueSubjectSelection",
    "RepositoryTarget",
]
