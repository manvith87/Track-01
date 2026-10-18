"""User-approved GitHub issue endpoints for BlastRadius Phase 6.

Routes (mounted under ``/api/v1`` by the version-one router):

* ``POST /api/v1/analyses/{analysis_id}/remediation/github-issue/preview`` —
  generate the exact, digest-bound proposal for one fix group or finding.  No
  GitHub write happens; the response carries a server-issued ``action_id`` and
  an expiry.
* ``POST /api/v1/actions/github-issue/confirm`` — execute the one authorized
  write.  Requires the dedicated confirmation secret in the
  ``X-BlastRadius-Approval`` header (never stored, logged or echoed), the exact
  payload digest and an unexpired, unconsumed action.

The safe default is that GitHub writes are disabled: both endpoints answer
``403 github_write_disabled`` until an operator explicitly enables the feature
and configures the dedicated token.  Server-side facts only: callers can select
a server-issued group/finding id, never a repository, version, severity or
issue body.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Header, Path

from app.actions.models import (
    IssueConfirmOut,
    IssueConfirmRequest,
    IssuePreviewOut,
    IssuePreviewRequest,
)
from app.actions.service import GitHubIssueService
from app.api.deps import get_github_issue_service, only_query_parameters
from app.core.logging import get_logger

_log = get_logger("api.actions")

router = APIRouter(tags=["actions"])

_ANALYSIS_PATH = Path(
    ...,
    min_length=1,
    max_length=200,
    description="Analysis identifier produced by graph ingestion.",
)

_APPROVAL_HEADER = Header(
    default=None,
    alias="X-BlastRadius-Approval",
    description=(
        "Dedicated confirmation secret (BLASTRADIUS_ACTIONS_APPROVAL_SECRET). "
        "Required for confirmation; never stored, logged or echoed."
    ),
)

_ACTION_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"description": "Invalid input (unknown fields or query parameters)"},
    401: {"description": "Unauthorized confirmation (missing or invalid secret)"},
    403: {"description": "Writes disabled, repository not allowlisted, or GitHub permission denied"},
    404: {"description": "Analysis, group, finding or action not found"},
    409: {"description": "Expired, consumed, conflicting or changed evidence"},
    410: {"description": "Expired action"},
    422: {"description": "Request validation error"},
    429: {"description": "GitHub rate limit exceeded"},
    502: {"description": "GitHub write failed or its outcome is unknown"},
    503: {"description": "Action token or confirmation secret not configured"},
}


@router.post(
    "/analyses/{analysis_id}/remediation/github-issue/preview",
    response_model=IssuePreviewOut,
    status_code=201,
    summary="Preview the exact GitHub issue a confirmed action would create",
    description=(
        "Builds the deterministic title/body for one server-issued fix group or "
        "finding id, validates the canonical repository target and its GitHub "
        "accessibility (read-only), and persists a digest-bound PREVIEWED action. "
        "No GitHub write is performed. Caller-supplied security facts are rejected."
    ),
    responses=_ACTION_RESPONSES,
)
def preview_github_issue(
    analysis_id: str = _ANALYSIS_PATH,
    body: IssuePreviewRequest = Body(...),
    service: GitHubIssueService = Depends(get_github_issue_service),
    _query: None = Depends(only_query_parameters()),
) -> IssuePreviewOut:
    """Return the exact proposal for the selected group or finding."""
    return service.preview(analysis_id, body)


@router.post(
    "/actions/github-issue/confirm",
    response_model=IssueConfirmOut,
    summary="Confirm and execute one previewed GitHub issue",
    description=(
        "Revalidates the analysis evidence, requires the dedicated confirmation "
        "secret and the exact payload digest, atomically reserves the action and "
        "creates the issue through the GitHub REST API. Expired, altered, "
        "replayed or concurrently executed actions are rejected; a repeated "
        "confirmation of a completed action returns the stored issue result."
    ),
    responses=_ACTION_RESPONSES,
)
def confirm_github_issue(
    body: IssueConfirmRequest = Body(...),
    approval: str | None = _APPROVAL_HEADER,
    service: GitHubIssueService = Depends(get_github_issue_service),
    _query: None = Depends(only_query_parameters()),
) -> IssueConfirmOut:
    """Execute the authorized write for one previewed action."""
    return service.confirm(body, approval_key=approval)


__all__ = ["router"]
