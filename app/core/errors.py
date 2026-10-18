"""Error taxonomy for BlastRadius.

Each exception carries a stable machine-readable code, a pipeline stage and an
HTTP status so that the API layer can translate failures into a consistent
response body without guessing.  Error messages never contain credentials:
URLs are redacted before they are embedded in a message.
"""

from __future__ import annotations

from typing import Any

from app.models.common import ErrorCode, IngestionStage
from app.models.ingestion import IngestionError


class BlastRadiusError(Exception):
    """Base class for every expected (non-bug) failure."""

    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    http_status: int = 500
    stage: IngestionStage = IngestionStage.UNKNOWN
    retryable: bool = False
    default_message: str = "Internal ingestion error"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        code: ErrorCode | None = None,
        retryable: bool | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.details: dict[str, Any] = dict(details or {})
        if code is not None:
            self.code = code
        if retryable is not None:
            self.retryable = retryable
        super().__init__(self.message)

    def to_record(self, *, manifest_path: str | None = None) -> IngestionError:
        """Convert the exception into a serialisable error record."""
        return IngestionError(
            code=self.code,
            message=self.message,
            stage=self.stage,
            manifest_path=manifest_path,
            retryable=self.retryable,
            details=self.details,
        )

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
class InputValidationError(BlastRadiusError):
    """The caller supplied something unusable or unsafe."""

    code = ErrorCode.INVALID_INPUT
    http_status = 400
    stage = IngestionStage.VALIDATION
    default_message = "Invalid ingestion request"


class InvalidRepositoryUrlError(InputValidationError):
    code = ErrorCode.INVALID_REPOSITORY_URL
    default_message = "The repository URL is not a valid public GitHub repository URL"


class UnsupportedHostError(InputValidationError):
    code = ErrorCode.UNSUPPORTED_HOST
    default_message = "Only repositories hosted on github.com are supported"


class EmbeddedCredentialsError(InputValidationError):
    code = ErrorCode.EMBEDDED_CREDENTIALS
    default_message = "Repository URLs must not contain credentials or access tokens"


class InvalidReferenceError(InputValidationError):
    code = ErrorCode.INVALID_REFERENCE
    default_message = "The requested Git reference is not a valid branch, tag or commit"


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
class RetrievalError(BlastRadiusError):
    """Base class for problems while obtaining repository content."""

    code = ErrorCode.RETRIEVAL_FAILED
    http_status = 502
    stage = IngestionStage.RETRIEVAL
    default_message = "Failed to retrieve the repository"


class RepositoryNotFoundError(RetrievalError):
    code = ErrorCode.REPOSITORY_NOT_FOUND
    http_status = 404
    default_message = "The repository does not exist or is not public"


class RepositoryAccessDeniedError(RetrievalError):
    code = ErrorCode.REPOSITORY_ACCESS_DENIED
    http_status = 403
    default_message = "Access to the repository was denied"


class RateLimitExceededError(RetrievalError):
    code = ErrorCode.RATE_LIMIT_EXCEEDED
    http_status = 429
    retryable = True
    default_message = "GitHub API rate limit exceeded"


class ReferenceNotFoundError(RetrievalError):
    code = ErrorCode.REFERENCE_NOT_FOUND
    http_status = 404
    default_message = "The requested reference does not exist in this repository"


class DownloadTimeoutError(RetrievalError):
    code = ErrorCode.DOWNLOAD_TIMEOUT
    http_status = 504
    retryable = True
    default_message = "Timed out while retrieving the repository"


class IngestionTimeoutError(RetrievalError):
    code = ErrorCode.INGESTION_TIMEOUT
    http_status = 504
    retryable = True
    stage = IngestionStage.RETRIEVAL
    default_message = "Ingestion exceeded the configured time budget"


class RepositoryTooLargeError(RetrievalError):
    code = ErrorCode.REPOSITORY_TOO_LARGE
    http_status = 413
    default_message = "The repository exceeds the configured size limit"


class NetworkFailureError(RetrievalError):
    code = ErrorCode.NETWORK_FAILURE
    http_status = 502
    retryable = True
    default_message = "Network failure while contacting GitHub"


class RetrievalToolMissingError(RetrievalError):
    code = ErrorCode.RETRIEVAL_TOOL_MISSING
    http_status = 503
    default_message = "No usable repository retrieval mechanism is available"


class UnsafeRepositoryContentError(RetrievalError):
    """The archive or working tree contained something dangerous."""

    code = ErrorCode.UNSAFE_ARCHIVE_CONTENT
    http_status = 422
    stage = IngestionStage.RETRIEVAL
    default_message = "The repository content failed safety validation"


class ArchiveExtractionError(RetrievalError):
    code = ErrorCode.ARCHIVE_EXTRACTION_FAILED
    http_status = 502
    default_message = "Failed to extract the repository archive"


# ---------------------------------------------------------------------------
# Fetch / metadata stage
# ---------------------------------------------------------------------------
class MetadataRetrievalError(RetrievalError):
    """GitHub metadata could not be fetched (recoverable: other resolvers exist)."""

    stage = IngestionStage.METADATA
    default_message = "Failed to retrieve repository metadata from GitHub"


# ---------------------------------------------------------------------------
# Secure user-approved GitHub actions (Phase 6)
#
# GitHub issue creation is a write operation.  The LLM's decision to call a
# tool, its recommendation, or a natural-language statement never authorizes
# the write: only a preview action bound to an exact payload digest and an
# explicitly authorized confirmation request do.  These errors carry the
# stable machine-readable codes that the API/MCP layers translate.
# ---------------------------------------------------------------------------
class ActionError(BlastRadiusError):
    """Base class for every failure of the Phase 6 approved-action workflow."""

    code = ErrorCode.INTERNAL_ERROR
    http_status = 500
    stage = IngestionStage.ACTIONS
    default_message = "The GitHub action could not be completed"


class GitHubWriteDisabledError(ActionError):
    """Write actions are disabled by configuration (the safe default)."""

    code = ErrorCode.GITHUB_WRITE_DISABLED
    http_status = 403
    default_message = "GitHub write actions are disabled in this deployment"


class ActionNotConfiguredError(ActionError):
    """The workflow is enabled but has no GitHub credential configured."""

    code = ErrorCode.ACTION_NOT_CONFIGURED
    http_status = 503
    default_message = (
        "GitHub issue actions are not configured: no action token is set"
    )


class ActionAuthorizationNotConfiguredError(ActionError):
    """No confirmation secret exists, so every confirmation must be refused."""

    code = ErrorCode.ACTION_AUTHORIZATION_NOT_CONFIGURED
    http_status = 503
    default_message = (
        "GitHub issue confirmation is disabled: no confirmation secret is configured"
    )


class ActionUnauthorizedError(ActionError):
    """The confirmation request carried no or an invalid authorization secret."""

    code = ErrorCode.ACTION_UNAUTHORIZED
    http_status = 401
    default_message = "The confirmation request is not authorized"


class ActionNotFoundError(ActionError):
    code = ErrorCode.ACTION_NOT_FOUND
    http_status = 404
    default_message = "The action id is unknown or has been purged"


class ActionExpiredError(ActionError):
    code = ErrorCode.ACTION_EXPIRED
    http_status = 410
    default_message = "The action has expired; generate a new preview"


class ActionConsumedError(ActionError):
    """The action was already approved/attempted and cannot be replayed."""

    code = ErrorCode.ACTION_CONSUMED
    http_status = 409
    default_message = "The action has already been consumed; generate a new preview"


class ActionInProgressError(ActionError):
    """Another confirmation of the same action is currently executing."""

    code = ErrorCode.ACTION_IN_PROGRESS
    http_status = 409
    default_message = "The action is already being executed"


class ActionPayloadMismatchError(ActionError):
    """The supplied digest does not match the stored preview payload."""

    code = ErrorCode.ACTION_PAYLOAD_MISMATCH
    http_status = 409
    default_message = "The payload digest does not match the stored preview"


class ActionEvidenceChangedError(ActionError):
    """The remediation evidence no longer reproduces the previewed payload."""

    code = ErrorCode.ACTION_EVIDENCE_CHANGED
    http_status = 409
    default_message = (
        "The analysis evidence has changed since the preview; generate a new preview"
    )


class ActionRepositoryInvalidError(ActionError):
    """The stored repository record cannot be trusted as a write target."""

    code = ErrorCode.ACTION_REPOSITORY_INVALID
    http_status = 409
    default_message = "The analysis repository identity is not a canonical GitHub repository"


class ActionRepositoryNotAllowedError(ActionError):
    """The target repository is outside the configured action allowlist."""

    code = ErrorCode.ACTION_REPOSITORY_NOT_ALLOWED
    http_status = 403
    default_message = "The repository is not in the configured GitHub action allowlist"


class ActionStoreError(ActionError):
    """The persistent action store failed."""

    code = ErrorCode.ACTION_STORE_ERROR
    http_status = 500
    default_message = "The action store is unavailable"


class GitHubCredentialsInvalidError(ActionError):
    """GitHub rejected the configured action token."""

    code = ErrorCode.GITHUB_CREDENTIALS_INVALID
    http_status = 503
    default_message = "GitHub rejected the configured action token (invalid or expired)"


class GitHubPermissionDeniedError(ActionError):
    code = ErrorCode.GITHUB_PERMISSION_DENIED
    http_status = 403
    default_message = (
        "The configured GitHub identity is not permitted to perform this operation"
    )


class GitHubIssuesDisabledError(ActionError):
    code = ErrorCode.GITHUB_ISSUES_DISABLED
    http_status = 409
    default_message = "Issues are disabled for the target repository"


class GitHubIssueCreationError(ActionError):
    """GitHub definitively rejected the issue creation request."""

    code = ErrorCode.GITHUB_ISSUE_CREATION_FAILED
    http_status = 502
    default_message = "GitHub rejected the issue creation request"


class GitHubWriteAmbiguousError(ActionError):
    """The write outcome could not be established; never blindly retried."""

    code = ErrorCode.GITHUB_WRITE_AMBIGUOUS
    http_status = 502
    default_message = (
        "The GitHub write outcome could not be established; it will not be retried automatically"
    )


__all__ = [
    "ActionAuthorizationNotConfiguredError",
    "ActionConsumedError",
    "ActionError",
    "ActionEvidenceChangedError",
    "ActionExpiredError",
    "ActionInProgressError",
    "ActionNotConfiguredError",
    "ActionNotFoundError",
    "ActionPayloadMismatchError",
    "ActionRepositoryInvalidError",
    "ActionRepositoryNotAllowedError",
    "ActionStoreError",
    "ActionUnauthorizedError",
    "ArchiveExtractionError",
    "BlastRadiusError",
    "DownloadTimeoutError",
    "EmbeddedCredentialsError",
    "GitHubCredentialsInvalidError",
    "GitHubIssueCreationError",
    "GitHubIssuesDisabledError",
    "GitHubPermissionDeniedError",
    "GitHubWriteAmbiguousError",
    "GitHubWriteDisabledError",
    "IngestionTimeoutError",
    "InputValidationError",
    "InvalidReferenceError",
    "InvalidRepositoryUrlError",
    "MetadataRetrievalError",
    "NetworkFailureError",
    "RateLimitExceededError",
    "ReferenceNotFoundError",
    "RepositoryAccessDeniedError",
    "RepositoryNotFoundError",
    "RepositoryTooLargeError",
    "RetrievalError",
    "RetrievalToolMissingError",
    "UnsafeRepositoryContentError",
    "UnsupportedHostError",
]
