"""Error taxonomy for OSV.dev upstream failures (Phase 3).

Mirrors :mod:`app.core.errors`: every expected failure is a typed,
machine-readable exception so the API layer can build the documented error
envelope without guessing.  Messages never contain credentials (OSV needs
none) and untrusted upstream content is never echoed verbatim.
"""

from __future__ import annotations

from typing import Any

from app.core.errors import BlastRadiusError
from app.models.common import ErrorCode, IngestionStage


class OsvError(BlastRadiusError):
    """Base class for expected OSV upstream failures."""

    code: ErrorCode = ErrorCode.OSV_INVALID_RESPONSE
    http_status: int = 502
    stage: IngestionStage = IngestionStage.UNKNOWN
    retryable: bool = False
    default_message: str = "OSV vulnerability lookup failed"


class OsvUnavailableError(OsvError):
    """The OSV API cannot be reached (connection refused, DNS, 5xx after retries)."""

    code = ErrorCode.NETWORK_FAILURE
    http_status = 502
    stage = IngestionStage.METADATA
    retryable = True
    default_message = "OSV vulnerability database is unavailable"


class OsvRateLimitedError(OsvError):
    """OSV replied 429 (rate limited) and retries were exhausted."""

    code = ErrorCode.RATE_LIMIT_EXCEEDED
    http_status = 429
    stage = IngestionStage.METADATA
    retryable = True
    default_message = "OSV API rate limit exceeded"


class OsvTimeoutError(OsvError):
    """An OSV request exceeded its configured timeout and retries."""

    code = ErrorCode.INGESTION_TIMEOUT
    http_status = 504
    stage = IngestionStage.METADATA
    retryable = True
    default_message = "OSV API request timed out"


class OsvInvalidResponseError(OsvError):
    """The upstream returned a malformed / unexpected payload."""

    code = ErrorCode.OSV_INVALID_RESPONSE
    http_status = 502
    stage = IngestionStage.METADATA
    default_message = "OSV API returned an invalid response"


class OsvRequestError(OsvError):
    """A request OSV rejects (4xx other than 429); not retryable."""

    code = ErrorCode.INVALID_INPUT
    http_status = 400
    stage = IngestionStage.VALIDATION
    default_message = "OSV API rejected the request"


class OsvRecordNotFoundError(OsvError):
    """A requested vulnerability record does not exist upstream (404)."""

    code = ErrorCode.RETRIEVAL_FAILED
    http_status = 404
    stage = IngestionStage.METADATA
    default_message = "Vulnerability record not found in OSV"


__all__ = [
    "OsvError",
    "OsvInvalidResponseError",
    "OsvRateLimitedError",
    "OsvRecordNotFoundError",
    "OsvRequestError",
    "OsvTimeoutError",
    "OsvUnavailableError",
]
