"""Error taxonomy for the evidence-grounded agent (Phase 4B).

Mirrors :mod:`app.osv.errors` and :mod:`app.core.errors`: every expected
failure is a typed, machine-readable exception that the API layer translates
into the documented error envelope.  Messages never contain credentials and
provider/upstream payloads are never echoed verbatim.
"""

from __future__ import annotations

from typing import Any

from app.core.errors import BlastRadiusError
from app.models.common import ErrorCode, IngestionStage


class AgentError(BlastRadiusError):
    """Base class for expected agent failures."""

    code: ErrorCode = ErrorCode.AGENT_PROVIDER_ERROR
    http_status: int = 502
    stage: IngestionStage = IngestionStage.AGENT
    retryable: bool = False
    default_message: str = "The security agent could not answer this question"


class AgentNotConfiguredError(AgentError):
    """No usable LLM provider credentials/model are configured."""

    code = ErrorCode.AGENT_NOT_CONFIGURED
    http_status = 503
    default_message = (
        "The agent is not configured: set BLASTRADIUS_AGENT_MODEL and "
        "BLASTRADIUS_AGENT_API_KEY (or OPENAI_API_KEY) to enable it"
    )


class AgentProviderError(AgentError):
    """The LLM provider returned an unexpected failure (HTTP error, bad payload)."""

    code = ErrorCode.AGENT_PROVIDER_ERROR
    http_status = 502
    default_message = "The model provider returned an error"


class AgentProviderTimeoutError(AgentError):
    """A provider request exceeded its timeout."""

    code = ErrorCode.AGENT_TIMEOUT
    http_status = 504
    retryable = True
    default_message = "The model provider request timed out"


class AgentMCPUnavailableError(AgentError):
    """The MCP endpoint could not be connected to or did not behave as expected."""

    code = ErrorCode.AGENT_MCP_UNAVAILABLE
    http_status = 502
    retryable = True
    default_message = "The MCP endpoint is unavailable or misbehaving"


class AgentToolError(AgentError):
    """A specific tool call failed at the MCP layer (protocol or tool error).

    This is used for *reporting* inside the bounded loop; the agent records it
    as a failed tool call (limitation) instead of aborting the whole answer.
    """

    code = ErrorCode.AGENT_MCP_UNAVAILABLE
    http_status = 502
    default_message = "An MCP tool call failed"

    def __init__(self, tool_name: str, message: str | None = None, **kwargs: Any) -> None:
        super().__init__(message or self.default_message, **kwargs)
        self.tool_name = tool_name


__all__ = [
    "AgentError",
    "AgentMCPUnavailableError",
    "AgentNotConfiguredError",
    "AgentProviderError",
    "AgentProviderTimeoutError",
    "AgentToolError",
]
