"""Response models for the Phase 4B agent endpoints.

The agent answer carries structured evidence references, a bounded tool-call
summary and machine-readable limitations so the client can see exactly what
backs (and what limits) the answer.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.agent.evidence import AgentResult

#: Question cap (mirrors the default of ``AgentSettings.max_question_chars``).
QuestionMaxLength: int = 1_000


class AgentAskRequest(BaseModel):
    """Request body for ``POST /api/v1/analyses/{analysis_id}/ask``."""

    question: str = Field(
        ...,
        min_length=1,
        max_length=QuestionMaxLength,
        description=(
            "Security question about the analysis, e.g. 'Which components "
            "appear in the reported impact paths?'. Max "
            f"{QuestionMaxLength} characters."
        ),
    )
    max_rounds: int | None = Field(
        default=None,
        ge=1,
        le=8,
        description="Optional per-request cap on reasoning rounds (bounded by server settings).",
    )


class AgentToolCallOut(BaseModel):
    """One model-requested tool invocation and its disposition."""

    round_index: int
    name: str
    status: str  # executed | rejected | failed
    reason: str | None = None
    result_chars: int = 0
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentEvidenceOut(BaseModel):
    """Reference to one MCP tool result backing the answer."""

    round_index: int
    tool: str
    sequence: int
    excerpt: str
    result_chars: int


class AgentAskResponse(BaseModel):
    """Structured, evidence-grounded agent answer."""

    analysis_id: str
    answer: str
    grounded: bool
    incomplete: bool
    rounds_used: int
    tool_calls: list[AgentToolCallOut] = Field(default_factory=list)
    evidence: list[AgentEvidenceOut] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    repository_id: str | None = None
    commit_sha: str | None = None
    advisory_links: list[str] = Field(default_factory=list)

    @classmethod
    def from_result(cls, result: AgentResult) -> "AgentAskResponse":
        """Build the API response from an internal :class:`AgentResult`."""
        return cls(
            analysis_id=result.analysis_id,
            answer=result.answer,
            grounded=result.grounded,
            incomplete=result.incomplete,
            rounds_used=result.rounds_used,
            tool_calls=[AgentToolCallOut(**record.model_dump()) for record in result.tool_calls],
            evidence=[
                AgentEvidenceOut(
                    round_index=entry.round_index,
                    tool=entry.tool,
                    sequence=entry.sequence,
                    excerpt=entry.excerpt,
                    result_chars=entry.result_chars,
                )
                for entry in result.evidence
            ],
            limitations=result.limitations,
            repository_id=result.repository_id,
            commit_sha=result.commit_sha,
            advisory_links=result.advisory_links,
        )


__all__ = [
    "AgentAskRequest",
    "AgentAskResponse",
    "AgentEvidenceOut",
    "AgentToolCallOut",
    "QuestionMaxLength",
]
