"""Evidence records and grounding validation for the Phase 4B agent.

Every graph/vulnerability fact the agent reports must come from MCP tool
results.  :mod:`app.agent.agent` records each executed call as evidence and,
before returning a final answer, runs the deterministic grounding scanner:
answers may only name vulnerability identifiers, publish OSV links or quote
severity scores that literally appear in the collected evidence text.

The scanner is a *tripwire*, not a semantic proof: it deterministically
blocks the most harmful fabrication classes (invented advisory IDs/links and
invented scores) that the test suite relies on.  Residual semantic
hallucination risk is documented in ``docs/PHASE4B.md``.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

#: Patterns that must be grounded in evidence when mentioned in an answer.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,9}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
_OSV_URL_RE = re.compile(r"https?://(?:osv\.dev|mig\.google\.dev)/\S+", re.IGNORECASE)
_SCORE_RE = re.compile(
    r"(?i)\b(?:cvss(?:\s*v?\d)?|severity)\b[^.]{0,24}?\b(\d{1,2}(?:\.\d{1,2})?)\b"
)
_FIXED_VERSION_RE = re.compile(
    r"(?i)\b(?:fixed|patched)\s+(?:in|version\s*[^.]{0,40}?)[^.]{0,60}?\b(v?\d+(?:\.\w+){1,4})\b"
)

MARK_MAX: int = 40


class ToolCallRecord(BaseModel):
    """Summary of one model-requested tool invocation."""

    round_index: int
    name: str
    status: str  # "executed" | "rejected" | "failed"
    reason: str | None = None
    result_chars: int = 0
    arguments: dict[str, Any] = Field(default_factory=dict)


class EvidenceReference(BaseModel):
    """Pointer to one MCP result that backs the answer."""

    round_index: int
    tool: str
    sequence: int
    excerpt: str
    result_chars: int


class AgentResult(BaseModel):
    """Structured result of one bounded agent run."""

    analysis_id: str
    answer: str
    grounded: bool
    incomplete: bool = False
    rounds_used: int
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    repository_id: str | None = None
    commit_sha: str | None = None
    advisory_links: list[str] = Field(default_factory=list)


class GroundingReport(BaseModel):
    """Result of the deterministic answer grounding scan."""

    grounded: bool
    ungrounded: list[str] = Field(default_factory=list)


def render_result_text(result: dict[str, Any], cap: int) -> str:
    """Render one tool result as bounded JSON text for messages and evidence."""
    import json

    text = json.dumps(result, ensure_ascii=True, default=str)
    if len(text) > cap:
        text = text[: max(cap - 12, 0)] + '...[truncated]'
    return text


def validate_groundedness(answer: str, evidence_text: str) -> GroundingReport:
    """Scan an answer for claims that must exist in collected evidence."""
    ungrounded: list[str] = []
    for pattern in (_CVE_RE, _GHSA_RE, _OSV_URL_RE):
        for match in pattern.findall(answer):
            if not re.search(re.escape(match), evidence_text, re.IGNORECASE):
                ungrounded.append(match)
    for match in _SCORE_RE.finditer(answer):
        marker = match.group(0) if match.group(0) else ""
        if not re.search(re.escape(marker), evidence_text, re.IGNORECASE):
            ungrounded.append(marker)
    for match in _FIXED_VERSION_RE.finditer(answer):
        version = match.group(1)
        if not re.search(re.escape(version), evidence_text, re.IGNORECASE):
            ungrounded.append(f"fixed version {version}")
    unique: list[str] = []
    for item in ungrounded:
        cleaned = item.strip()[:MARK_MAX]
        if cleaned.lower() not in {existing.lower() for existing in unique}:
            unique.append(cleaned)
    # Severity claims without any digit are vacuous; only scored claims matter.
    return GroundingReport(grounded=not unique, ungrounded=unique[:5])


def extract_advisory_links(evidence_text: str, limit: int = 10) -> list[str]:
    """Deterministically collect OSV/advisory URLs from collected evidence."""
    links: list[str] = []
    for match in _OSV_URL_RE.finditer(evidence_text):
        url = match.group(0).rstrip('\'",)]}')
        if url not in links:
            links.append(url)
        if len(links) >= limit:
            break
    return links


def strip_argument_values(arguments: dict[str, Any], max_chars: int = 120) -> dict[str, Any]:
    """Argument echo for the response payload (values bounded, secrets none)."""
    safe: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            safe[str(key)] = value[:max_chars]
        elif isinstance(value, (bool, int, float)) or value is None:
            safe[str(key)] = value
        elif isinstance(value, list):
            safe[str(key)] = [str(item)[:max_chars] for item in value[:10]]
        elif isinstance(value, dict):
            safe[str(key)] = strip_argument_values(value, max_chars)
    return safe


__all__ = [
    "AgentResult",
    "EvidenceReference",
    "GroundingReport",
    "ToolCallRecord",
    "extract_advisory_links",
    "render_result_text",
    "strip_argument_values",
    "validate_groundedness",
]
