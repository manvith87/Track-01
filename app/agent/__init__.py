"""Evidence-grounded security agent (Phase 4B).

Package layout:

* :mod:`app.agent.config` — ``BLASTRADIUS_AGENT_*`` settings, one provider
  dialect (``openai-compat``), MCP endpoint, bounded-loop limits;
* :mod:`app.agent.errors` — typed agent failures riding the shared error
  envelope;
* :mod:`app.agent.provider` — LLM provider interface + OpenAI-compatible
  tool-calling adapter (``httpx``, injectable transport);
* :mod:`app.agent.mcp_client` — official MCP SDK Streamable HTTP client used
  for ``tools/list`` discovery and ``tools/call`` execution;
* :mod:`app.agent.evidence` — evidence/tool-call records and the
  deterministic grounding validator;
* :mod:`app.agent.agent` — the bounded orchestration loop.

The FastAPI surface (``POST /api/v1/analyses/{analysis_id}/ask``) lives in
:mod:`app.api.v1.agent`.  The agent is read-only by construction: it can only
execute tools the Phase 4A MCP server advertises, and nothing here writes to
the graph, OSV, GitHub or the local system.
"""

from __future__ import annotations

from app.agent.agent import BlastAgent
from app.agent.config import (
    AgentSettings,
    get_agent_settings,
    reset_agent_settings_cache,
)
from app.agent.evidence import (
    AgentResult,
    EvidenceReference,
    GroundingReport,
    ToolCallRecord,
)
from app.agent.mcp_client import DiscoveredTool, MCPToolClient
from app.agent.provider import (
    LLMProvider,
    OpenAICompatProvider,
    ProviderToolCall,
    ProviderTurn,
    build_provider,
)

__all__ = [
    "AgentResult",
    "AgentSettings",
    "BlastAgent",
    "DiscoveredTool",
    "EvidenceReference",
    "GroundingReport",
    "LLMProvider",
    "MCPToolClient",
    "OpenAICompatProvider",
    "ProviderToolCall",
    "ProviderTurn",
    "ToolCallRecord",
    "build_provider",
    "get_agent_settings",
    "reset_agent_settings_cache",
]
