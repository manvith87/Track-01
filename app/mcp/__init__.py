"""BlastRadius Phase 4A MCP server package.

Read-only Model Context Protocol server exposing the dependency graph and OSV
vulnerability intelligence to AI clients.  No application code, dependencies,
settings, graph schema, or existing tests are changed by this package beyond
mounting the MCP Streamable HTTP endpoint on the FastAPI application.
"""

from __future__ import annotations

__all__ = ["create_mcp_app", "mcp_lifespan", "mount_mcp"]
