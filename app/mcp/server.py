"""MCP Streamable HTTP server for BlastRadius Phase 4A.

Exposes read-only graph and OSV vulnerability intelligence to AI clients via
the Model Context Protocol (Streamable HTTP transport, mounted on the existing
FastAPI application).

All tools are read-only: no graph writes, no OSV ingestion, no arbitrary
Cypher execution.  Tools wrap the existing :class:`~app.graph.service.GraphService`,
:class:`~app.graph.vulnerability.VulnerabilityGraphService` and
:class:`~app.osv.service.OsvService` instances — no new data-access code is
introduced.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from mcp.types import INVALID_PARAMS, INTERNAL_ERROR

mcp = MCPServer(
    name="blastradius",
    title="BlastRadius MCP Server",
    description=(
        "Read-only access to the BlastRadius dependency graph and OSV.dev "
        "vulnerability intelligence.  All tools are read-only: no graph writes, "
        "no OSV ingestion, and no arbitrary Cypher execution."
    ),
    instructions=(
        "Use graph.health to check FalkorDB connectivity.  Use analysis.* tools "
        "to inspect a specific analysis (obtain the analysis_id from the Phase 1 "
        "ingest response or the Phase 2 graph endpoints).  Use vulnerability.* "
        "tools to inspect stored OSV records and their affected graph components. "
        "Use osv.lookup for live read-only OSV queries (no graph writes).  "
        "Use remediation.issue_preview to prepare — never create — a GitHub issue "
        "preview for a remediation group or finding; creating the issue requires "
        "the user's explicit confirmation through BlastRadius's authorized "
        "confirmation step and is never performed by any tool.  "
        "Results are graph facts only — no severity scores, risk scores, or "
        "vulnerability records are ever invented."
    ),
)

# Register tools (the import triggers @mcp.tool() decoration in tools.py).
# Imported after ``mcp`` is defined to avoid a circular import.
from app.mcp import tools  # noqa: E402, F401  (must be after mcp is defined)


def create_mcp_app():
    """Return the Starlette Streamable HTTP app for the MCP server.

    ``json_response=True`` keeps responses as plain JSON (easier to test and to
    put behind a reverse proxy) instead of Server-Sent Events.  The route path
    is ``/`` because the app is mounted under ``/mcp`` in the FastAPI
    application; Starlette's ``Mount`` strips the ``/mcp`` prefix before
    dispatching, leaving ``/`` for the MCP endpoint.
    """
    return mcp.streamable_http_app(json_response=True, streamable_http_path="/")


@asynccontextmanager
async def mcp_lifespan(app) -> AsyncIterator[None]:
    """Run the MCP Streamable HTTP session manager within the app's lifespan.

    The ASGI ``lifespan`` scope is only ever sent to the *top-level*
    application: Starlette's :class:`~starlette.routing.Mount` has no way to
    forward startup/shutdown events to a mounted sub-app, so the MCP session
    manager that backs the mounted Starlette app would never be initialised
    and every MCP request would fail with ``Task group is not initialized``.

    :func:`mount_mcp` therefore stores the freshly created session manager on
    ``app.state.mcp_session_manager``, and the parent application passes this
    context manager as its ``lifespan`` (see ``app.main.create_app``) so the
    manager starts with the app and is cancelled cleanly on shutdown.

    This is a no-op when the MCP sub-app is not mounted on ``app``.
    """
    manager = getattr(app.state, "mcp_session_manager", None)
    if manager is None:  # MCP not mounted — nothing to run.
        yield
        return
    async with manager.run():
        yield


def mount_mcp(app, path: str = "/mcp") -> None:
    """Mount the MCP Streamable HTTP app on a FastAPI application.

    Also attaches the session manager instance to ``app.state`` so the parent
    application's lifespan (:func:`mcp_lifespan`) can run it — mounted
    sub-apps never receive the ASGI ``lifespan`` scope.
    """
    sub_app = create_mcp_app()  # installs a fresh session manager on ``mcp``
    app.state.mcp_session_manager = mcp.session_manager
    app.mount(path, sub_app)


__all__ = ["mcp", "create_mcp_app", "mcp_lifespan", "mount_mcp", "INVALID_PARAMS", "INTERNAL_ERROR"]
