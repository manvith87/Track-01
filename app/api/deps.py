"""FastAPI dependencies.

These small providers exist so that tests can override the ingestion service
with a deterministic stub instead of reaching out to GitHub, the OSV API or
FalkorDB.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

from fastapi import Request

from app.actions.config import ActionSettings
from app.actions.config import get_action_settings as _configured_action_settings
from app.actions.service import GitHubIssueService
from app.actions.store import ActionStore
from app.core.config import Settings, get_settings
from app.core.errors import InputValidationError
from app.github.issue_client import GitHubIssueClient
from app.ingestion.service import ingest_repository
from app.models.ingestion import IngestionResult
from app.graph.client import GraphClient
from app.graph.config import get_graph_settings
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.osv.client import OsvApiClient
from app.osv.config import get_osv_settings
from app.osv.service import OsvService
from app.remediation.service import RemediationService

IngestionCallable = Callable[..., IngestionResult]


def only_query_parameters(*allowed: str) -> Callable[[Request], None]:
    """Reject query parameters the route does not define.

    The Phase 5/6 endpoints accept identifiers and pagination only.  Advisory
    or repository data supplied by a caller (CVE ids, severities, fixed
    versions, repository names) must be rejected explicitly instead of being
    silently ignored.
    """

    allowed_set = frozenset(allowed)

    def _dependency(request: Request) -> None:
        unexpected = sorted(set(request.query_params.keys()) - allowed_set)
        if unexpected:
            raise InputValidationError(
                "Unsupported query parameter(s): " + ", ".join(unexpected),
                details={
                    "unsupported_query_parameters": unexpected,
                    "allowed_query_parameters": sorted(allowed_set),
                },
            )

    return _dependency


def get_ingestion_service() -> IngestionCallable:
    """Return the reusable ingestion service function."""
    return ingest_repository


def get_app_settings() -> Settings:
    """Return the effective application settings."""
    return get_settings()


def get_graph_client() -> GraphClient:
    """Return a FalkorDB graph client (connects lazily on first use)."""
    return GraphClient(get_graph_settings())


def get_graph_service() -> GraphService:
    """Return a graph service backed by a FalkorDB client.

    Tests can override this dependency with a test double.
    """
    return GraphService(get_graph_client())


def get_osv_service() -> OsvService:
    """Return the OSV orchestration service (single shared HTTP client).

    OSV needs no credentials and is read-only, so one process-wide
    :class:`OsvApiClient` is safe to reuse across requests.
    """
    return _osv_service_singleton()


def get_vulnerability_service() -> VulnerabilityGraphService:
    """Return a graph service for vulnerability intelligence writes/reads."""
    return VulnerabilityGraphService(get_graph_client())


def get_remediation_service() -> RemediationService:
    """Return the deterministic Phase 5 prioritization/remediation service.

    The service is read-only and LLM-free: it computes everything from the
    persisted graph facts on request.  Tests override this dependency with a
    deterministic stub (or a service backed by a fake graph client).
    """
    client = get_graph_client()
    graph_service = GraphService(client)
    return RemediationService(graph_service, VulnerabilityGraphService(client, graph_service))


def get_action_settings() -> ActionSettings:
    """Return the effective Phase 6 GitHub action settings."""
    return _configured_action_settings()


def get_action_store() -> ActionStore:
    """Return the process-wide persistent action store (initialised lazily)."""
    return _action_store_singleton()


def get_github_issue_client() -> GitHubIssueClient:
    """Return the process-wide GitHub issue client (connection reuse)."""
    return _github_issue_client_singleton()


def get_github_issue_service() -> GitHubIssueService:
    """Return the Phase 6 preview/confirm service.

    Built per request from the graph services, the persistent action store and
    the GitHub issue client.  The configuration gates (writes enabled, token,
    confirmation secret) are enforced by the service itself, so an unconfigured
    deployment yields a stable typed error instead of a startup failure.
    Tests override this dependency with a fully deterministic service.
    """
    client = get_graph_client()
    graph_service = GraphService(client)
    remediation = RemediationService(
        graph_service, VulnerabilityGraphService(client, graph_service)
    )
    return GitHubIssueService(
        remediation=remediation,
        graph=graph_service,
        github=get_github_issue_client(),
        store=get_action_store(),
        settings=get_action_settings(),
    )


def reset_action_caches() -> None:
    """Clear the action settings/client/store singletons (tests, config reloads)."""
    _action_store_singleton.cache_clear()
    _github_issue_client_singleton.cache_clear()
    _configured_action_settings.cache_clear()


def get_agent() -> "BlastAgent":
    """Return the Phase 4B evidence-grounded security agent.

    Built per request (it opens its own MCP session per question). Provider
    credentials are validated when the question is asked, so an unconfigured
    deployment yields a stable ``agent_not_configured`` error instead of a
    startup failure. Tests override this dependency with a deterministic
    agent.
    """
    from app.agent.agent import BlastAgent
    from app.agent.config import get_agent_settings

    return BlastAgent(get_agent_settings())


@lru_cache(maxsize=1)
def _osv_service_singleton() -> OsvService:
    client = OsvApiClient(get_osv_settings())
    return OsvService(client, get_osv_settings())


@lru_cache(maxsize=1)
def _action_store_singleton() -> ActionStore:
    store = ActionStore(get_action_settings().effective_store_path)
    store.initialize()
    return store


@lru_cache(maxsize=1)
def _github_issue_client_singleton() -> GitHubIssueClient:
    return GitHubIssueClient(get_action_settings())


__all__ = [
    "IngestionCallable",
    "get_action_settings",
    "get_action_store",
    "get_agent",
    "get_app_settings",
    "get_github_issue_client",
    "get_github_issue_service",
    "get_graph_client",
    "get_graph_service",
    "get_ingestion_service",
    "get_osv_service",
    "get_remediation_service",
    "get_vulnerability_service",
    "only_query_parameters",
    "reset_action_caches",
]
